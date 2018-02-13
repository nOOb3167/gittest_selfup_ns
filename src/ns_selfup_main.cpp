#include <cassert>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>

#include <git2.h>

#include <selfup/NetworkPacket.h>
#include <selfup/ns_conf.h>
#include <selfup/ns_filesys.h>
#include <selfup/ns_git_aux.h>
#include <selfup/ns_git_shims.h>
#include <selfup/ns_gui.h>
#include <selfup/ns_helpers.h>
#include <selfup/ns_log.h>
#include <selfup/TCPAsync.h>

#define SELFUP_ARG_CHILD "--xchild"
#define SELFUP_ARG_VERSUB "--xversub"
#define SELFUP_ARG_VERSUB_SUCCESS_CODE 42

#define SELFUP_FRAME_SIZE_MAX (256 * 1024 * 1024)
#define SELFUP_LONG_TIMEOUT_MS (30 * 1000)

#define NS_STATUS(cstr) do { NS_LOG_SZ(cstr, strlen(cstr)); NS_GUI_STATUS(cstr); } while (0);

#define NS_LOGDUMP(addr, magic) do { NS_LOG_LOCK(); TCPLogDump::dump((addr), (magic), g_log->getBuf().data(), g_log->getBuf().size()); } while (0);

/* NOTE: attempting to exit with non-joined std::threads causes abort() */
/* NOTE: main() must not leak exceptions due to reliance on stack unwinding (see RefKill) */
#define NS_TOPLEVEL_CATCH_SELFUP(retname, funcname, ...)	\
	do {											\
		try {										\
			funcname(__VA_ARGS__);					\
		} catch (const std::exception &e) {			\
			retname = 1;							\
			std::string msg(e.what());				\
			NS_LOG_SZ(msg.data(), msg.size());		\
		}											\
	} while(0)

int g_selfup_selfupdate_skip_fileops = 1;

long long selfup_timestamp()
{
	struct timespec tspec = {};

#ifdef _WIN32
	/* supposedly not available in VS2013 - switch to something else */
	if (! timespec_get(&tspec, TIME_UTC))
		throw std::runtime_error("timestamp get");
#else
	if (!! clock_gettime(CLOCK_MONOTONIC, &tspec))
		throw std::runtime_error("timestamp get");
#endif
	return (tspec.tv_sec * 1000) + (tspec.tv_nsec / (1000 * 1000));
}

class SelfupRespond
{
public:
	virtual ~SelfupRespond() = default;

	void respondOneshot(NetworkPacket packet)
	{
		virtualRespond(std::move(packet));
	}

	NetworkPacket waitFrame()
	{
		return std::move(virtualWaitFrame());
	}

protected:
	virtual void virtualRespond(NetworkPacket packet) = 0;
	virtual NetworkPacket virtualWaitFrame() = 0;
};

class SelfupRespondWork : public SelfupRespond
{
public:
	SelfupRespondWork(const std::shared_ptr<TCPSocket> &sock) :
		m_sock(sock)
	{}

protected:
	void virtualRespond(NetworkPacket packet) override
	{
		m_sock->Send(&packet);
	}

	NetworkPacket virtualWaitFrame() override
	{
		/* FIXME: timeout support */
		return m_sock->Recv();
	}

private:
	std::shared_ptr<TCPSocket> m_sock;
};

class SelfupWork
{
public:
	SelfupWork(Address addr) :
		m_sock(new TCPSocket()),
		m_respond(new SelfupRespondWork(m_sock)),
		m_thread(),
		m_thread_exc()
	{
		m_sock->Connect(addr);
	}

	virtual ~SelfupWork() = default;

	void threadFunc()
	{
		try {
			virtualThreadFunc();
		}
		catch (std::exception &e) {
			m_thread_exc = std::current_exception();
		}
	}

	virtual void virtualThreadFunc() = 0;

	void start()
	{
		m_thread.reset(new std::thread(&SelfupWork::threadFunc, this));
	}

	void join()
	{
		m_thread->join();

		if (m_thread_exc) {
			try {
				std::rethrow_exception(m_thread_exc);
			}
			catch (std::exception &e) {
				throw;
			}
		}
	}

	void readEnsureCmd(NetworkPacket *packet, uint8_t cmdid)
	{
		if (cmdid != readGetCmd(packet))
			throw ProtocolExc("cmd");
	}

	uint8_t readGetCmd(NetworkPacket *packet)
	{
		assert(packet->isReset());
		uint8_t c;
		(*packet) >> c;
		return c;
	}

protected:
	std::shared_ptr<TCPSocket>     m_sock;
	std::unique_ptr<SelfupRespond> m_respond;
	std::unique_ptr<std::thread> m_thread;
	std::exception_ptr           m_thread_exc;
};

class SelfupConExt1
{
public:
	SelfupConExt1(const std::string &cur_exe_filename, const std::string &refname) :
		m_cur_exe_filename(cur_exe_filename),
		m_refname(refname),
		m_update_have(false),
		m_update_buffer()
	{}

	void confirmUpdate(std::unique_ptr<std::string> update_buffer)
	{
		m_update_have = true;
		m_update_buffer = std::move(update_buffer);
	}

public:
	std::string                  m_cur_exe_filename;
	std::string                  m_refname;

	bool                         m_update_have;
	std::unique_ptr<std::string> m_update_buffer;
};

class SelfupWork1 : public SelfupWork
{
public:
	SelfupWork1(Address addr, std::shared_ptr<SelfupConExt1> ext) :
		SelfupWork(addr),
		m_ext(ext)
	{}

	void virtualThreadFunc() override
	{
		unique_ptr_gitrepository memory_repository(selfup_git_memory_repository_new(), deleteGitrepository);

		NS_STATUS("selfup net latest request");

		NetworkPacket packet_req_latest(SELFUP_CMD_REQUEST_LATEST_SELFUPDATE_BLOB, networkpacket_cmd_tag_t());
		packet_req_latest << (uint32_t) m_ext->m_refname.size();
		packet_req_latest.outSizedStr(m_ext->m_refname.data(), m_ext->m_refname.size());
		m_respond->respondOneshot(std::move(packet_req_latest));

		NetworkPacket res_latest_pkt = m_respond->waitFrame();
		readEnsureCmd(&res_latest_pkt, SELFUP_CMD_RESPONSE_LATEST_SELFUPDATE_BLOB);
		NS_STATUS("selfup net latest response");
		git_oid res_latest_oid = {};
		git_oid_fromraw(&res_latest_oid, (const unsigned char *) res_latest_pkt.inSizedStr(GIT_OID_RAWSZ));

		NS_STATUS("selfup net hash");

		git_oid oid_cur_exe = {};
		/* empty as_path parameter means no filters applied */
		if (!! git_repository_hashfile(&oid_cur_exe, memory_repository.get(), m_ext->m_cur_exe_filename.c_str(), GIT_OBJ_BLOB, ""))
			throw std::runtime_error("hash");

		if (git_oid_cmp(&oid_cur_exe, &res_latest_oid) == 0)
			return;

		NS_STATUS("selfup net objs request");

		requestAndRecvAndWriteObj(memory_repository.get(), res_latest_oid);

		NS_STATUS("selfup net objs updatebuf");

		unique_ptr_gitblob blob(selfup_git_blob_lookup(memory_repository.get(), &res_latest_oid), deleteGitblob);

		std::unique_ptr<std::string> update_buffer(new std::string((char *) git_blob_rawcontent(blob.get()), git_blob_rawsize(blob.get())));

		m_ext->confirmUpdate(std::move(update_buffer));

		return;
	}

	void requestAndRecvAndWriteObj(git_repository *memory_repository, git_oid missing_obj_oid)
	{
		/* REQ_OBJS3 */

		NS_STATUS("selfup net objs req");

		NetworkPacket req_obj_pkt(SELFUP_CMD_REQUEST_OBJS3, networkpacket_cmd_tag_t());
		req_obj_pkt << (uint32_t) 1;
		req_obj_pkt.outSizedStr((char *) missing_obj_oid.id, GIT_OID_RAWSZ);
		m_respond->respondOneshot(std::move(req_obj_pkt));

		/* RES_OBJS3 */

		NetworkPacket res_obj_pkt = m_respond->waitFrame();
		readEnsureCmd(&res_obj_pkt, SELFUP_CMD_RESPONSE_OBJS3);
		NS_STATUS("selfup net objs res");
		uint32_t res_obj_blen = 0;
		res_obj_pkt >> res_obj_blen;

		ns_git::NsGitObject obj(ns_git::read_object_memory_ex(std::string(res_obj_pkt.inSizedStr(res_obj_blen), res_obj_blen)));

		NS_STATUS("selfup net objs write");

		git_oid written_oid = {};
		if (!! git_blob_create_frombuffer(&written_oid, memory_repository, obj.m_inflated.data() + obj.m_inflated_offset, obj.m_inflated_size))
			throw std::runtime_error("blob create from buffer");
		if (git_oid_cmp(&written_oid, &missing_obj_oid) != 0)
			throw std::runtime_error("blob mismatch");

		/* RES_OBJS3_DONE */

		NetworkPacket res_obj_done_pkt = m_respond->waitFrame();
		readEnsureCmd(&res_obj_done_pkt, SELFUP_CMD_RESPONSE_OBJS3_DONE);
		NS_STATUS("selfup net objs done");
	}

private:
	std::shared_ptr<SelfupConExt1> m_ext;
};

class SelfupConExt2
{
public:
	SelfupConExt2(std::string repopath, std::string refname) :
		m_repopath(repopath),
		m_refname(refname),
		m_update_have(false)
	{}

	void confirmUpdate()
	{
		m_update_have = true;
	}

public:
	std::string m_repopath;
	std::string m_refname;

	bool m_update_have;
};

class SelfupWork2 : public SelfupWork
{
public:
	SelfupWork2(Address addr, std::shared_ptr<SelfupConExt2> ext) :
		SelfupWork(addr),
		m_ext(ext)
	{}

	void virtualThreadFunc() override
	{
		git_oid oid_zero = {};
		unique_ptr_gitrepository repo(selfup_git_repository_open(m_ext->m_repopath), deleteGitrepository);

		/* request latest version git_oid */

		NS_STATUS("mainup net latest request");

		NetworkPacket packet_req_latest(SELFUP_CMD_REQUEST_LATEST_COMMIT_TREE, networkpacket_cmd_tag_t());
		packet_req_latest << (uint32_t) m_ext->m_refname.size();
		packet_req_latest.outSizedStr(m_ext->m_refname.data(), m_ext->m_refname.size());
		m_respond->respondOneshot(std::move(packet_req_latest));

		NetworkPacket res_latest_pkt = m_respond->waitFrame();
		readEnsureCmd(&res_latest_pkt, SELFUP_CMD_RESPONSE_LATEST_COMMIT_TREE);
		NS_STATUS("mainup net latest response");
		git_oid res_latest_oid = {};
		git_oid_fromraw(&res_latest_oid, (const unsigned char *) res_latest_pkt.inSizedStr(GIT_OID_RAWSZ));

		/* determine local version git_oid - defaults to zeroed-out */

		NS_STATUS("mainup net headtree");

		{
			RefKill rfk(repo.get(), m_ext->m_refname);

			git_oid repo_head_tree_oid = getHeadTree(repo.get(), m_ext->m_refname);

			/* matching versions suggest an update is unnecessary */

			if (git_oid_cmp(&repo_head_tree_oid, &res_latest_oid) == 0)
				return;
		}

		/* request list of trees comprising latest version */

		NS_STATUS("mainup net treelist request");

		NetworkPacket req_treelist_pkt(SELFUP_CMD_REQUEST_TREELIST, networkpacket_cmd_tag_t());
		req_treelist_pkt.outSizedStr((char *) res_latest_oid.id, GIT_OID_RAWSZ);
		m_respond->respondOneshot(std::move(req_treelist_pkt));

		NetworkPacket res_treelist_pkt = m_respond->waitFrame();
		readEnsureCmd(&res_treelist_pkt, SELFUP_CMD_RESPONSE_TREELIST);
		NS_STATUS("mainup net treelist response");
		uint32_t res_treelist_treenum = 0;
		std::vector<git_oid> res_treelist_treevec;
		res_treelist_pkt >> res_treelist_treenum;
		for (size_t i = 0; i < res_treelist_treenum; i++) {
			git_oid tmp = {};
			memcpy(tmp.id, res_treelist_pkt.inSizedStr(GIT_OID_RAWSZ), GIT_OID_RAWSZ);
			res_treelist_treevec.push_back(tmp);
		}

		/* determine which trees are missing */

		NS_STATUS("mainup net missing tree determine");

		std::deque<git_oid> missing_tree_oids;
		for (size_t i = 0; i < res_treelist_treevec.size(); i++)
			if (! selfup_git_exists(repo.get(), &res_treelist_treevec[i]))
				missing_tree_oids.push_back(res_treelist_treevec[i]);

		/* request missing trees and write received into the repository */

		NS_STATUS("mainup net missing tree obtain");

		requestAndRecvAndWriteObjs(repo.get(), &missing_tree_oids);

		/* determine which blobs are missing - validating trees and their entries in the meantime */

		/* by now all required trees should of been either preexistent or missing but written into the repository.
		   validating trees comprises of:
		     - confirming existence of trees themselves
			 - examining the trees' entries:
			   - tree entries for existence
			   - blob entries for existence, recording missing blobs */

		NS_STATUS("mainup net missing blob determine");

		std::deque<git_oid> missing_blob_oids;

		for (size_t i = 0; i < res_treelist_treevec.size(); i++) {
			unique_ptr_gitodb odb(selfup_git_repository_odb(repo.get()), deleteGitodb);
			unique_ptr_gittree tree(selfup_git_tree_lookup(repo.get(), &res_treelist_treevec[i]), deleteGittree);
			for (size_t j = 0; j < git_tree_entrycount(tree.get()); j++) {
				const git_tree_entry *entry = git_tree_entry_byindex(tree.get(), j);
				if (git_tree_entry_type(entry) == GIT_OBJ_TREE) {
					if (! git_odb_exists(odb.get(), git_tree_entry_id(entry)))
						throw std::runtime_error("entry tree inexistant");
				}
				else if (git_tree_entry_type(entry) == GIT_OBJ_BLOB) {
					if (! git_odb_exists(odb.get(), git_tree_entry_id(entry)))
						missing_blob_oids.push_back(*git_tree_entry_id(entry));
				}
				else {
					throw std::runtime_error("entry type");
				}
			}
		}

		/* request missing blobs and write received into the repository */

		NS_STATUS("mainup net missing blob obtain");

		requestAndRecvAndWriteObjs(repo.get(), &missing_blob_oids);

		/* by now all required blobs should of been either preexistent or missing but written into the repository */

		/* required trees were confirmed present above and required blobs are present within the repository.
		   supposedly we have correctly received a full update. */

		NS_STATUS("mainup net commit and setref");

		git_oid new_commit_oid = writeCommitDummy(repo.get(), res_latest_oid);
		unique_ptr_gitreference new_ref(selfup_git_reference_create_and_force_set(repo.get(), m_ext->m_refname, new_commit_oid), deleteGitreference);

		m_ext->confirmUpdate();
	}

	git_oid getHeadTree(git_repository *repo, const std::string &refname)
	{
		git_oid oid_head(selfup_git_reference_name_to_id(repo, refname));
		unique_ptr_gitcommit commit_head(selfup_git_commit_lookup(repo, &oid_head), deleteGitcommit);
		unique_ptr_gittree   commit_tree(selfup_git_commit_tree(commit_head.get()), deleteGittree);
		return *git_tree_id(commit_tree.get());
	}

	git_oid writeCommitDummy(git_repository *repo, git_oid tree_oid)
	{
		unique_ptr_gitodb odb(selfup_git_repository_odb(repo), deleteGitodb);
		unique_ptr_gittree tree(selfup_git_tree_lookup(repo, &tree_oid), deleteGittree);
		unique_ptr_gitsignature sig(selfup_git_signature_new_dummy(), deleteGitsignature);

		git_buf buf = {};
		git_oid commit_oid_pre = {};
		git_oid commit_oid = {};

		if (!! git_commit_create_buffer(&buf, repo, sig.get(), sig.get(), "UTF-8", "Dummy", tree.get(), 0, NULL))
			throw std::runtime_error("git commit create buffer");

		if (!! git_odb_hash(&commit_oid_pre, buf.ptr, buf.size, GIT_OBJ_COMMIT))
			throw std::runtime_error("git odb hash");

		if (git_odb_exists(odb.get(), &commit_oid_pre))
			return commit_oid_pre;

		if (!! git_odb_write(&commit_oid, odb.get(), buf.ptr, buf.size, GIT_OBJ_COMMIT))
			throw std::runtime_error("git odb write");

		assert(git_oid_cmp(&commit_oid_pre, &commit_oid) == 0);

		return commit_oid;
	}

	/* @missing_obj_oids: will be popped as objects are received - empties completely on success */
	void requestAndRecvAndWriteObjs(git_repository *repo, std::deque<git_oid> *missing_obj_oids)
	{
		size_t missing_obj_request_limit = missing_obj_oids->size();
		do {
			NS_STATUS("mainup net objs req");

			NetworkPacket req_objs(SELFUP_CMD_REQUEST_OBJS3, networkpacket_cmd_tag_t());
			req_objs << (uint32_t) missing_obj_request_limit;
			for (size_t i = 0; i < missing_obj_request_limit; i++)
				req_objs.outSizedStr((char *) (*missing_obj_oids)[i].id, GIT_OID_RAWSZ);
			m_respond->respondOneshot(std::move(req_objs));

			std::vector<git_oid> received_obj_oids = recvAndWriteObjsUntilDone(repo);

			NS_STATUS("mainup net objs chk");

			for (size_t i = 0; i < received_obj_oids.size(); i++) {
				if (missing_obj_oids->empty() || git_oid_cmp(&received_obj_oids[i], &missing_obj_oids->front()) != 0)
					throw std::runtime_error("unsolicited obj received and written?");
				missing_obj_oids->pop_front();
			}

			missing_obj_request_limit = GS_MIN(missing_obj_oids->size(), received_obj_oids.size() * 2);
		} while (! missing_obj_oids->empty());
	}

	std::vector<git_oid> recvAndWriteObjsUntilDone(git_repository *repo)
	{
		std::vector<git_oid> received_blob_oids;
		unique_ptr_gitodb odb(selfup_git_repository_odb(repo), deleteGitodb);
		while (true) {
			NetworkPacket res_blobs = m_respond->waitFrame();
			uint8_t res_blobs_cmd = readGetCmd(&res_blobs);
			NS_STATUS("mainup net objs res");
			if (res_blobs_cmd == SELFUP_CMD_RESPONSE_OBJS3) {
				uint32_t size = 0;
				res_blobs >> size;

				ns_git::NsGitObject obj(ns_git::read_object_memory_ex(std::string(res_blobs.inSizedStr(size), size)));

				NS_STATUS("mainup net objs write");

				git_oid written_oid = {};
				if (!! git_odb_write(&written_oid, odb.get(), obj.m_inflated.data() + obj.m_inflated_offset, obj.m_inflated_size, (git_otype) obj.m_type))
					throw std::runtime_error("inflate write");
				received_blob_oids.push_back(written_oid);
			}
			else if (res_blobs_cmd == SELFUP_CMD_RESPONSE_OBJS3_DONE) {
				NS_STATUS("mainup net objs done");
				break;
			}
			else {
				throw std::runtime_error("cmd objs3");
			}
		}
		return received_blob_oids;
	}

private:
	std::shared_ptr<SelfupConExt2> m_ext;
};

void selfup_dryrun(std::string exe_filename)
{
	std::string arg(SELFUP_ARG_VERSUB);
	std::string command;
	command.append(exe_filename);
	command.append(" ");
	command.append(arg);

	int ret = system(command.c_str());

	if (ret != SELFUP_ARG_VERSUB_SUCCESS_CODE)
		throw std::runtime_error("dryrun retcode");
}

void selfup_reexec_probably_blocking(std::string exe_filename)
{
	std::string arg(SELFUP_ARG_CHILD);
	std::string command;
	command.append(exe_filename);
	command.append(" ");
	command.append(arg);

	int ret_ignored = system(command.c_str());
}

void selfup_checkout(std::string repopath, std::string refname, std::string checkoutpath)
{
	NS_STATUS("mainup checkout makedir");
	ns_filesys::directory_create_unless_exist(checkoutpath);

	NS_STATUS("mainup checkout ref and tree");

	unique_ptr_gitrepository repo(selfup_git_repository_open(repopath), deleteGitrepository);

	{
		RefKill rki(repo.get(), refname);

		git_oid commit_head_oid(selfup_git_reference_name_to_id(repo.get(), refname));
		unique_ptr_gitcommit commit_head(selfup_git_commit_lookup(repo.get(), &commit_head_oid), deleteGitcommit);
		unique_ptr_gittree   commit_tree(selfup_git_commit_tree(commit_head.get()), deleteGittree);

		NS_STATUS("mainup checkout tree");

		/* https://libgit2.github.com/docs/guides/101-samples/#objects_casting */
		// FIXME: reevaluate checkout_strategy flag GIT_CHECKOUT_REMOVE_UNTRACKED

		git_checkout_options opts = GIT_CHECKOUT_OPTIONS_INIT;
		opts.checkout_strategy = GIT_CHECKOUT_FORCE;
		opts.disable_filters = 1;
		opts.target_directory = checkoutpath.c_str();

		if (!! git_checkout_tree(repo.get(), (git_object *) commit_tree.get(), &opts))
			throw std::runtime_error("checkout tree");
	}
}

unique_ptr_gitrepository selfup_ensure_repository(const std::string &repopath, const std::string &sanity_check_lump)
{
	if (repopath.substr(repopath.size() - sanity_check_lump.size()) != sanity_check_lump)
		throw std::runtime_error("ensure repository sanity check");

	git_repository *repo = NULL;
	git_repository_init_options init_options = GIT_REPOSITORY_INIT_OPTIONS_INIT;
	assert(init_options.version == 1 && GIT_REPOSITORY_INIT_OPTIONS_VERSION == 1);
	/* MKPATH for whole path creation (MKDIR only the last component) */
	/* BARE could be used (ex no dotgit dir) */
	init_options.flags = GIT_REPOSITORY_INIT_NO_REINIT | GIT_REPOSITORY_INIT_MKDIR;
	init_options.mode = GIT_REPOSITORY_INIT_SHARED_UMASK;
	init_options.workdir_path = NULL;
	init_options.description = NULL;
	init_options.template_path = NULL;
	init_options.initial_head = NULL;
	init_options.origin_url = NULL;

	int err = git_repository_init_ext(&repo, repopath.c_str(), &init_options);
	if (!!err && err == GIT_EEXISTS) {
		assert(!repo);
		return unique_ptr_gitrepository(selfup_git_repository_open(repopath.c_str()), deleteGitrepository);
	}
	if (!!err)
		throw std::runtime_error("ensure repository init");

	return unique_ptr_gitrepository(repo, deleteGitrepository);
}

void selfup_start_mainupdate_crank(Address addr)
{
	std::string repopath = ns_filesys::current_executable_relative_filename("clnt_repo/.git");
	std::string refname = "refs/heads/master";
	std::string checkoutpath = ns_filesys::current_executable_relative_filename("clnt_chkout");
	selfup_ensure_repository(repopath, ".git");
	std::shared_ptr<SelfupConExt2> ext(new SelfupConExt2(repopath, refname));
	std::unique_ptr<SelfupWork2> work(new SelfupWork2(addr, ext));

	NS_STATUS("mainup net start");

	work->start();
	work->join();

	NS_STATUS("mainup net end");

	NS_STATUS("mainup checkout start");

	selfup_checkout(repopath, refname, checkoutpath);

	NS_STATUS("mainup checkout end");
}

void selfup_start_crank(Address addr)
{
	std::string cur_exe_filename = ns_filesys::current_executable_filename();
	std::shared_ptr<SelfupConExt1> ext(new SelfupConExt1(cur_exe_filename, "refs/heads/selfup"));
	std::unique_ptr<SelfupWork1> work(new SelfupWork1(addr, ext));

	NS_STATUS("selfup net start");

	work->start();
	work->join();

	NS_STATUS("selfup net end");

	if (! ext->m_update_have)
		return;

	NS_STATUS("selfup filesys start");

	std::string temp_filename = ns_filesys::build_modified_filename(
		cur_exe_filename, "", ".exe", "_helper", ".exe");
	std::string old_filename = ns_filesys::build_modified_filename(
		cur_exe_filename, "", ".exe", "_helper_old", ".exe");

	if (g_selfup_selfupdate_skip_fileops)
		return;

	NS_STATUS("selfup filesys write");

	ns_filesys::file_write_frombuffer(temp_filename, ext->m_update_buffer->data(), ext->m_update_buffer->size());

	NS_STATUS("selfup filesys dryrun");

	selfup_dryrun(temp_filename);

	NS_STATUS("selfup filesys rename");

	ns_filesys::rename_file_file(cur_exe_filename, old_filename);
	ns_filesys::rename_file_file(temp_filename, cur_exe_filename);

	NS_STATUS("selfup filesys reexec");

	selfup_reexec_probably_blocking(cur_exe_filename);

	NS_STATUS("selfup filesys end");
}

void toplevel(Address addr)
{
	NS_STATUS("startup");

	selfup_start_crank(addr);
	selfup_start_mainupdate_crank(addr);

	NS_STATUS("shutdown");
}

int main(int argc, char **argv)
{
	int ret = 0;

	tcpthreaded_startup_helper();

	if (git_libgit2_init() < 0)
		throw std::runtime_error("libgit2 init");

	ns_conf::Conf::initGlobal();
	NsLog::initGlobal();

	ns_gui::GuiCtx::initGlobal();
	g_gui_ctx->start();

	g_tcpasync_disable_timeout = g_conf->getDec("tcpasync_disable_timeout");

	Address addr(AF_INET, g_conf->getDec("serv_port"), g_conf->getHex("serv_conn_addr"), address_ipv4_tag_t());

	NS_TOPLEVEL_CATCH_SELFUP(ret, toplevel, addr);

	g_gui_ctx->stopRequest();
	g_gui_ctx->join();

	if (!! ret)
		NS_LOGDUMP(addr, 0x04030201);

	if (ret == 0)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}
