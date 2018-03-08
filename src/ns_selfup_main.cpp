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
#include <vector>

#include <git2.h>

#include <ns_version.h>
#include <selfup/NetworkPacket.h>
#include <selfup/ns_conf.h>
#include <selfup/ns_crash.h>
#include <selfup/ns_filesys.h>
#include <selfup/ns_git_aux.h>
#include <selfup/ns_git_shims.h>
#include <selfup/ns_gui.h>
#include <selfup/ns_helpers.h>
#include <selfup/ns_log.h>
#include <selfup/ns_selfup_aux.h>
#include <selfup/TCPAsync.h>

#define SELFUP_ARG_CHILD "--xchild"
#define SELFUP_ARG_VERSUB "--xversub"
#define SELFUP_ARG_VERSUB_SUCCESS_CODE 42

int g_selfup_selfupdate_skip_fileops = 0;

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

class SelfupWork2 : public SelfupThread
{
public:
	SelfupWork2(const char *node, const char *service, std::shared_ptr<SelfupConExt2> ext) :
		m_respond(new SelfupRespond(std::shared_ptr<TCPSocket>(new TCPSocket(node, service, tcpsocket_connect_tag_t())))),
		m_ext(ext)
	{}

	void virtualThreadFunc() override
	{
		git_oid oid_zero = {};
		unique_ptr_gitrepository repo(selfup_git_repository_open(m_ext->m_repopath));

		/* request latest version git_oid */

		NS_STATUS("mainup net latest request");

		NetworkPacket packet_req_latest(SELFUP_CMD_REQUEST_LATEST_COMMIT_TREE, networkpacket_cmd_tag_t());
		packet_req_latest << (uint32_t) m_ext->m_refname.size();
		packet_req_latest.outSizedStr(m_ext->m_refname.data(), m_ext->m_refname.size());
		m_respond->respondOneshot(std::move(packet_req_latest));

		NetworkPacket res_latest_pkt = m_respond->waitFrame();
		res_latest_pkt.readEnsureCmd(SELFUP_CMD_RESPONSE_LATEST_COMMIT_TREE);
		NS_STATUS("mainup net latest response");
		git_oid res_latest_oid = {};
		git_oid_fromraw(&res_latest_oid, (const unsigned char *) res_latest_pkt.inSizedStr(GIT_OID_RAWSZ));

		/* determine local version git_oid - defaults to zeroed-out */

		NS_STATUS("mainup net headtree");

		git_oid repo_head_tree_oid = getHeadTreeOrDefaultZero(repo.get(), m_ext->m_refname);

		/* matching versions suggest an update is unnecessary */

		if (git_oid_cmp(&repo_head_tree_oid, &res_latest_oid) == 0)
			return;

		/* request list of trees comprising latest version */

		NS_STATUS("mainup net treelist request");

		NetworkPacket req_treelist_pkt(SELFUP_CMD_REQUEST_TREELIST, networkpacket_cmd_tag_t());
		req_treelist_pkt.outSizedStr((char *) res_latest_oid.id, GIT_OID_RAWSZ);
		m_respond->respondOneshot(std::move(req_treelist_pkt));

		NetworkPacket res_treelist_pkt = m_respond->waitFrame();
		res_treelist_pkt.readEnsureCmd(SELFUP_CMD_RESPONSE_TREELIST);
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
			unique_ptr_gitodb odb(selfup_git_repository_odb(repo.get()));
			unique_ptr_gittree tree(selfup_git_tree_lookup(repo.get(), &res_treelist_treevec[i]));
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
		unique_ptr_gitreference new_ref(selfup_git_reference_create_and_force_set(repo.get(), m_ext->m_refname, new_commit_oid));

		m_ext->confirmUpdate();
	}

	git_oid getHeadTreeOrDefaultZero(git_repository *repo, const std::string &refname)
	{
		try {
			git_oid oid_head(selfup_git_reference_name_to_id(repo, refname));
			unique_ptr_gitcommit commit_head(selfup_git_commit_lookup(repo, &oid_head));
			unique_ptr_gittree   commit_tree(selfup_git_commit_tree(commit_head.get()));
			return *git_tree_id(commit_tree.get());
		}
		catch (const std::exception &e) {
			git_oid oid_zero = {};
			return oid_zero;
		}
	}

	git_oid writeCommitDummy(git_repository *repo, git_oid tree_oid)
	{
		unique_ptr_gitodb odb(selfup_git_repository_odb(repo));
		unique_ptr_gittree tree(selfup_git_tree_lookup(repo, &tree_oid));
		unique_ptr_gitsignature sig(selfup_git_signature_new_dummy());

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
		size_t gui_missing_initial_size = missing_obj_oids->size();
		size_t gui_received_count = 0;

		size_t missing_obj_request_limit = missing_obj_oids->size();
		do {
			NS_STATUS("mainup net objs req");

			NetworkPacket req_objs(SELFUP_CMD_REQUEST_OBJS3, networkpacket_cmd_tag_t());
			req_objs << (uint32_t) missing_obj_request_limit;
			for (size_t i = 0; i < missing_obj_request_limit; i++)
				req_objs.outSizedStr((char *) (*missing_obj_oids)[i].id, GIT_OID_RAWSZ);
			m_respond->respondOneshot(std::move(req_objs));

			std::vector<git_oid> received_obj_oids = recvAndWriteObjsUntilDone(repo, gui_missing_initial_size, &gui_received_count);

			NS_STATUS("mainup net objs chk");

			for (size_t i = 0; i < received_obj_oids.size(); i++) {
				if (missing_obj_oids->empty() || git_oid_cmp(&received_obj_oids[i], &missing_obj_oids->front()) != 0)
					throw std::runtime_error("unsolicited obj received and written?");
				missing_obj_oids->pop_front();
			}

			missing_obj_request_limit = GS_MIN(missing_obj_oids->size(), received_obj_oids.size() * 2);
		} while (! missing_obj_oids->empty());
	}

	std::vector<git_oid> recvAndWriteObjsUntilDone(git_repository *repo, size_t gui_missing_initial_size, size_t *gui_received_count)
	{
		std::vector<git_oid> received_blob_oids;
		unique_ptr_gitodb odb(selfup_git_repository_odb(repo));
		while (true) {
			NetworkPacket res_blobs = m_respond->waitFrame();
			uint8_t res_blobs_cmd = res_blobs.readGetCmd();

			if (res_blobs_cmd == SELFUP_CMD_RESPONSE_OBJS3) {
				uint32_t size = 0;
				res_blobs >> size;

				ns_git::NsGitObject obj(ns_git::read_object_memory_ex(std::string(res_blobs.inSizedStr(size), size)));

				git_oid written_oid = {};
				if (!! git_odb_write(&written_oid, odb.get(), obj.m_inflated.data() + obj.m_inflated_offset, obj.m_inflated_size, (git_otype) obj.m_type))
					throw std::runtime_error("inflate write");
				received_blob_oids.push_back(written_oid);

				NS_GUI_MODE_RATIO(gui_missing_initial_size - (*gui_received_count)++, gui_missing_initial_size);
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
	std::unique_ptr<SelfupRespond> m_respond;
	std::shared_ptr<SelfupConExt2> m_ext;
};

void selfup_dryrun(std::string exe_filename)
{
	long long ret;
	ns_filesys::process_start(exe_filename, { SELFUP_ARG_VERSUB }, &ret);
	if (ret != SELFUP_ARG_VERSUB_SUCCESS_CODE)
		throw std::runtime_error("dryrun retcode");
}

void selfup_reexec(std::string exe_filename)
{
	ns_filesys::process_start(exe_filename, { SELFUP_ARG_CHILD }, NULL);
}

void selfup_mainexec(std::string exe_filename)
{
	ns_filesys::process_start(exe_filename, {}, NULL);
}

void selfup_checkout(std::string repopath, std::string refname, std::string checkoutpath)
{
	NS_STATUS("mainup checkout makedir");
	ns_filesys::directory_create_unless_exist(checkoutpath);

	NS_STATUS("mainup checkout ref and tree");

	unique_ptr_gitrepository repo(selfup_git_repository_open(repopath));

	{
		RefKill rki(repo.get(), refname);

		git_oid commit_head_oid(selfup_git_reference_name_to_id(repo.get(), refname));
		unique_ptr_gitcommit commit_head(selfup_git_commit_lookup(repo.get(), &commit_head_oid));
		unique_ptr_gittree   commit_tree(selfup_git_commit_tree(commit_head.get()));

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

std::string selfup_checkout_memory(std::string repopath, std::string refname)
{
	unique_ptr_gitrepository repo(selfup_git_repository_open(repopath));

	{
		RefKill rki(repo.get(), refname);

		git_oid commit_head_oid(selfup_git_reference_name_to_id(repo.get(), refname));
		unique_ptr_gitcommit commit_head(selfup_git_commit_lookup(repo.get(), &commit_head_oid));
		unique_ptr_gittree   commit_tree(selfup_git_commit_tree(commit_head.get()));

		const git_tree_entry *entry = git_tree_entry_byname(commit_tree.get(), SELFUP_SELFUPDATE_BLOB_ENTRY_FILENAME);
		unique_ptr_gitblob blob(selfup_git_blob_lookup(repo.get(), git_tree_entry_id(entry)));
		std::string update_buffer((char *)git_blob_rawcontent(blob.get()), (size_t)git_blob_rawsize(blob.get()));
		return update_buffer;
	}
	throw std::runtime_error("checkout memory");
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
		return unique_ptr_gitrepository(selfup_git_repository_open(repopath.c_str()));
	}
	if (!!err)
		throw std::runtime_error("ensure repository init");

	return unique_ptr_gitrepository(repo, deleteGitrepository);
}

void selfup_start_mainupdate_crank(const char *node, const char *service)
{
	std::string repopath = ns_filesys::current_executable_relative_filename("clnt_repo/.git");
	std::string refname = "refs/heads/mainup";
	std::string checkoutpath = ns_filesys::current_executable_relative_filename("clnt_chkout");
	selfup_ensure_repository(repopath, ".git");
	std::shared_ptr<SelfupConExt2> ext(new SelfupConExt2(repopath, refname));
	std::unique_ptr<SelfupWork2> work(new SelfupWork2(node, service, ext));

	NS_STATUS("mainup net start");

	work->start();
	work->join();

	NS_STATUS("mainup net end");

	NS_STATUS("mainup checkout start");

	selfup_checkout(repopath, refname, checkoutpath);

	NS_STATUS("mainup checkout end");

	selfup_mainexec(ns_filesys::path_append_abs_rel(checkoutpath, "bin/minetest.exe"));
}

bool selfup_start_crank(const char *node, const char *service)
{
	std::string cur_exe_filename = ns_filesys::current_executable_filename();
	std::string repopath = ns_filesys::current_executable_relative_filename("clnt_repo/.git");
	std::string refname = "refs/heads/selfup";
	selfup_ensure_repository(repopath, ".git");
	std::shared_ptr<SelfupConExt2> ext(new SelfupConExt2(repopath, refname));
	std::unique_ptr<SelfupWork2> work(new SelfupWork2(node, service, ext));

	NS_STATUS("selfup net start");

	work->start();
	work->join();

	NS_STATUS("selfup net end");

	if (! ext->m_update_have)
		return false;

	if (g_selfup_selfupdate_skip_fileops)
		return false;

	NS_STATUS("selfup filesys start");

	std::string temp_filename = ns_filesys::build_modified_filename(
		cur_exe_filename, "", ".exe", "_helper", ".exe");
	std::string old_filename = ns_filesys::build_modified_filename(
		cur_exe_filename, "", ".exe", "_helper_old", ".exe");

	NS_STATUS("selfup filesys write");

	std::string update_buffer = selfup_checkout_memory(repopath, refname);

	ns_filesys::file_write_frombuffer(temp_filename, update_buffer.data(), update_buffer.size());

	NS_STATUS("selfup filesys dryrun");

	selfup_dryrun(temp_filename);

	NS_STATUS("selfup filesys rename");

	ns_filesys::rename_file_file(cur_exe_filename, old_filename);
	ns_filesys::rename_file_file(temp_filename, cur_exe_filename);

	NS_STATUS("selfup filesys reexec");

	selfup_reexec(cur_exe_filename);

	NS_STATUS("selfup filesys end");

	return true;
}

void toplevel(const char *node, const char *service)
{
	NS_STATUS("startup");

	NS_STATUS(NS_GITVER);

	if (! selfup_start_crank(node, service))
		selfup_start_mainupdate_crank(node, service);

	NS_STATUS("shutdown");
}

void global_initialization()
{
	/* init */

	tcpthreaded_startup_helper();

#ifdef NS_DEF_USING_LIBGIT2
	if (git_libgit2_init() < 0)
		throw std::runtime_error("libgit2 init");
#endif

	ns_conf::Conf::initGlobal();
	ns_log::NsLog::initGlobal();
	ns_gui::GuiCtx::initGlobal();

	/* global config */

	g_crash_mbox = g_conf->getDec("crash_mbox");
	g_tcpasync_disable_timeout = g_conf->getDec("tcpasync_disable_timeout");
	g_selfup_selfupdate_skip_fileops = g_conf->getDec("selfupdate_skip_fileops");

	/* more init */

	ns_crash_handler_setup(g_conf->get("serv_conn_addr").c_str(), g_conf->get("serv_port").c_str());
}

int main(int argc, char **argv)
{
	int ret = 0;

	if (argc >= 2 && std::string(argv[1]) == SELFUP_ARG_VERSUB)
		return SELFUP_ARG_VERSUB_SUCCESS_CODE;

	if (argc >= 2 && std::string(argv[1]) == SELFUP_ARG_CHILD)
		(void) 0;

	global_initialization();

	g_gui_ctx->start();

	NS_TOPLEVEL_CATCH_SELFUP(ret, toplevel, g_conf->get("serv_conn_addr").c_str(), g_conf->get("serv_port").c_str());

	g_gui_ctx->stopRequest();
	g_gui_ctx->join();

	if (!! ret)
		TCPASYNC_LOGDUMP(g_crash_addrinfo.get(), 0x04030201);

	if (ret == 0)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}
