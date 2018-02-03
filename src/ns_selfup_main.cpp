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
#include <git2/sys/repository.h>  /* git_repository_new (no backends so custom may be added) */
#include <git2/sys/mempack.h>     /* in-memory backend */
#include <git2/sys/memes.h>

#include <selfup/NetworkPacket.h>
#include <selfup/ns_filesys.h>
#include <selfup/ns_gui.h>
#include <selfup/ns_helpers.h>
#include <selfup/TCPAsync.h>

#define SELFUP_ARG_CHILD "--xchild"
#define SELFUP_ARG_VERSUB "--xversub"
#define SELFUP_ARG_VERSUB_SUCCESS_CODE 42

#define SELFUP_FRAME_SIZE_MAX (256 * 1024 * 1024)
#define SELFUP_LONG_TIMEOUT_MS (30 * 1000)

typedef ::std::unique_ptr<git_repository, void(*)(git_repository *)> unique_ptr_gitrepository;
typedef ::std::unique_ptr<git_blob, void(*)(git_blob *)> unique_ptr_gitblob;
typedef ::std::unique_ptr<git_commit, void(*)(git_commit *)> unique_ptr_gitcommit;
typedef ::std::unique_ptr<git_tree, void(*)(git_tree *)> unique_ptr_gittree;
typedef ::std::unique_ptr<git_odb, void(*)(git_odb *)> unique_ptr_gitodb;
typedef ::std::unique_ptr<git_signature, void(*)(git_signature *)> unique_ptr_gitsignature;
typedef ::std::unique_ptr<git_reference, void(*)(git_reference *)> unique_ptr_gitreference;

int g_selfup_disable_timeout = 1;
int g_selfup_selfupdate_skip_fileops = 1;

void deleteGitrepository(git_repository *p)
{
	if (p)
		git_repository_free(p);
}
void deleteGitblob(git_blob *p)
{
	if (p)
		git_blob_free(p);
}
void deleteGitcommit(git_commit *p)
{
	if (p)
		git_commit_free(p);
}
void deleteGittree(git_tree *p)
{
	if (p)
		git_tree_free(p);
}
void deleteGitodb(git_odb *p)
{
	if (p)
		git_odb_free(p);
}
void deleteGitsignature(git_signature *p)
{
	if (p)
		git_signature_free(p);
}
void deleteGitreference(git_reference *p)
{
	if (p)
		git_reference_free(p);
}
git_repository * selfup_git_repository_new()
{
	/* https://github.com/libgit2/libgit2/blob/master/include/git2/sys/repository.h */
	git_repository *p = NULL;
	if (!! git_repository_new(&p))
		throw std::runtime_error("repository new");
	return p;
}
git_repository * selfup_git_repository_open(std::string path)
{
	git_repository *p = NULL;
	if (!! git_repository_open(&p, path.c_str()))
		throw std::runtime_error("repository new");
	return p;
}
git_odb * selfup_git_repository_odb(git_repository *repository)
{
	git_odb *p = NULL;
	if (!! git_repository_odb(&p, repository))
		throw std::runtime_error("repository odb");
	return p;
}

git_repository * selfup_git_memory_repository_new()
{
	int r = 0;

	unique_ptr_gitrepository repository_memory(selfup_git_repository_new(), deleteGitrepository);
	unique_ptr_gitodb repository_odb(selfup_git_repository_odb(repository_memory.get()), deleteGitodb);

	/* NOTE: backend is owned by odb, and odb is owned by repository.
	         backend thus destroyed indirectly with the repository. */
	git_odb_backend *backend_memory = NULL;
	/* https://github.com/libgit2/libgit2/blob/master/include/git2/sys/mempack.h */
	if (!!(r = git_mempack_new(&backend_memory)))
		throw std::runtime_error("mempack");
	if (!!(r = git_odb_add_backend(repository_odb.get(), backend_memory, 999)))
		throw std::runtime_error("backend");

	return repository_memory.release();
}

git_signature * selfup_git_signature_new_dummy()
{
	git_signature *sig = NULL;
	if (!! git_signature_new(&sig, "DummyName", "DummyEMail", 0, 0))
		throw std::runtime_error("signature");
	return sig;
}

git_reference * selfup_git_reference_create_and_force_set(git_repository *repo, const std::string &refname, git_oid commit_oid)
{
	git_reference *ref = NULL;
	if (!! git_reference_create(&ref, repo, refname.c_str(), &commit_oid, true, "DummyLogMessage"))
		throw std::runtime_error("reference");
	return ref;
}

git_blob * selfup_git_blob_lookup(git_repository *repository, git_oid *oid)
{
	git_blob *p = NULL;
	if (!! git_blob_lookup(&p, repository, oid))
		throw std::runtime_error("blob lookup");
	return p;
}
git_commit * selfup_git_commit_lookup(git_repository *repository, git_oid *oid)
{
	// FIXME: not sure if GIT_ENOTFOUND return counts as official API for git_commit_lookup
	//        but may be useful as optional extra failure information ?
	git_commit *p = NULL;
	if (!! git_commit_lookup(&p, repository, oid))
		throw std::runtime_error("commit lookup");
	return p;
}
git_tree * selfup_git_commit_tree(git_commit *commit)
{
	git_tree *p = NULL;
	if (!! git_commit_tree(&p, commit))
		throw std::runtime_error("commit tree");
	return p;
}
git_tree * selfup_git_tree_lookup(git_repository *repository, git_oid *oid)
{
	git_tree *p = NULL;
	if (!! git_tree_lookup(&p, repository, oid))
		throw std::runtime_error("tree lookup");
	return p;
}

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

		NetworkPacket packet_req_latest(SELFUP_CMD_REQUEST_LATEST_SELFUPDATE_BLOB, networkpacket_cmd_tag_t());
		packet_req_latest << (uint32_t) m_ext->m_refname.size();
		packet_req_latest.outSizedStr(m_ext->m_refname.data(), m_ext->m_refname.size());
		m_respond->respondOneshot(std::move(packet_req_latest));

		NetworkPacket res_latest_pkt = m_respond->waitFrame();
		readEnsureCmd(&res_latest_pkt, SELFUP_CMD_RESPONSE_LATEST_SELFUPDATE_BLOB);
		git_oid res_latest_oid = {};
		git_oid_fromraw(&res_latest_oid, (const unsigned char *) res_latest_pkt.inSizedStr(GIT_OID_RAWSZ));

		git_oid oid_cur_exe = {};
		/* empty as_path parameter means no filters applied */
		if (!! git_repository_hashfile(&oid_cur_exe, memory_repository.get(), m_ext->m_cur_exe_filename.c_str(), GIT_OBJ_BLOB, ""))
			throw std::runtime_error("hash");

		if (git_oid_cmp(&oid_cur_exe, &res_latest_oid) == 0)
			return;

		requestAndRecvAndWriteObj(memory_repository.get(), res_latest_oid);

		unique_ptr_gitblob blob(selfup_git_blob_lookup(memory_repository.get(), &res_latest_oid), deleteGitblob);

		std::unique_ptr<std::string> update_buffer(new std::string((char *) git_blob_rawcontent(blob.get()), git_blob_rawsize(blob.get())));

		m_ext->confirmUpdate(std::move(update_buffer));

		return;
	}

	void requestAndRecvAndWriteObj(git_repository *memory_repository, git_oid missing_obj_oid)
	{
		/* REQ_OBJS3 */

		NetworkPacket req_obj_pkt(SELFUP_CMD_REQUEST_OBJS3, networkpacket_cmd_tag_t());
		req_obj_pkt << (uint32_t) 1;
		req_obj_pkt.outSizedStr((char *) missing_obj_oid.id, GIT_OID_RAWSZ);
		m_respond->respondOneshot(std::move(req_obj_pkt));

		/* RES_OBJS3 */

		NetworkPacket res_obj_pkt = m_respond->waitFrame();
		readEnsureCmd(&res_obj_pkt, SELFUP_CMD_RESPONSE_OBJS3);
		uint32_t res_obj_blen = 0;
		res_obj_pkt >> res_obj_blen;

		git_buf inflated = {};
		git_otype inflated_type = GIT_OBJ_BAD;
		size_t inflated_offset = 0;
		size_t inflated_size = 0;
		if (!! git_memes_inflate(res_obj_pkt.inSizedStr(res_obj_blen), res_obj_blen, &inflated, &inflated_type, &inflated_offset, &inflated_size))
			throw std::runtime_error("inflate");
		if (inflated_type != GIT_OBJ_BLOB)
			throw std::runtime_error("inflate type");
		// FIXME: legacy memes_inflate (as opposed to ns_git::read_object) appends trailing zero so -1
		assert(inflated_offset + inflated_size == inflated.size - 1);

		git_oid written_oid = {};
		if (!! git_blob_create_frombuffer(&written_oid, memory_repository, inflated.ptr + inflated_offset, inflated_size))
			throw std::runtime_error("blob create from buffer");
		if (git_oid_cmp(&written_oid, &missing_obj_oid) != 0)
			throw std::runtime_error("blob mismatch");

		/* RES_OBJS3_DONE */

		NetworkPacket res_obj_done_pkt = m_respond->waitFrame();
		readEnsureCmd(&res_obj_done_pkt, SELFUP_CMD_RESPONSE_OBJS3_DONE);
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

		NetworkPacket packet_req_latest(SELFUP_CMD_REQUEST_LATEST_COMMIT_TREE, networkpacket_cmd_tag_t());
		packet_req_latest << (uint32_t) m_ext->m_refname.size();
		packet_req_latest.outSizedStr(m_ext->m_refname.data(), m_ext->m_refname.size());
		m_respond->respondOneshot(std::move(packet_req_latest));

		NetworkPacket res_latest_pkt = m_respond->waitFrame();
		readEnsureCmd(&res_latest_pkt, SELFUP_CMD_RESPONSE_LATEST_COMMIT_TREE);
		git_oid res_latest_oid = {};
		git_oid_fromraw(&res_latest_oid, (const unsigned char *) res_latest_pkt.inSizedStr(GIT_OID_RAWSZ));

		/* determine local version git_oid - defaults to zeroed-out */

		git_oid repo_head_tree_oid = getHeadTree(repo.get(), m_ext->m_refname);

		/* matching versions suggest an update is unnecessary */

		if (git_oid_cmp(&repo_head_tree_oid, &res_latest_oid) == 0)
			return;

		/* request list of trees comprising latest version */

		NetworkPacket req_treelist_pkt(SELFUP_CMD_REQUEST_TREELIST, networkpacket_cmd_tag_t());
		req_treelist_pkt.outSizedStr((char *) res_latest_oid.id, GIT_OID_RAWSZ);
		m_respond->respondOneshot(std::move(req_treelist_pkt));

		NetworkPacket res_treelist_pkt = m_respond->waitFrame();
		readEnsureCmd(&res_treelist_pkt, SELFUP_CMD_RESPONSE_TREELIST);
		uint32_t res_treelist_treenum = 0;
		std::vector<git_oid> res_treelist_treevec;
		res_treelist_pkt >> res_treelist_treenum;
		for (size_t i = 0; i < res_treelist_treenum; i++) {
			git_oid tmp = {};
			memcpy(tmp.id, res_treelist_pkt.inSizedStr(GIT_OID_RAWSZ), GIT_OID_RAWSZ);
			res_treelist_treevec.push_back(tmp);
		}

		/* determine which trees are missing */

		std::deque<git_oid> missing_tree_oids;
		for (size_t i = 0; i < res_treelist_treevec.size(); i++) {
			try {
				unique_ptr_gittree tree(selfup_git_tree_lookup(repo.get(), &res_treelist_treevec[i]), deleteGittree);
			}
			catch (std::exception &) {
				// FIXME: handle only GIT_ENOTFOUND / missing case here
				missing_tree_oids.push_back(res_treelist_treevec[i]);
			}
		}

		/* request missing trees and write received into the repository */

		requestAndRecvAndWriteObjs(repo.get(), &missing_tree_oids);

		/* determine which blobs are missing - validating trees and their entries in the meantime */

		/* by now all required trees should of been either preexistent or missing but written into the repository.
		   validating trees comprises of:
		     - confirming existence of trees themselves
			 - examining the trees' entries:
			   - tree entries for existence
			   - blob entries for existence, recording missing blobs */

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
					if (git_odb_exists(odb.get(), git_tree_entry_id(entry)))
						continue;
					missing_blob_oids.push_back(*git_tree_entry_id(entry));
				}
				else {
					throw std::runtime_error("entry type");
				}
			}
		}

		/* request missing blobs and write received into the repository */

		requestAndRecvAndWriteObjs(repo.get(), &missing_blob_oids);

		/* by now all required blobs should of been either preexistent or missing but written into the repository */

		/* required trees were confirmed present above and required blobs are present within the repository.
		   supposedly we have correctly received a full update. */

		git_oid new_commit_oid = writeCommitDummy(repo.get(), res_latest_oid);
		unique_ptr_gitreference new_ref(selfup_git_reference_create_and_force_set(repo.get(), m_ext->m_refname, new_commit_oid), deleteGitreference);

		m_ext->confirmUpdate();
	}

	git_oid getHeadTree(git_repository *repo, const std::string &refname)
	{
		git_oid oid_zero = {};
		git_oid repo_head_commit_oid = {};
		git_oid repo_head_tree_oid = {};
		
		int err = git_reference_name_to_id(&repo_head_commit_oid, repo, refname.c_str());
		if (!!err && err != GIT_ENOTFOUND)
			throw std::runtime_error("refname id");
		
		if (err == GIT_ENOTFOUND) {
			git_oid_cpy(&repo_head_tree_oid, &oid_zero);
		}
		else {
			unique_ptr_gitcommit commit_head(selfup_git_commit_lookup(repo, &repo_head_commit_oid), deleteGitcommit);
			unique_ptr_gittree   commit_tree(selfup_git_commit_tree(commit_head.get()), deleteGittree);
			git_oid_cpy(&repo_head_tree_oid, git_tree_id(commit_tree.get()));
		}
		return repo_head_tree_oid;
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
			NetworkPacket req_objs(SELFUP_CMD_REQUEST_OBJS3, networkpacket_cmd_tag_t());
			req_objs << (uint32_t) missing_obj_request_limit;
			for (size_t i = 0; i < missing_obj_request_limit; i++)
				req_objs.outSizedStr((char *) (*missing_obj_oids)[i].id, GIT_OID_RAWSZ);
			m_respond->respondOneshot(std::move(req_objs));

			std::vector<git_oid> received_obj_oids = recvAndWriteObjsUntilDone(repo);

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
			if (res_blobs_cmd == SELFUP_CMD_RESPONSE_OBJS3) {
				uint32_t size = 0;
				res_blobs >> size;
				git_buf inflated = {};
				git_otype inflated_type = GIT_OBJ_BAD;
				size_t inflated_offset = 0;
				size_t inflated_size = 0;
				if (!! git_memes_inflate(res_blobs.inSizedStr(size), size, &inflated, &inflated_type, &inflated_offset, &inflated_size))
					throw std::runtime_error("inflate");
				if (inflated_type == GIT_OBJ_BAD)
					throw std::runtime_error("inflate type");
				// FIXME: legacy memes_inflate (as opposed to ns_git::read_object) appends trailing zero so -1
				assert(inflated_offset + inflated_size == inflated.size - 1);
				// FIXME: compute and check hash before writing?
				//        see git_odb_hash
				git_oid written_oid = {};
				if (!! git_odb_write(&written_oid, odb.get(), inflated.ptr + inflated_offset, inflated_size, inflated_type))
					throw std::runtime_error("inflate write");
				received_blob_oids.push_back(written_oid);
			}
			else if (res_blobs_cmd == SELFUP_CMD_RESPONSE_OBJS3_DONE) {
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
	unique_ptr_gitrepository repo(selfup_git_repository_open(repopath), deleteGitrepository);

	git_oid commit_head_oid = {};

	if (!! git_reference_name_to_id(&commit_head_oid, repo.get(), refname.c_str()))
		throw std::runtime_error("refname id");

	unique_ptr_gitcommit commit_head(selfup_git_commit_lookup(repo.get(), &commit_head_oid), deleteGitcommit);
	unique_ptr_gittree   commit_tree(selfup_git_commit_tree(commit_head.get()), deleteGittree);

	ns_filesys::directory_create_unless_exist(checkoutpath);

	git_checkout_options opts = GIT_CHECKOUT_OPTIONS_INIT;
	opts.checkout_strategy = 0;
	opts.checkout_strategy |= GIT_CHECKOUT_FORCE;
	// FIXME: want this flag but bugs have potential to cause more damage - enable after enough testing
	//opts.checkout_strategy |= GIT_CHECKOUT_REMOVE_UNTRACKED;

	opts.disable_filters = 1;
	opts.target_directory = checkoutpath.c_str();

	/* https://libgit2.github.com/docs/guides/101-samples/#objects_casting */
	if (!! git_checkout_tree(repo.get(), (git_object *) commit_tree.get(), &opts))
		throw std::runtime_error("checkout tree");
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
	work->start();
	work->join();

	selfup_checkout(repopath, refname, checkoutpath);
}

void selfup_start_crank(Address addr)
{
	std::string cur_exe_filename = ns_filesys::current_executable_filename();
	std::shared_ptr<SelfupConExt1> ext(new SelfupConExt1(cur_exe_filename, "refs/heads/selfup"));
	std::unique_ptr<SelfupWork1> work(new SelfupWork1(addr, ext));

	work->start();
	work->join();

	if (! ext->m_update_have)
		return;

	std::string temp_filename = ns_filesys::build_modified_filename(
		cur_exe_filename, "", ".exe", "_helper", ".exe");
	std::string old_filename = ns_filesys::build_modified_filename(
		cur_exe_filename, "", ".exe", "_helper_old", ".exe");

	ns_filesys::file_write_frombuffer(temp_filename, ext->m_update_buffer->data(), ext->m_update_buffer->size());

	if (g_selfup_selfupdate_skip_fileops)
		return;

	selfup_dryrun(temp_filename);

	ns_filesys::rename_file_file(cur_exe_filename, old_filename);
	ns_filesys::rename_file_file(temp_filename, cur_exe_filename);

	selfup_reexec_probably_blocking(cur_exe_filename);
}

int main(int argc, char **argv)
{
	tcpthreaded_startup_helper();

	if (git_libgit2_init() < 0)
		throw std::runtime_error("libgit2 init");

	ns_gui::GuiCtx::initGlobal();
	g_gui_ctx->start();

	NS_GUI_MODE_RATIO(3, 5);
	NS_GUI_STATUS("hello world");

	selfup_start_crank(Address(AF_INET, 6757, 0x7F000001, address_ipv4_tag_t()));
	selfup_start_mainupdate_crank(Address(AF_INET, 6757, 0x7F000001, address_ipv4_tag_t()));

	g_gui_ctx->join();

	return EXIT_SUCCESS;
}
