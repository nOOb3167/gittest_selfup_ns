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
#include <selfup/ns_helpers.h>
#include <selfup/TCPSocket.h>

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

int selfup_disable_timeout = 1;

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
		uint32_t sz = packet.getDataSize();
		uint8_t buf[4] = { (sz >> 24) & 0xFF, (sz >> 16) & 0xFF, (sz >> 8) & 0xFF, (sz >> 0) & 0xFF };

		// FIXME: use writev / WSASend multibuffer

		m_sock->Send("FRAME", 5);
		m_sock->Send(buf, sizeof buf);

		m_sock->Send(packet.getDataPtr(), packet.getDataSize());
	}

	NetworkPacket virtualWaitFrame() override
	{
		long long timestamp = selfup_timestamp();
		const long long deadline = selfup_disable_timeout ? LLONG_MAX : timestamp + SELFUP_LONG_TIMEOUT_MS;
		long long buf_off = 0;
		std::string buf;
		int rcvt = 0;
		while (timestamp <= deadline) {
			/* decide how much data to wait for*/
			size_t wait_for = 0;

			if (buf_off < 9)
				wait_for = 9 - buf_off; /* decide to wait_for just header */
			if (buf_off >= 9) {
				/* validate */
				if (!! memcmp(&buf[0], "FRAME", 5))
					throw ProtocolExc("waitFrame frame");
				/* decide to wait_for header+data */
				uint32_t sz = (buf[5] << 24) | (buf[6] << 16) | (buf[7] << 8) | (buf[8] << 0);
				if (sz > SELFUP_FRAME_SIZE_MAX)
					throw std::runtime_error("waitFrame size");
				wait_for = (9 + sz) - buf_off;
				/* but we might have enough data already - so see if we can output */
				if (buf_off >= 9 + sz) {
					/* thanks to the wait_for mechanism should have exactly enough data - no leftover */
					assert(buf_off == 9 + sz);
					NetworkPacket packet((uint8_t *)&buf[9], sz, networkpacket_buf_len_tag_t());
					return std::move(packet);
				}
			}

			/* ensure space for wait_for */
			if (buf.size() < buf_off + wait_for)
				buf.resize(buf_off + wait_for);

			if (-1 == (rcvt = m_sock->ReceiveWaiting(((uint8_t *) buf.data()) + buf_off, wait_for, deadline - timestamp)))
				throw std::runtime_error("waitFrame time");
			buf_off += rcvt;

			timestamp = selfup_timestamp();
		}
		assert(! (timestamp <= deadline));
		throw std::runtime_error("waitFrame time");
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

	void threadFunc()
	{
		try {
			virtualThreadFunc();
		}
		catch (std::exception &) {
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

protected:
	std::shared_ptr<TCPSocket>     m_sock;
	std::unique_ptr<SelfupRespond> m_respond;
	std::unique_ptr<std::thread> m_thread;
	std::exception_ptr           m_thread_exc;
};

class SelfupConExt1
{
public:
	SelfupConExt1(const std::string &cur_exe_filename) :
		m_cur_exe_filename(cur_exe_filename),
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

		NetworkPacket req_blob_pkt(SELFUP_CMD_REQUEST_BLOB_SELFUPDATE, networkpacket_cmd_tag_t());
		req_blob_pkt.outSizedStr((char *) res_latest_oid.id, GIT_OID_RAWSZ);
		m_respond->respondOneshot(std::move(req_blob_pkt));

		NetworkPacket res_blob_pkt = m_respond->waitFrame();
		readEnsureCmd(&res_blob_pkt, SELFUP_CMD_RESPONSE_BLOB_SELFUPDATE);
		uint32_t res_blob_blen = 0;
		res_blob_pkt >> res_blob_blen;
		git_oid res_blob_oid = {};
		if (!! git_blob_create_frombuffer(&res_blob_oid, memory_repository.get(), res_blob_pkt.inSizedStr(res_blob_blen), res_blob_blen))
			throw std::runtime_error("blob");
		/* wtf? was the wrong blob sent? */
		if (git_oid_cmp(&res_blob_oid, &res_latest_oid) != 0)
			throw std::runtime_error("blob2");

		unique_ptr_gitblob blob(selfup_git_blob_lookup(memory_repository.get(), &res_blob_oid), deleteGitblob);

		std::unique_ptr<std::string> update_buffer(new std::string((char *) git_blob_rawcontent(blob.get()), git_blob_rawsize(blob.get())));

		m_ext->confirmUpdate(std::move(update_buffer));

		return;
	}

	void readEnsureCmd(NetworkPacket *packet, uint8_t cmdid)
	{
		assert(packet->isReset());
		uint8_t c;
		(*packet) >> c;
		if (c != cmdid)
			throw ProtocolExc("cmd");
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

		git_oid repo_head_tree_oid = {};
		try {
			git_oid repo_head_commit_oid = {};
			if (!! git_reference_name_to_id(&repo_head_commit_oid, repo.get(), m_ext->m_refname.c_str()))
				throw std::runtime_error("refname id");
			unique_ptr_gitcommit commit_head(selfup_git_commit_lookup(repo.get(), &repo_head_commit_oid), deleteGitcommit);
			unique_ptr_gittree   commit_tree(selfup_git_commit_tree(commit_head.get()), deleteGittree);
			git_oid_cpy(&repo_head_tree_oid, git_tree_id(commit_tree.get()));
		}
		catch (std::exception &) {
			// FIXME: handle only GIT_ENOTFOUND / missing case here
			git_oid_cpy(&repo_head_tree_oid, &oid_zero);
		}

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
				assert(inflated.size == inflated_size);
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
		throw std::runtime_error("");
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

void selfup_start_mainupdate_crank(Address addr)
{
	std::string repopath = ns_filesys::current_executable_relative_filename("clnt_repo/.git");
	std::shared_ptr<SelfupConExt2> ext(new SelfupConExt2(repopath, "refs/heads/master"));
	std::unique_ptr<SelfupWork2> work(new SelfupWork2(addr, ext));
	work->start();
	work->join();

	if (! ext->m_update_have)
		return;
}

void selfup_start_crank(Address addr)
{
	std::string cur_exe_filename = ns_filesys::current_executable_filename();
	std::shared_ptr<SelfupConExt1> ext(new SelfupConExt1(cur_exe_filename));
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

	selfup_dryrun(temp_filename);

	ns_filesys::rename_file_file(cur_exe_filename, old_filename);
	ns_filesys::rename_file_file(temp_filename, cur_exe_filename);

	selfup_reexec_probably_blocking(cur_exe_filename);
}

int main(int argc, char **argv)
{
	if (git_libgit2_init() < 0)
		throw std::runtime_error("libgit2 init");

	tcpsocket_startup_helper();
	//selfup_start_crank(Address(AF_INET, 6757, 0x7F000001, address_ipv4_tag_t()));
	selfup_start_mainupdate_crank(Address(AF_INET, 6757, 0x7F000001, address_ipv4_tag_t()));

	return EXIT_SUCCESS;
}
