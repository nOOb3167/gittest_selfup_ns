#include <cassert>
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

#include <selfup/NetworkPacket.h>
#include <selfup/ns_filesys.h>
#include <selfup/TCPSocket.h>

#define GS_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define GS_MIN(x, y) (((x) < (y)) ? (x) : (y))

#define SELFUP_ARG_CHILD "--xchild"
#define SELFUP_ARG_VERSUB "--xversub"
#define SELFUP_ARG_VERSUB_SUCCESS_CODE 42

#define SELFUP_FRAME_SIZE_MAX (256 * 1024 * 1024)
#define SELFUP_LONG_TIMEOUT_MS (30 * 1000)

#define SELFUP_CMD_REQUEST_BLOB_SELFUPDATE 9
#define SELFUP_CMD_RESPONSE_BLOB_SELFUPDATE 10
#define SELFUP_CMD_REQUEST_LATEST_SELFUPDATE_BLOB 11
#define SELFUP_CMD_RESPONSE_LATEST_SELFUPDATE_BLOB 12

typedef ::std::unique_ptr<git_repository, void(*)(git_repository *)> unique_ptr_gitrepository;
typedef ::std::unique_ptr<git_blob, void(*)(git_blob *)> unique_ptr_gitblob;
typedef ::std::unique_ptr<git_commit, void(*)(git_commit *)> unique_ptr_gitcommit;
typedef ::std::unique_ptr<git_tree, void(*)(git_tree *)> unique_ptr_gittree;
typedef ::std::unique_ptr<git_odb, void(*)(git_odb *)> unique_ptr_gitodb;

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
git_tree * selfup_git_commit_tree(git_repository *repository, git_commit *commit)
{
	git_tree *p = NULL;
	if (!! git_commit_tree(&p, commit))
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
		const long long deadline = timestamp + SELFUP_LONG_TIMEOUT_MS;
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
		m_thread.reset(new std::thread(&SelfupWork::threadFunc, this));
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

	void join()
	{
		if (m_thread_exc)
			std::rethrow_exception(m_thread_exc);
	}

protected:
	std::shared_ptr<TCPSocket>     m_sock;
	std::unique_ptr<SelfupRespond> m_respond;
	std::unique_ptr<std::thread> m_thread;
	std::exception_ptr           m_thread_exc;
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
	unique_ptr_gittree   commit_tree(selfup_git_commit_tree(repo.get(), commit_head.get()), deleteGittree);

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

void selfup_start_crank(Address addr)
{
	std::string cur_exe_filename = ns_filesys::current_executable_filename();
	std::shared_ptr<SelfupConExt1> ext(new SelfupConExt1(cur_exe_filename));
	std::unique_ptr<SelfupWork1> work(new SelfupWork1(addr, ext));
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

	return EXIT_SUCCESS;
}
