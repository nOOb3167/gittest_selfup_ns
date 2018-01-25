#include <exception>
#include <memory>
#include <stdexcept>
#include <thread>

#include <selfup/ns_git_shims.h>
#include <selfup/ns_helpers.h>
#include <selfup/TCPAsync.h>

#define SERVUP_ASYNC_TIMEOUT_MS 10000

using namespace ns_git;

typedef TCPAsync::Respond Respond;

class ServupWork
{
public:
	ServupWork(Address addr) :
		m_async(new TCPAsync1(addr, std::bind(&ServupWork::virtualFrameDispatch, this, std::placeholders::_1, std::placeholders::_2))),
		m_thread(),
		m_thread_exc()
	{
		m_thread.reset(new std::thread(&ServupWork::threadFunc, this));
	}

	void threadFunc()
	{
		try {
			m_async->Loop(SERVUP_ASYNC_TIMEOUT_MS);
		}
		catch (std::exception &) {
			m_thread_exc = std::current_exception();
		}
	}

	void join()
	{
		if (m_thread_exc)
			std::rethrow_exception(m_thread_exc);
	}

protected:
	virtual void virtualFrameDispatch(NetworkPacket *packet, Respond *respond) = 0;

private:
	std::unique_ptr<TCPAsync1>    m_async;
	std::unique_ptr<std::thread>  m_thread;
	std::exception_ptr            m_thread_exc;
};

class ServupCacheHead
{
public:
	ServupCacheHead(ns_git_oid commit_tree_oid, treemap_t trees) :
		m_commit_tree_oid(commit_tree_oid),
		m_trees(std::move(trees))
	{}

public:
	ns_git_oid m_commit_tree_oid;
	treemap_t  m_trees;
};

class ServupConExt2
{
public:
	ServupConExt2() {};

	void cacheHeadRefresh(ns_git_oid wanted_oid)
	{
		// FIXME: make cache head per-refname

		if (m_cache_head && oid_comparator_t()(m_cache_head->m_commit_tree_oid, wanted_oid))
			return;

		treemap_t trees(treelist_recursive(m_repopath, wanted_oid));
		std::shared_ptr<ServupCacheHead> cache_head(new ServupCacheHead(wanted_oid, std::move(trees)));

		m_cache_head = cache_head;
	}

public:
	std::string m_repopath;
	std::shared_ptr<ServupCacheHead> m_cache_head;
};

class ServupWork2 : public ServupWork
{
public:
	ServupWork2(Address addr, std::shared_ptr<ServupConExt2> ext) :
		ServupWork(addr),
		m_ext(ext)
	{}

	void virtualFrameDispatch(NetworkPacket *packet, Respond *respond) override
	{
		uint8_t id;

		(*packet) >> id;

		switch (id)
		{

		case SELFUP_CMD_REQUEST_LATEST_COMMIT_TREE:
		{
			uint32_t refnum = 0;

			(*packet) >> refnum;

			std::string refname(packet->inSizedStr(refnum), refnum);
			ns_git_oid latest_oid(latest_commit_tree_oid(m_ext->m_repopath, refname));

			m_ext->cacheHeadRefresh(latest_oid);

			NetworkPacket res_latest_pkt(SELFUP_CMD_RESPONSE_LATEST_COMMIT_TREE, networkpacket_cmd_tag_t());
			res_latest_pkt.outSizedStr((char *) latest_oid.id, NS_GIT_OID_RAWSZ);
			respond->respondOneshot(std::move(res_latest_pkt));
		}
		break;

		default:
			throw std::runtime_error("id");
		}
	}

private:
	std::shared_ptr<ServupConExt2> m_ext;
};

void servup_start_crank(Address addr)
{
	std::shared_ptr<ServupConExt2> ext(new ServupConExt2());
	std::unique_ptr<ServupWork2> work(new ServupWork2(addr, ext));
	work->join();
}

int main(int argc, char **argv)
{
	return EXIT_SUCCESS;
}
