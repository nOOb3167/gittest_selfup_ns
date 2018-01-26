#include <cstring>
#include <exception>
#include <memory>
#include <stdexcept>
#include <thread>

#include <selfup/ns_git_shims.h>
#include <selfup/ns_helpers.h>
#include <selfup/TCPAsync.h>

#define SERVUP_THREAD_NUM 16

using namespace ns_git;

typedef TCPThreaded::Respond Respond;

class ServupWork
{
public:
	ServupWork(Address addr, size_t thread_num) :
		m_thrd(new TCPThreaded1(addr, thread_num, std::bind(&ServupWork::virtualFrameDispatch, this, std::placeholders::_1, std::placeholders::_2))),
		m_thread(),
		m_thread_exc()
	{
		m_thread.reset(new std::thread(&ServupWork::threadFunc, this));
	}

	void threadFunc()
	{
		try {
			m_thrd->ListenLoop();
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
	std::unique_ptr<TCPThreaded1>    m_thrd;
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

		if (m_cache_head && oid_equals(m_cache_head->m_commit_tree_oid, wanted_oid))
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
	ServupWork2(Address addr, size_t thread_num, std::shared_ptr<ServupConExt2> ext) :
		ServupWork(addr, thread_num),
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

		case SELFUP_CMD_REQUEST_TREELIST:
		{
			ns_git_oid requested_oid = {};
			memcpy(requested_oid.id, packet->inSizedStr(NS_GIT_OID_RAWSZ), NS_GIT_OID_RAWSZ);

			/* serve from cache if applicable */

			const treemap_t &trees = oid_equals(m_ext->m_cache_head->m_commit_tree_oid, requested_oid)
				? m_ext->m_cache_head->m_trees
				: treelist_recursive(m_ext->m_repopath, requested_oid);

			NetworkPacket res_treelist_pkt(SELFUP_CMD_RESPONSE_TREELIST, networkpacket_cmd_tag_t());
			res_treelist_pkt << (uint32_t) trees.size();
			for (auto it = trees.begin(); it != trees.end(); ++it)
				res_treelist_pkt.outSizedStr((char *) it->second.m_oid.id, NS_GIT_OID_RAWSZ);
			respond->respondOneshot(std::move(res_treelist_pkt));
		}
		break;

		case SELFUP_CMD_REQUEST_OBJS3:
		{
			uint32_t oidnum = 0;

			(*packet) >> oidnum;

			for (size_t i = 0; i < oidnum; i++) {
				ns_git_oid requested_oid = {};
				memcpy(requested_oid.id, packet->inSizedStr(NS_GIT_OID_RAWSZ), NS_GIT_OID_RAWSZ);
				NsGitObject requested_obj = read_object(m_ext->m_repopath, requested_oid, true);
				NetworkPacket res_objs3(SELFUP_CMD_RESPONSE_OBJS3, networkpacket_cmd_tag_t());
				res_objs3 << (uint32_t) requested_obj.m_deflated.size();
				res_objs3.outSizedStr(requested_obj.m_deflated.data(), requested_obj.m_deflated.size());
				respond->respondOneshot(std::move(res_objs3));
			}

			NetworkPacket res_objs3_done(SELFUP_CMD_RESPONSE_OBJS3_DONE, networkpacket_cmd_tag_t());
			respond->respondOneshot(std::move(res_objs3_done));
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
	std::unique_ptr<ServupWork2> work(new ServupWork2(addr, SERVUP_THREAD_NUM, ext));
	work->join();
}

int main(int argc, char **argv)
{
	return EXIT_SUCCESS;
}
