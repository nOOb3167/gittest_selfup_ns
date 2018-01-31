#include <cstring>
#include <exception>
#include <map>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>

#include <selfup/ns_git_shims.h>
#include <selfup/ns_helpers.h>
#include <selfup/TCPAsync.h>

#define SERVUP_THREAD_NUM 1

using namespace ns_git;

typedef TCPThreaded::Respond Respond;

class ServupCache
{
public:
	class Head
	{
	public:
		ns_git_oid m_commit_tree_oid = oid_zero();
		treemap_t  m_trees;
	};

	ServupCache() :
		m_cache()
	{}

	void refreshOid(const std::string &repopath, ns_git_oid wanted_oid)
	{
		/* ensure entry */
		auto it = m_cache.find(wanted_oid);
		if (it == m_cache.end())
			it = m_cache.insert(std::make_pair(wanted_oid, Head())).first;
		/* skip refresh if entry not outdated */
		if (oid_equals(it->second.m_commit_tree_oid, wanted_oid))
			return;
		/* actually refresh */
		it->second.m_commit_tree_oid = wanted_oid;
		it->second.m_trees = std::move(treelist_recursive(repopath, wanted_oid));
	}

	const treemap_t & getOidTrees(const std::string &repopath, ns_git_oid wanted_oid)
	{
		refreshOid(repopath, wanted_oid);
		assert(m_cache.find(wanted_oid) != m_cache.end());
		return m_cache.find(wanted_oid)->second.m_trees;
	}

public:
	std::map<ns_git_oid, Head, oid_comparator_t> m_cache;
};

class ServupConExt2
{
public:
	ServupConExt2(const std::string &repopath) :
		m_repopath(repopath),
		m_cache(new ServupCache())
	{};

	void cacheHeadRefresh(ns_git_oid wanted_oid)
	{
		m_cache->refreshOid(m_repopath, wanted_oid);
	}

public:
	std::string m_repopath;
	std::shared_ptr<ServupCache> m_cache;
};

class ServupWork2
{
public:
	ServupWork2(Address addr, size_t thread_num, std::shared_ptr<ServupConExt2> ext) :
		m_thrd(new TCPThreaded(addr, thread_num)),
		m_ext(ext)
	{}

	void start()
	{
		m_thrd->setFrameDispatch(std::bind(&ServupWork2::frameDispatch, this, std::placeholders::_1, std::placeholders::_2));
		m_thrd->startBoth();
	}

	void join()
	{
		m_thrd->joinBoth();
	}

	void frameDispatch(NetworkPacket *packet, Respond *respond)
	{
		uint8_t id;

		(*packet) >> id;

		switch (id)
		{

		case SELFUP_CMD_REQUEST_LATEST_SELFUPDATE_BLOB:
		{
			uint32_t refnum = 0;

			(*packet) >> refnum;

			std::string refname(packet->inSizedStr(refnum), refnum);
			ns_git_oid latest_oid(latest_selfupdate_blob_oid(m_ext->m_repopath, refname, SELFUP_SELFUPDATE_BLOB_ENTRY_FILENAME));

			NetworkPacket res_latest_selfupdate_pkt(SELFUP_CMD_RESPONSE_LATEST_SELFUPDATE_BLOB, networkpacket_cmd_tag_t());
			res_latest_selfupdate_pkt.outSizedStr((char *) latest_oid.id, NS_GIT_OID_RAWSZ);
			respond->respondOneshot(std::move(res_latest_selfupdate_pkt));
		}
		break;

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

			const treemap_t &trees = m_ext->m_cache->getOidTrees(m_ext->m_repopath, requested_oid);

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
	std::unique_ptr<TCPThreaded>  m_thrd;
	std::shared_ptr<ServupConExt2> m_ext;
};

void servup_start_crank(Address addr)
{
	std::string repopath = ns_filesys::current_executable_relative_filename("serv_repo/.git");
	std::shared_ptr<ServupConExt2> ext(new ServupConExt2(repopath));
	std::unique_ptr<ServupWork2> work(new ServupWork2(addr, SERVUP_THREAD_NUM, ext));
	work->start();
	work->join();
}

int main(int argc, char **argv)
{
	tcpsocket_startup_helper();
	servup_start_crank(Address(AF_INET, 6757, 0x7F000001, address_ipv4_tag_t()));

	return EXIT_SUCCESS;
}
