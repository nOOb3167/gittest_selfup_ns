#include <cstdio>
#include <cstring>
#include <exception>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include <selfup/ns_conf.h>
#include <selfup/ns_git_shims.h>
#include <selfup/ns_helpers.h>
#include <selfup/ns_log.h>
#include <selfup/ns_systemd.h>
#include <selfup/TCPAsync.h>

#define SERVUP_THREAD_NUM 1

#define NS_TOPLEVEL_CATCH_SERV(retname, funcname, ...)	\
	do {											\
		try {										\
			funcname(__VA_ARGS__);					\
		} catch (const std::exception &e) {			\
			retname = 1;							\
			std::string msg(e.what());				\
			NS_SOG_PF("%s", e.what());				\
		}											\
	} while(0)

using namespace ns_git;

typedef TCPThreaded::Respond Respond;

class ServupCache
{
public:
	/* Head should be immutable once inserted in cache */
	struct Head
	{
		size_t      m_treeoids_num;
		std::string m_treeoids;
	};

	typedef std::map<ns_git_oid, std::shared_ptr<Head>, oid_comparator_t> cache_map_t;

	ServupCache() :
		m_mutex(),
		m_cache()
	{}

	std::shared_ptr<Head> getRefreshHeadOid(const std::string &repopath, ns_git_oid wanted_oid)
	{
		std::unique_lock<std::mutex> lock(m_mutex);
		return refreshHeadOid_(repopath, wanted_oid)->second;
	}

private:
	cache_map_t::iterator refreshHeadOid_(const std::string &repopath, ns_git_oid wanted_oid)
	{
		/* ensure entry */
		auto it = m_cache.find(wanted_oid);
		if (it == m_cache.end()) {
			const treemap_t &trees = treelist_recursive(repopath, wanted_oid);
			std::shared_ptr<Head> h(new Head());
			h->m_treeoids_num = trees.size();
			for (auto it = trees.begin(); it != trees.end(); ++it)
				h->m_treeoids.append((char *)it->second.m_oid.id, NS_GIT_OID_RAWSZ);
			it = m_cache.insert(std::make_pair(wanted_oid, h)).first;
		}
		return it;
	}

public:
	std::mutex  m_mutex;
	cache_map_t m_cache;
};

class ServupConExt2
{
public:
	ServupConExt2(const std::string &repopath) :
		m_repopath(repopath),
		m_cache(new ServupCache())
	{};

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

	void run()
	{
		/* start */
		m_thrd->setFrameDispatch(std::bind(&ServupWork2::frameDispatch, this, std::placeholders::_1, std::placeholders::_2));
		m_thrd->startBoth();
		/* start confirm */
		ns_sd_notify(0, "READY=1");
		/* join */
		m_thrd->joinBoth();
	}

	void frameDispatch(NetworkPacket *packet, Respond *respond)
	{
		uint8_t id;

		(*packet) >> id;

		switch (id)
		{

		case SELFUP_CMD_LOGDUMP:
		{
			uint32_t magic = 0;
			uint32_t datanum = 0;

			(*packet) >> magic >> datanum;

			const char *data = packet->inSizedStr(datanum);

			NS_SOG_DUMP(data, datanum);
		}
		break;

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

			m_ext->m_cache->getRefreshHeadOid(m_ext->m_repopath, latest_oid);

			NetworkPacket res_latest_pkt(SELFUP_CMD_RESPONSE_LATEST_COMMIT_TREE, networkpacket_cmd_tag_t());
			res_latest_pkt.outSizedStr((char *) latest_oid.id, NS_GIT_OID_RAWSZ);
			respond->respondOneshot(std::move(res_latest_pkt));
		}
		break;

		case SELFUP_CMD_REQUEST_TREELIST:
		{
			ns_git_oid requested_oid = {};
			memcpy(requested_oid.id, packet->inSizedStr(NS_GIT_OID_RAWSZ), NS_GIT_OID_RAWSZ);

			std::shared_ptr<ServupCache::Head> &head = m_ext->m_cache->getRefreshHeadOid(m_ext->m_repopath, requested_oid);

			NetworkPacket res_treelist_pkt(SELFUP_CMD_RESPONSE_TREELIST, networkpacket_cmd_tag_t());
			res_treelist_pkt << (uint32_t) head->m_treeoids_num;
			res_treelist_pkt.outSizedStr(head->m_treeoids.data(), head->m_treeoids.size());
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
	work->run();
}

void toplevel(Address addr)
{
	NS_SOG_PF("startup");

	servup_start_crank(addr);

	NS_SOG_PF("shutdown");
}

int main(int argc, char **argv)
{
	int ret = 0;

	tcpthreaded_startup_helper();

	ns_conf::Conf::initGlobal();
	NsLog::initGlobal();

	Address addr(AF_INET, g_conf->getDec("serv_port"), g_conf->getHex("serv_bind_addr"), address_ipv4_tag_t());

	NS_TOPLEVEL_CATCH_SERV(ret, toplevel, addr);

	if (ret == 0)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}
