#include <selfup/ns_ex_config.h>

#ifdef NS_EX_CONFIG_EXTRA_HAVE
#include <ns_ex_config_extra.h>
#else
const char * g_ns_ex_config[][2] =
{
	{ "serv_conn_addr", "desu.no-ip.info" },
	{ "serv_port", "6757" },
	{ "selfup_file_ops_skip", "0" },
	{ "tcpsocket_disable_timeout", "0" },
};
#endif

std::map<std::string, std::string> g_ns_ex_config_map;

void NsExConfig::initGlobal()
{
	std::map<std::string, std::string> map;
	for (size_t i = 0; i < sizeof g_ns_ex_config / sizeof *g_ns_ex_config; i++)
		map[g_ns_ex_config[i][0]] = g_ns_ex_config[i][1];
	g_ns_ex_config_map = map;
}

const char * NsExConfig::get(const char * key)
{
	auto it = g_ns_ex_config_map.find(key);
	if (it == g_ns_ex_config_map.end())
		throw std::runtime_error("config key");
	return it->second.c_str();
}
