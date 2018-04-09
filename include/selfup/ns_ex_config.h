#ifndef _NS_EX_CONFIG_H_
#define _NS_EX_CONFIG_H_

#include <map>
#include <string>

extern const char * g_ns_ex_config[][2];
extern std::map<std::string, std::string> g_ns_ex_config_map;

class NsExConfig
{
public:
	static void initGlobal();
	static const char * get(const char *key);
};

#endif /* _NS_EX_CONFIG_H_ */
