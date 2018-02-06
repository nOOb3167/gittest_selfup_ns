#ifndef _NS_CONF_H_
#define _NS_CONF_H_

#include <map>
#include <memory>
#include <stdexcept>
#include <string>

#define NS_CONF_FILENAME "ns_conf.conf"

#define NS_CONF_STR(builtin_varname) std::string((char *)(builtin_varname), sizeof (builtin_varname))

class ConfExc : public std::runtime_error
{
public:
	ConfExc(const char *msg) :
		std::runtime_error(msg)
	{}
};

namespace ns_conf
{

class Conf
{
public:
	Conf();

	void load(const std::string &raw);

	std::string get(const std::string &key);
	uint32_t    getHex(const std::string &key);
	int32_t     getDec(const std::string &key);

	static void initGlobal();

private:
	static std::map<std::string, std::string> loadRaw(const std::string &raw);

private:
	std::map<std::string, std::string> m_map;
};

} /* namespace ns_conf */

extern std::unique_ptr<ns_conf::Conf> g_conf;

#endif /* _NS_CONF_H_ */
