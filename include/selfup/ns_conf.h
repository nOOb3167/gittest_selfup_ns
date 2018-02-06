#ifndef _NS_CONF_H_
#define _NS_CONF_H_

#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <utility>

#include <ns_conf_builtin.h>
#include <selfup/ns_filesys.h>
#include <selfup/ns_helpers.h>

#define NS_CONF_FILENAME "ns_conf.conf"

#define NS_CONF_STR(builtin_varname) std::string((char *)(builtin_varname), sizeof (builtin_varname))

namespace ns_conf { class Conf; }
extern std::unique_ptr<ns_conf::Conf> g_conf;

namespace ns_conf
{

class ConfExc : public std::runtime_error
{
public:
	ConfExc(const char *msg) :
		std::runtime_error(msg)
	{}
};

class Conf
{
public:
	Conf() :
		m_map()
	{}

	void load(const std::string &raw)
	{
		m_map = loadRaw(raw);
	}

	std::string get(const std::string &key)
	{
		auto it = m_map.find(key);
		if (it == m_map.end())
			throw ConfExc("key missing");
		return it->second;
	}

	uint32_t getHex(const std::string &key)
	{
		std::string val = get(key);
		if (! (val.size() >= 3 && val[0] == '0' && val[1] == 'x'))
			throw ConfExc("val hex format");
		uint32_t num = 0;
		for (size_t off = 2; off < val.size(); off++)
			num = 16 * num + decode_hex_char(val[off]);
		return num;
	}

	int32_t getDec(const std::string &key)
	{
		std::string val = get(key);
		int32_t num = 0;
		for (size_t off = 0; off < val.size(); off++) {
			if (val[off] < '0' || val[off] - '0' > 9)
				throw ConfExc("conf val format X");
			num = 10 * num + (val[off] - '0');
		}
		return num;
	}

	static std::unique_ptr<Conf> createDefault()
	{
		std::string raw;
		try {
			std::string path = ns_filesys::path_append_abs_rel(ns_filesys::current_executable_directory(), NS_CONF_FILENAME);
			raw = std::move(ns_filesys::file_read(path));
		}
		catch (const FilesysExc &)
		{
			raw = std::move(NS_CONF_STR(g_conf_builtin_str));
		}
		std::unique_ptr<Conf> conf(new Conf());
		conf->load(raw);
		return conf;
	}

private:
	static std::map<std::string, std::string> loadRaw(const std::string &raw)
	{
		std::map<std::string, std::string> map;

		std::string nor;

		size_t old = 0;
		for (size_t off = raw.find_first_of('\r', 0); off != std::string::npos; old = off + 1, off = raw.find_first_of('\r', off + 1))
			nor.append(raw.substr(old, off - old));
		if (old != raw.size())
			nor.append(raw.substr(old, std::string::npos));

		std::vector<std::string> lines;

		old = 0;
		for (size_t off = nor.find_first_of('\n', 0); off != std::string::npos; old = off + 1, off = nor.find_first_of('\n', off + 1))
			lines.push_back(nor.substr(old, off - old));
		if (old != nor.size())
			lines.push_back(nor.substr(old, std::string::npos));

		for (size_t i = 0; i < lines.size(); i++) {
			if (lines[i].empty() || lines[i][0] == '#')
				continue;
			size_t off = lines[i].find_first_of('=');
			if (off == std::string::npos)
				throw ConfExc("expected equalsign");
			std::string key = lines[i].substr(0, off);
			std::string value = lines[i].substr(off + 1, std::string::npos);
			map[key] = value;
		}

		return map;
	}

private:
	std::map<std::string, std::string> m_map;
};

}

#endif /* _NS_CONF_H_ */
