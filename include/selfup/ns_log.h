#ifndef _NS_LOG_H_
#define _NS_LOG_H_

#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

#include <selfup/ns_systemd.h>

#define NS_LOG_LOCK() std::lock_guard<std::mutex> lock(g_log->getMutex())

#define NS_LOG_SZ(msg, msg_len) do { NS_LOG_LOCK(); g_log->logSimple((msg), (msg_len)); } while (0)

#define NS_SOG_DUMP(msg, msg_len) do { NS_LOG_LOCK(); g_log->srvLogDump((msg), (msg_len)); } while (0)
#define NS_SOG_PF(...)            do { NS_LOG_LOCK(); g_log->srvLogPf(__FILE__, __LINE__, __VA_ARGS__); } while(0)

class NsLog;
extern std::unique_ptr<NsLog> g_log;

class NsLogTls
{
public:
	virtual ~NsLogTls() {};
	virtual std::string & virtualGetIdent() { return m_empty; };

private:
	std::string m_empty;
};

class NsLog
{
public:
	NsLog();

	std::mutex & getMutex() { return m_mutex; }
	std::string & getBuf() { return m_buf; }

	void logSimple(const char *msg, size_t msg_len);

	void srvLogDump(const char *data, size_t data_num);
	void srvLogPf(const char *cpp_file, int cpp_line, const char *format, ...);

	static void initGlobal();

	static void threadInitTls(NsLogTls *log_tls);

private:
	std::mutex   m_mutex;
	std::string  m_buf;

	ns_systemd_fd m_fd;
};

#endif /* _NS_LOG_H_ */
