#ifndef _NS_LOG_H_
#define _NS_LOG_H_

#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

#define NS_LOG_LOCK() std::lock_guard<std::mutex> lock(g_log->getMutex())

#define NS_LOG_SZ(msg, msg_len) do { NS_LOG_LOCK(); g_log->logSimple((msg), (msg_len)); } while (0)

class NsLog;
extern std::unique_ptr<NsLog> g_log;

class NsLog
{
public:
	NsLog();

	std::mutex & getMutex() { return m_mutex; }
	std::string & getBuf() { return m_buf; }

	void logSimple(const char *msg, size_t msg_len);

	static void initGlobal();

private:
	std::mutex   m_mutex;
	std::string  m_buf;
};

#endif /* _NS_LOG_H_ */
