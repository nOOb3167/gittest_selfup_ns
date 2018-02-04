#include <memory>

#include <selfup/ns_log.h>

std::unique_ptr<NsLog> g_log;

NsLog::NsLog() :
	m_mutex(),
	m_buf()
{
	m_buf.reserve(64536);
}

void NsLog::logSimple(const char * msg, size_t msg_len)
{
	m_buf.append("[raw]: ");
	m_buf.append(msg, msg_len);
	m_buf.append(1, '\n');
}

void NsLog::initGlobal()
{
	if (g_log)
		throw std::runtime_error("log global");
	std::unique_ptr<NsLog> log(new NsLog());
	std::lock_guard<std::mutex> lock(log->getMutex());
	g_log = std::move(log);
}
