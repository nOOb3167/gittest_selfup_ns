#include <cstdarg>
#include <cstdio>
#include <memory>
#include <mutex>

#include <selfup/ns_helpers.h>
#include <selfup/ns_log.h>
#include <selfup/ns_systemd.h>

NS_THREAD_LOCAL_DESIGNATOR ns_log::NsLogTls * g_log_tls = NULL;

std::unique_ptr<ns_log::NsLog> g_log;

namespace ns_log
{

NsLog::NsLog() :
	m_mutex(),
	m_buf(),
	m_fd(ns_sd_journal_create_fd())
{
	m_buf.reserve(64536);
}

void NsLog::logSimple(const char * msg, size_t msg_len)
{
	std::unique_lock<std::mutex> lock(m_mutex);
	m_buf.append("[raw]: ");
	m_buf.append(msg, msg_len);
	m_buf.append(1, '\n');
}

void NsLog::srvLogDump(const char *msg, size_t msg_len)
{
	std::unique_lock<std::mutex> lock(m_mutex);
	struct nsiovec iov[3] = {};
	iov[0].iov_base = (void *) g_log_tls->virtualGetIdent().data();
	iov[0].iov_len  = g_log_tls->virtualGetIdent().size();
	iov[1].iov_base = (void *) "[logdump]:\n";
	iov[1].iov_len  = sizeof "[logdump]:\n" - 1;
	iov[2].iov_base = (void *) msg;
	iov[2].iov_len  = msg_len;

	ns_sd_journal_send_fd_iov(*m_fd, iov, 3);
}

void NsLog::srvLogPf(const char *cpp_file, int cpp_line, const char *format, ...)
{
	std::unique_lock<std::mutex> lock(m_mutex);
	// FIXME: what is a good length limit for vsnprintf ?
	char buf[8192];

	va_list argp;
	va_start(argp, format);

	int nw = 0;

	try {
		if ((nw = vsnprintf(buf, 8192, format, argp)) < 0 || nw >= 8192)
			throw std::runtime_error("logpf write");

		struct nsiovec iov[2] = {};
		iov[0].iov_base = (void *) g_log_tls->virtualGetIdent().data();
		iov[0].iov_len  = g_log_tls->virtualGetIdent().size();
		iov[1].iov_base = (void *) buf;
		iov[1].iov_len  = nw;

		ns_sd_journal_send_fd_iov(*m_fd, iov, 2);
	}
	catch (const std::exception &e) {
		va_end(argp);
		throw;
	}

	va_end(argp);
}

void NsLog::initGlobal()
{
	if (g_log)
		throw std::runtime_error("log global");
	g_log = std::unique_ptr<NsLog>(new NsLog());
	NsLog::threadInitTls(new NsLogTls());
}

void NsLog::threadInitTls(NsLogTls * log_tls)
{
	if (g_log_tls)
		throw std::runtime_error("log_tls global");
	g_log_tls = log_tls;
}

} /* namespace ns_log */
