#include <cstdarg>
#include <cstdio>
#include <memory>

#include <selfup/ns_log.h>
#include <selfup/ns_systemd.h>

std::unique_ptr<NsLog> g_log;

NsLog::NsLog() :
	m_mutex(),
	m_buf(),
	m_fd(ns_sd_journal_create_fd())
{
	m_buf.reserve(64536);
}

void NsLog::logSimple(const char * msg, size_t msg_len)
{
	m_buf.append("[raw]: ");
	m_buf.append(msg, msg_len);
	m_buf.append(1, '\n');
}

void NsLog::srvLogDump(const char *msg, size_t msg_len)
{
	struct nsiovec iov[2] = {};
	iov[0].iov_base = (void *) "[logdump]:\n";
	iov[0].iov_len  = sizeof "[logdump]:\n" - 1;
	iov[1].iov_base = (void *) msg;
	iov[1].iov_len  = msg_len;

	ns_sd_journal_send_fd_iov(*m_fd, iov, 2);
}

void NsLog::srvLogPf(const char *cpp_file, int cpp_line, const char *format, ...)
{
	// FIXME: what is a good length limit for vsnprintf ?
	char buf[8192];

	va_list argp;
	va_start(argp, format);

	int nw = 0;

	try {
		if ((nw = vsnprintf(buf, 8192, format, argp)) < 0 || nw >= 8192)
			throw std::runtime_error("logpf write");

		ns_sd_journal_send_fd(*m_fd, buf, nw);
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
	std::unique_ptr<NsLog> log(new NsLog());
	std::lock_guard<std::mutex> lock(log->getMutex());
	g_log = std::move(log);
}
