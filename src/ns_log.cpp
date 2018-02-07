#include <cstdarg>
#include <cstdio>
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

void NsLog::srvLogDump(const char *msg, size_t msg_len)
{
	/* FIXME: THANKS DREPPER https://sourceware.org/bugzilla/show_bug.cgi?id=5998 */
	const char hdr[] = "[logdump]:\n";
	if (fwrite(hdr, 1, sizeof hdr - 1, stdout) != sizeof hdr - 1)
		throw std::runtime_error("logdump write hdr");
	if (fwrite(msg, 1, msg_len, stdout) != msg_len)
		throw std::runtime_error("logdump write data");
	if (fwrite("\n", 1, 1, stdout) != 1)
		throw std::runtime_error("logpf write nl");
	if (fflush(stdout) != 0)
		throw std::runtime_error("logdump write flush");
}

void NsLog::srvLogPf(const char *cpp_file, int cpp_line, const char *format, ...)
{
	va_list argp;
	va_start(argp, format);

	int numwrite = 0;

	if (vfprintf(stdout, format, argp) < 0)
		throw std::runtime_error("logpf write");
	if (fwrite("\n", 1, 1, stdout) != 1)
		throw std::runtime_error("logpf write nl");
	if (fflush(stdout) != 0)
		throw std::runtime_error("logpf flush");

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
