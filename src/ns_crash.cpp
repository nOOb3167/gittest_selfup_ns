#include <cstdint>
#include <cstdlib>

#include <selfup/ns_crash.h>
#include <selfup/ns_log.h>
#include <selfup/TCPAddress.h>
#include <selfup/TCPAsync.h>

int g_crash_mbox = 0;

Address  g_crash_addr = {};
uint32_t g_crash_magic = 0x00000000;

#ifdef _WIN32

LONG WINAPI ns_crash_handler_unhandled_exception_filter_(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	if (g_crash_mbox)
		MessageBox(NULL, "[NOTE] ns_crash_handler_unhandled_exception_filter_ : attach debugger", NULL, MB_OK);

	try {
		TCPLogDump::dump(g_crash_addr, g_crash_magic, g_log->getBuf().data(), g_log->getBuf().size());
	}
	catch (const std::exception &e) {
		fprintf(stderr, "[ERROR] ns_crash_handler_unhandled_exception_filter_ [%s]\n", e.what());
	}
	catch (...) {
		fprintf(stderr, "[ERROR] ns_crash_handler_unhandled_exception_filter_ [???]\n");
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

void ns_crash_handler_setup(Address addr)
{
	g_crash_addr = addr;

	SetUnhandledExceptionFilter(ns_crash_handler_unhandled_exception_filter_);
}

void ns_crash_handler_set_magic(uint32_t magic)
{
	g_crash_magic = magic;
}

#else /* _WIN32 */

void ns_crash_handler_setup(Address addr)
{
	g_crash_addr = addr;

	/* not implemented */
}

void ns_crash_handler_set_magic(uint32_t magic)
{
	g_crash_magic = magic;
}

#endif /* _WIN32 */
