#include <cstdint>
#include <cstdlib>

#include <selfup/ns_crash.h>
#include <selfup/ns_helpers.h>
#include <selfup/ns_log.h>
#include <selfup/TCPAddress.h>
#include <selfup/TCPSocket.h>

int g_crash_mbox = 0;
uint32_t g_crash_magic = 0x00000000;
unique_ptr_addrinfo g_crash_addrinfo(NULL, delete_addrinfo);

void TCPLogDump::dump(addrinfo *addr, uint32_t magic, const char * data, size_t data_len)
{
	NetworkPacket packet(SELFUP_CMD_LOGDUMP, networkpacket_cmd_tag_t());
	packet << magic;
	packet << (uint32_t)data_len;
	packet.outSizedStr(data, data_len);

	unique_ptr_fd sock(tcpsocket_socket_connecting_helper_gai(addr));
	tcpsocket_blocking_write_helper(*sock, &packet, 0);
}

#ifdef _WIN32

LONG WINAPI ns_crash_handler_unhandled_exception_filter_(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	if (g_crash_mbox)
		MessageBox(NULL, "[NOTE] ns_crash_handler_unhandled_exception_filter_ : attach debugger", NULL, MB_OK);

	try {
		TCPLogDump::dump(g_crash_addrinfo.get(), g_crash_magic, g_log->getBuf().data(), g_log->getBuf().size());
		return EXCEPTION_CONTINUE_SEARCH;
	}
	catch (const std::exception &e) {
		fprintf(stderr, "[ERROR] ns_crash_handler_unhandled_exception_filter_ [%s]\n", e.what());
	}
	catch (...) {
		fprintf(stderr, "[ERROR] ns_crash_handler_unhandled_exception_filter_ [???]\n");
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void ns_crash_handler_setup(const char *node, const char *service)
{
	g_crash_addrinfo = do_getaddrinfo_tcp(node, service);

	SetUnhandledExceptionFilter(ns_crash_handler_unhandled_exception_filter_);
}

void ns_crash_handler_set_magic(uint32_t magic)
{
	g_crash_magic = magic;
}

#else /* _WIN32 */

void ns_crash_handler_setup(const char *node, const char *service)
{
	/* not implemented */
}

void ns_crash_handler_set_magic(uint32_t magic)
{
	g_crash_magic = magic;
}

#endif /* _WIN32 */
