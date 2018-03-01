#include <cstdint>
#include <cstdlib>

#include <selfup/ns_crash.h>
#include <selfup/ns_log.h>
#include <selfup/TCPAddress.h>
#include <selfup/TCPAsync.h>

int g_crash_mbox = 0;

size_t   g_crash_addr_num = 0;
Address  g_crash_addr[NS_CRASH_ADDR_MAX] = {};
uint32_t g_crash_magic = 0x00000000;

#ifdef _WIN32

LONG WINAPI ns_crash_handler_unhandled_exception_filter_(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	if (g_crash_mbox)
		MessageBox(NULL, "[NOTE] ns_crash_handler_unhandled_exception_filter_ : attach debugger", NULL, MB_OK);

	for (size_t i = 0; i < g_crash_addr_num; i++) {
		try {
			TCPLogDump::dump(g_crash_addr[i], SOCK_STREAM, 0, g_crash_magic, g_log->getBuf().data(), g_log->getBuf().size());
			return EXCEPTION_CONTINUE_SEARCH;
		}
		catch (const std::exception &e) {
			fprintf(stderr, "[ERROR] ns_crash_handler_unhandled_exception_filter_ [%s]\n", e.what());
		}
		catch (...) {
			fprintf(stderr, "[ERROR] ns_crash_handler_unhandled_exception_filter_ [???]\n");
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

void ns_crash_handler_setup(const char *node, const char *service)
{
	addrinfo hint = {};
	hint.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = 0;

	unique_ptr_addrinfo res(do_getaddrinfo(node, service, &hint), delete_addrinfo);

	for (addrinfo *r = res.get(); r != NULL && g_crash_addr_num < NS_CRASH_ADDR_MAX; r = r->ai_next) {
		struct sockaddr_storage storage = {};
		memcpy(&storage, r->ai_addr, r->ai_addrlen);
		g_crash_addr[g_crash_addr_num++] = Address(&storage, address_storage_tag_t());
	}

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
