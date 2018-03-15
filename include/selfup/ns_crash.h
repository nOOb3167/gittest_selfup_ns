#ifndef _NS_CRASH_H_
#define _NS_CRASH_H_

#include <cstdint>
#include <memory>

#include <selfup/TCPAddress.h>

#define NS_CRASH_ADDR_MAX 8

extern int g_crash_mbox;
extern uint32_t g_crash_magic;
extern unique_ptr_addrinfo g_crash_addrinfo;

class TCPLogDump
{
public:
	static void dump(addrinfo *addr, uint32_t magic, const char * data, size_t data_len);
};

void ns_crash_handler_setup(const char *node, const char *service);
void ns_crash_handler_set_magic(uint32_t magic);

#endif /* _NS_CRASH_H_ */
