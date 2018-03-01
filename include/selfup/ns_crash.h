#ifndef _NS_CRASH_H_
#define _NS_CRASH_H_

#include <cstdint>

#include <selfup/TCPAddress.h>

#define NS_CRASH_ADDR_MAX 8

extern int g_crash_mbox;
extern size_t   g_crash_addr_num;
extern Address  g_crash_addr[NS_CRASH_ADDR_MAX];
extern uint32_t g_crash_magic;

void ns_crash_handler_setup(const char *node, const char *service);
void ns_crash_handler_set_magic(uint32_t magic);

#endif /* _NS_CRASH_H_ */
