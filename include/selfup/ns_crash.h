#ifndef _NS_CRASH_H_
#define _NS_CRASH_H_

#include <cstdint>

#include <selfup/TCPAddress.h>

extern int g_crash_mbox;
extern Address  g_crash_addr;
extern uint32_t g_crash_magic;

void ns_crash_handler_setup(Address addr);
void ns_crash_handler_set_magic(uint32_t magic);

#endif /* _NS_CRASH_H_ */
