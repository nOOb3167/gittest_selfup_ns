#ifndef _TCPADDRESS_H_
#define _TCPADDRESS_H_

#include <cassert>
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#define VSERV_ADDRESS_ADDR_SIZE 16

struct address_ipv4_tag_t {};

class Address
{
public:
	union ns_addr_union
	{
		uint8_t  m_addr[VSERV_ADDRESS_ADDR_SIZE];
		uint32_t m_addr4;
		uint16_t m_addr6[8];
	};

	Address();
	Address(int family, uint16_t port, uint32_t addr, address_ipv4_tag_t);

	int      getFamily() const { return m_family; }
	uint16_t getPort() const { return m_port; }
	uint32_t getAddr4() const { assert(m_family == AF_INET); return m_addr.m_addr4; }

	ns_addr_union getAddrUnion() { return m_addr; }

private:
	int      m_family;
	uint16_t m_port;
	ns_addr_union m_addr;

	friend struct address_less_t;
};

struct address_less_t {
	bool operator()(const Address &a, const Address &b) const;
};

Address::ns_addr_union address_union_to_network_byte_order(int family, Address::ns_addr_union inun);

#endif /* _TCPADDRESS_H_ */
