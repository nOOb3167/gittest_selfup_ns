#ifndef _TCPADDRESS_H_
#define _TCPADDRESS_H_

#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>

#ifdef _WIN32
#include <winsock2.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
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

	Address() :
		m_family(AF_UNSPEC),
		m_port(0),
		m_addr()
	{
		memset(m_addr.m_addr, '\0', VSERV_ADDRESS_ADDR_SIZE);
	}

	Address(int family, uint16_t port, uint32_t addr, address_ipv4_tag_t) :
		m_family(family),
		m_port(port),
		m_addr()
	{
		memset(m_addr.m_addr, '\0', VSERV_ADDRESS_ADDR_SIZE);
		m_addr.m_addr4 = addr;
	}

	int getFamily() const { return m_family; }
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
	bool operator()(const Address &a, const Address &b) const
	{
		bool n0 = a.m_family < b.m_family;
		bool n1 = a.m_port < b.m_port;
		bool n2 = a.getAddr4() < b.getAddr4();
		return a.m_family != b.m_family ? n0 : (a.m_port != b.m_port ? n1 : (a.getAddr4() != b.getAddr4() ? n2 : false));
	}
};

Address::ns_addr_union address_union_to_network_byte_order(int family, Address::ns_addr_union inun)
{
	Address::ns_addr_union un = inun;
	switch (family) {
	case AF_INET:
		for (size_t i = 0; i < 4; i++)
			un.m_addr[i] = inun.m_addr[3 - i];
		return un;
	case AF_INET6:
		for (size_t i = 0; i < 8; i++) {
			un.m_addr[2 * i + 0] = inun.m_addr[2 * i + 1];
			un.m_addr[2 * i + 1] = inun.m_addr[2 * i + 0];
		}
		return un;
	default:
		assert(0);
		return un;
	}
}

#endif /* _TCPADDRESS_H_ */
