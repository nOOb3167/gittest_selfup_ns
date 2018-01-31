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
	Address() :
		m_family(AF_UNSPEC),
		m_port(0),
		m_addr()
	{
		memset(m_addr, '\0', VSERV_ADDRESS_ADDR_SIZE);
	}


	Address(int family, uint16_t port, uint32_t addr, address_ipv4_tag_t) :
		m_family(family),
		m_port(port),
		m_addr()
	{
		memset(m_addr, '\0', VSERV_ADDRESS_ADDR_SIZE);
		memcpy(m_addr, &addr, sizeof (uint32_t));
	}

	int getFamily() { return m_family; }
	uint16_t getPort() { return m_port; }
	uint32_t getAddr4() { return *(uint32_t *) m_addr; }

private:
	int      m_family;
	uint16_t m_port;
	uint8_t  m_addr[VSERV_ADDRESS_ADDR_SIZE];

	friend struct address_less_t;
};

struct address_less_t {
	bool operator()(const Address &a, const Address &b) const
	{
		bool n0 = a.m_family < b.m_family;
		bool n1 = a.m_port < b.m_port;
		int  n2cmp = memcmp(a.m_addr, b.m_addr, VSERV_ADDRESS_ADDR_SIZE);
		bool n2 = n2cmp < 0;
		return a.m_family != b.m_family ? n0 : (a.m_port != b.m_port ? n1 : (n2cmp != 0 ? n2 : false));
	}
};

#endif /* _TCPADDRESS_H_ */
