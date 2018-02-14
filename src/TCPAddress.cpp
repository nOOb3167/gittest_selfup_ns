#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>

#include <selfup/TCPAddress.h>

Address::Address() :
	m_family(AF_UNSPEC),
	m_port(0),
	m_addr()
{
	memset(m_addr.m_addr, '\0', VSERV_ADDRESS_ADDR_SIZE);
}

Address::Address(int family, uint16_t port, uint32_t addr, address_ipv4_tag_t) :
	m_family(family),
	m_port(port),
	m_addr()
{
	memset(m_addr.m_addr, '\0', VSERV_ADDRESS_ADDR_SIZE);
	m_addr.m_addr4 = addr;
}

bool address_less_t::operator()(const Address &a, const Address &b) const
{
	bool n0 = a.m_family < b.m_family;
	bool n1 = a.m_port < b.m_port;
	bool n2 = a.getAddr4() < b.getAddr4();
	return a.m_family != b.m_family ? n0 : (a.m_port != b.m_port ? n1 : (a.getAddr4() != b.getAddr4() ? n2 : false));
}

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
