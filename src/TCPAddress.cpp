#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>

#include <selfup/TCPAddress.h>

Address::Address() :
	m_storage()
{
	memset(&m_storage, '\0', sizeof m_storage);
	m_storage.ss_family = AF_UNSPEC;
}

Address::Address(uint16_t port, uint32_t addr4, address_ipv4_tag_t) :
	m_storage()
{
	memset(&m_storage, '\0', sizeof m_storage);
	struct sockaddr_in *addr = (struct sockaddr_in *) &m_storage;
	addr->sin_family = AF_INET;
	addr->sin_port   = htons(port);
	addr->sin_addr.s_addr = htonl(addr4);
}

Address::Address(uint16_t port, uint16_t *addr6, size_t addr6_num, address_ipv6_tag_t) :
	m_storage()
{
	assert(addr6_num == 8);
	memset(&m_storage, '\0', sizeof m_storage);
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &m_storage;
	addr->sin6_family = AF_INET6;
	addr->sin6_port   = htons(port);
	for (size_t i = 0; i < 8; i++)
		((uint16_t *)addr->sin6_addr.s6_addr)[i] = htons(addr6[i]);
}

Address::Address(struct sockaddr *addr, long long addrlen, address_sockaddr_tag_t) :
	m_storage()
{
	assert(addrlen <= sizeof (sockaddr));
	assert(addrlen <= sizeof (sockaddr_storage));
	memset(&m_storage, '\0', sizeof (sockaddr_storage));
	memcpy(&m_storage, addr, addrlen);
}

Address::Address(struct sockaddr_storage *storage, address_storage_tag_t) :
	m_storage(*storage)
{}

int Address::getFamily() const
{
	return m_storage.ss_family;
}

uint16_t Address::getPort() const
{
	switch (m_storage.ss_family)
	{
	case AF_INET:
		return ((struct sockaddr_in *) &m_storage)->sin_port;
	case AF_INET6:
		return ((struct sockaddr_in6 *) &m_storage)->sin6_port;
	default:
		assert(0);
		return 0;
	}
}

std::string Address::getStr() const
{
	char b4[INET_ADDRSTRLEN] = {};
	char b6[INET6_ADDRSTRLEN] = {};
	const char *res = NULL;
	switch (m_storage.ss_family)
	{
	case AF_INET:
		res = inet_ntop(AF_INET, &((struct sockaddr_in *) &m_storage)->sin_addr.s_addr, b4, sizeof b4);
		break;
	case AF_INET6:
		res = inet_ntop(AF_INET, &((struct sockaddr_in6 *) &m_storage)->sin6_addr.s6_addr, b6, sizeof b6);
		break;
	default:
		assert(0);
	}
	if (! res)
		throw std::runtime_error("inet_ntop");
	std::string str(res);
	return str;
}

const struct sockaddr_storage * Address::getStorage() const
{
	return &m_storage;
}

size_t Address::getStorageLen() const
{
	switch (m_storage.ss_family)
	{
	case AF_INET:
		return sizeof (struct sockaddr_in);
	case AF_INET6:
		return sizeof (struct sockaddr_in6);
	default:
		assert(0);
		return 0;
	}
}

bool address_less_t::operator()(const Address &a, const Address &b) const
{
	if (a.m_storage.ss_family != b.m_storage.ss_family)
		return a.m_storage.ss_family < b.m_storage.ss_family;
	
	switch (a.m_storage.ss_family)
	{
	case AF_INET:
	{
		struct sockaddr_in *aa = (struct sockaddr_in *) &a.m_storage;
		struct sockaddr_in *bb = (struct sockaddr_in *) &a.m_storage;
		if (aa->sin_port != bb->sin_port)
			return aa->sin_port < bb->sin_port;
		if (aa->sin_addr.s_addr != bb->sin_addr.s_addr)
			return aa->sin_addr.s_addr < bb->sin_addr.s_addr;
	}
	break;

	case AF_INET6:
	{
		struct sockaddr_in6 *aa = (struct sockaddr_in6 *) &a.m_storage;
		struct sockaddr_in6 *bb = (struct sockaddr_in6 *) &a.m_storage;
		if (aa->sin6_port != bb->sin6_port)
			return aa->sin6_port < bb->sin6_port;
		int qq = memcmp(aa->sin6_addr.s6_addr, bb->sin6_addr.s6_addr, 2*8);
		if (qq != 0)
			return qq < 0;
		if (aa->sin6_scope_id != bb->sin6_scope_id)
			return aa->sin6_scope_id < bb->sin6_scope_id;
	}
	break;

	default:
		assert(0);
	}

	return false;
}

void delete_addrinfo(addrinfo *p)
{
	if (p)
		freeaddrinfo(p);
}

unique_ptr_addrinfo do_getaddrinfo(const char *node, const char *service, const addrinfo *hints)
{
	addrinfo *res = NULL;
	if (getaddrinfo(node, service, hints, &res) != 0)
		throw std::runtime_error("getaddrinfo");
	return unique_ptr_addrinfo(res, delete_addrinfo);
}

unique_ptr_addrinfo do_getaddrinfo_tcp(const char *node, const char *service)
{
	addrinfo hint = {};
	hint.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = 0;

	return do_getaddrinfo(node, service, &hint);
}

unique_ptr_addrinfo do_getaddrinfo_tcp_listen(const char *node, const char *service)
{
	addrinfo hint = {};
	hint.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_PASSIVE;
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = 0;

	return do_getaddrinfo(node, service, &hint);
}
