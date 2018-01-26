#ifndef _TCPSOCKET_H_
#define _TCPSOCKET_H_

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

class TCPSocket
{
public:
	/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms740516(v=vs.85).aspx */
	typedef ::std::unique_ptr<int, void(*)(int *fd)> unique_ptr_fd;
	typedef ::std::shared_ptr<int>                   shared_ptr_fd;

	TCPSocket() :
		m_handle(new int(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)), deleteFd)
	{
		if (*m_handle < 0)
			throw std::runtime_error("UDPSocket socket");
	}

	void Connect(Address addr)
	{
		if (addr.getFamily() != AF_INET)
			throw std::runtime_error("TCPSocket connect family");

		struct sockaddr_in sockaddr = {};

		sockaddr.sin_family = addr.getFamily();
		sockaddr.sin_port = htons(addr.getPort());
		sockaddr.sin_addr.s_addr = htonl(addr.getAddr4());

		if (connect(*m_handle, (struct sockaddr *) &sockaddr, sizeof sockaddr) < 0)
			throw std::runtime_error("TCPSocket connect connect");
	}

	void Bind(Address addr)
	{
		if (addr.getFamily() != AF_INET)
			throw std::runtime_error("TCPSocket bind family");

		struct sockaddr_in sockaddr = {};

		sockaddr.sin_family = addr.getFamily();
		sockaddr.sin_port = htons(addr.getPort());
		sockaddr.sin_addr.s_addr = htonl(addr.getAddr4());

		if (bind(*m_handle, (struct sockaddr *) &sockaddr, sizeof sockaddr) < 0)
			throw std::runtime_error("TCPSocket bind bind");
	}

	void Send(const void *data, size_t size)
	{
		int sent = send(*m_handle, (const char *) data, size, 0);

		if (sent < 0 || sent != size)
			throw std::runtime_error("TCPSocket send sent");
	}

	int ReceiveWaiting(void *data, int size, int timeout_ms)
	{
		if (! WaitData(timeout_ms))
			return -1;

		int rcvt = recv(*m_handle, (char *) data, size, 0);

		if (rcvt < 0)
			throw std::runtime_error("TCPSocket send sent");

		return rcvt;
	}

	bool WaitData(int timeout_ms)
	{
		fd_set readset;

		FD_ZERO(&readset);
		FD_SET(*m_handle, &readset);

		struct timeval tv = {};
		tv.tv_sec  = 0;
		tv.tv_usec = timeout_ms * 1000;

		int result = select(*m_handle + 1, &readset, NULL, NULL, &tv);

		if (result < 0)
			throw std::runtime_error("TCPSocket wait");

		if (result == 0 || ! FD_ISSET(*m_handle, &readset))
			return false;

		return true;
	}

	static void deleteFd(int *fd)
	{
		if (fd) {
#ifdef _WIN32
			if (*fd != INVALID_SOCKET) {
				closesocket(*fd);
				*fd = INVALID_SOCKET;
			}
#else
			if (*fd != -1) {
				close(*fd);
				*fd = -1;
			}
#endif
			delete fd;
		}
	}

	static void deleteFdFileNotSocket(int *fd)
	{
		if (fd) {
#ifdef _WIN32
			if (*fd != -1) {
				_close(*fd);
				*fd = -1;
			}
#else
			if (*fd != -1) {
				close(*fd);
				*fd = -1;
			}
#endif
		}
	}

private:
	unique_ptr_fd m_handle;
};

#endif /* _TCPSOCKET_H_ */
