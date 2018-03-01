#ifndef _TCPADDRESS_H_
#define _TCPADDRESS_H_

#include <cassert>
#include <cstdint>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

struct address_ipv4_tag_t {};
struct address_ipv6_tag_t {};
struct address_storage_tag_t {};

class Address
{
public:
	Address();
	Address(uint16_t port, uint32_t addr4, address_ipv4_tag_t);
	Address(uint16_t port, uint16_t *addr6, size_t addr6_num, address_ipv6_tag_t);
	Address(struct sockaddr_storage *storage, address_storage_tag_t);

	int      getFamily() const;
	uint16_t getPort() const;
	std::string getStr() const;
	const struct sockaddr_storage * getStorage() const;
	size_t getStorageLen() const;

private:
	struct sockaddr_storage m_storage;

	friend struct address_less_t;
};

struct address_less_t {
	bool operator()(const Address &a, const Address &b) const;
};

#endif /* _TCPADDRESS_H_ */
