#ifndef _TCPSOCKET_H_
#define _TCPSOCKET_H_

#include <memory>
#include <string>

#include <selfup/NetworkPacket.h>
#include <selfup/TCPAddress.h>

#define TCPSOCKET_FRAME_SIZE_MAX (256 * 1024 * 1024)
#define TCPSOCKET_ACCEPT_RCVTIMEO_MSEC 30000

/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms740516(v=vs.85).aspx */
typedef ::std::unique_ptr<int, void(*)(int *fd)> unique_ptr_fd;
typedef ::std::shared_ptr<int>                   shared_ptr_fd;

struct tcpsocket_connect_tag_t {};

extern int g_tcpsocket_disable_timeout;

class TCPSocket
{
public:

	TCPSocket(const char *node, const char *service, tcpsocket_connect_tag_t);

	void Send(NetworkPacket *packet);
	NetworkPacket Recv();

	static void deleteFd(int *fd);
	static void deleteFdFileNotSocket(int *fd);

private:
	unique_ptr_fd m_handle;
};

void tcpsocket_socket_close_helper(int *fd);
unique_ptr_fd tcpsocket_socket_connecting_helper_gai(addrinfo *addr);
unique_ptr_fd tcpsocket_socket_connecting_helper(const char *node, const char *service);
Address tcpsocket_socket_peer_helper(int fd);
unique_ptr_fd tcpsocket_socket_listen_helper(const char *node, const char *service);
unique_ptr_fd tcpsocket_socket_accept_helper(int fd);
NetworkPacket tcpsocket_blocking_read_helper(int fd);
void tcpsocket_blocking_write_helper(int fd, NetworkPacket *packet, size_t afterpacket_extra_size);
void tcpsocket_blocking_sendfile_helper(int fd, int fdfile, size_t size);
unique_ptr_fd tcpsocket_file_open_size_helper(const std::string &filename, size_t *o_size);
void tcpsocket_file_close_helper(int *fd);
void tcpsocket_startup_helper();

#endif /* _TCPSOCKET_H_ */
