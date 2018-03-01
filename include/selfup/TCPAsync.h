#ifndef _TCPASYNC_H_
#define _TCPASYNC_H_

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <selfup/TCPAddress.h>
#include <selfup/NetworkPacket.h>

#define TCPASYNC_FRAME_SIZE_MAX (256 * 1024 * 1024)
#define TCPASYNC_SENDFILE_COUNT_PARAM 524288
#define TCPASYNC_ACCEPT_RCVTIMEO_MSEC 30000

extern int g_tcpasync_disable_timeout;

/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms740516(v=vs.85).aspx */
typedef ::std::unique_ptr<int, void(*)(int *fd)> unique_ptr_fd;
typedef ::std::shared_ptr<int>                   shared_ptr_fd;

typedef ::std::unique_ptr<addrinfo, void(*)(addrinfo *p)> unique_ptr_addrinfo;

struct tcpsocket_connect_tag_t {};

class NsLogTlsServ : public NsLogTls
{
public:
	NsLogTlsServ(const std::string &thread_idx_s);
	NsLogTlsServ(size_t thread_idx);

	virtual std::string & virtualGetIdent() override;

private:
	std::string m_thread_idx_s;
};

class TimeoutExc : public std::runtime_error
{
public:
	TimeoutExc(const char *msg);
};

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

class TCPThreaded
{
public:
	class Respond
	{
	public:
		Respond(int fd);

		void respondOneshot(NetworkPacket packet);
		void respondOneshotSendfile(NetworkPacket packet, const std::string &filename);

	private:
		int m_fd;
	};

	class ThreadCtx
	{
	public:
		ThreadCtx(size_t thread_idx);

	public:
		std::thread m_thread;
		size_t      m_thread_idx;
	};

	typedef ::std::function<void(NetworkPacket *packet, Respond *respond)> function_framedispatch_t;

	TCPThreaded(const char *node, const char *service, size_t thread_num);

	void setFrameDispatch(const function_framedispatch_t &framedispatch);
	void startBoth();
	void joinBoth();

protected:
	void threadFuncListenLoop();
	void threadFuncListenLoop2();
	void threadFunc(const std::shared_ptr<ThreadCtx> &ctx);
	void threadFunc2(const std::shared_ptr<ThreadCtx> &ctx);

private:
	function_framedispatch_t m_framedispatch;

	unique_ptr_fd m_listen;
	std::exception_ptr m_listen_thread_exc;
	std::thread m_listen_thread;

	std::vector<std::exception_ptr> m_thread_exc;
	std::vector<std::shared_ptr<ThreadCtx> > m_thread;

	std::mutex m_queue_mutex;
	std::condition_variable m_queue_cv;
	std::deque<unique_ptr_fd> m_queue_incoming;
};

class TCPLogDump
{
public:
	static void dumpResolving(const char *node, const char *service, uint32_t magic, const char *data, size_t data_len);
	static void dump(Address addr, int socktype, int protocol, uint32_t magic, const char * data, size_t data_len);
};

void delete_addrinfo(addrinfo *p);
addrinfo * do_getaddrinfo(const char *node, const char *service, const addrinfo *hints);

void tcpthreaded_socket_close_helper(int *fd);
unique_ptr_fd tcpthreaded_socket_connecting_helper(const char *node, const char *service);
Address tcpthreaded_socket_peer_helper(int fd);
unique_ptr_fd tcpthreaded_socket_listen_helper(const char *node, const char *service);
unique_ptr_fd tcpthreaded_socket_accept_helper(int fd);
NetworkPacket tcpthreaded_blocking_read_helper(int fd);
void tcpthreaded_blocking_write_helper(int fd, NetworkPacket *packet, size_t afterpacket_extra_size);
void tcpthreaded_blocking_sendfile_helper(int fd, int fdfile, size_t size);
unique_ptr_fd tcpthreaded_file_open_size_helper(const std::string &filename, size_t *o_size);
void tcpthreaded_file_close_helper(int *fd);
void tcpthreaded_startup_helper();

#endif /* _TCPASYNC_H_ */
