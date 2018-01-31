#ifndef _TCPASYNC_H_
#define _TCPASYNC_H_

#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <selfup/TCPAddress.h>
#include <selfup/NetworkPacket.h>

#define TCPASYNC_FRAME_SIZE_MAX (256 * 1024 * 1024)

/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms740516(v=vs.85).aspx */
typedef ::std::unique_ptr<int, void(*)(int *fd)> unique_ptr_fd;
typedef ::std::shared_ptr<int>                   shared_ptr_fd;

unique_ptr_fd tcpthreaded_socket_helper();
unique_ptr_fd tcpthreaded_socket_listen_helper(Address addr);
unique_ptr_fd tcpthreaded_socket_accept_helper(int fd);
void tcpthreaded_socket_connect_helper(int fd, Address addr);
NetworkPacket tcpthreaded_blocking_read_helper(int fd);
void tcpthreaded_blocking_write_helper(int fd, NetworkPacket *packet, size_t afterpacket_extra_size);
void tcpthreaded_blocking_sendfile_helper(int fd, int fdfile, size_t size);
unique_ptr_fd tcpthreaded_file_open_size_helper(const std::string &filename, size_t *o_size);
void tcpthreaded_startup_helper();

class TCPSocket
{
public:

	TCPSocket() :
		m_handle(tcpthreaded_socket_helper())
	{}

	void Connect(Address addr)
	{
		if (addr.getFamily() != AF_INET)
			throw std::runtime_error("TCPSocket connect family");

		tcpthreaded_socket_connect_helper(*m_handle, addr);
	}

	void Send(NetworkPacket *packet)
	{
		tcpthreaded_blocking_write_helper(*m_handle, packet, 0);
	}

	NetworkPacket Recv()
	{
		return tcpthreaded_blocking_read_helper(*m_handle);
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

class TCPThreaded
{
public:
	class Respond
	{
	public:
		Respond(int fd) :
			m_fd(fd)
		{}

		void respondOneshot(NetworkPacket packet)
		{
			tcpthreaded_blocking_write_helper(m_fd, &packet, 0);
		}

		void respondOneshotSendfile(NetworkPacket packet, const std::string &filename)
		{
			size_t size = 0;
			unique_ptr_fd fdfile(tcpthreaded_file_open_size_helper(filename, &size));
			tcpthreaded_blocking_write_helper(m_fd, &packet, size);
			tcpthreaded_blocking_sendfile_helper(m_fd, *fdfile, size);
		}

	private:
		int m_fd;
	};

	class ThreadCtx
	{
	public:
		ThreadCtx(size_t thread_idx) :
			m_thread(),
			m_thread_idx(thread_idx)
		{}

	public:
		std::thread m_thread;
		size_t      m_thread_idx;
	};

	typedef ::std::function<void(NetworkPacket *packet, Respond *respond)> function_framedispatch_t;

	TCPThreaded(Address addr, size_t thread_num) :
		m_framedispatch(),
		m_listen(tcpthreaded_socket_listen_helper(addr)),
		m_listen_thread_exc(),
		m_listen_thread(),
		m_thread_exc(),
		m_thread(),
		m_queue_mutex(),
		m_queue_cv(),
		m_queue_incoming()
	{
		for (size_t i = 0; i < thread_num; i++)
			m_thread_exc.push_back(std::exception_ptr());
		for (size_t i = 0; i < thread_num; i++)
			m_thread.push_back(std::shared_ptr<ThreadCtx>(new ThreadCtx(i)));
	}

	void setFrameDispatch(const function_framedispatch_t &framedispatch)
	{
		m_framedispatch = framedispatch;
	}

	void startBoth()
	{
		m_listen_thread = std::move(std::thread(&TCPThreaded::threadFuncListenLoop, this));
		for (size_t i = 0; i < m_thread.size(); i++)
			m_thread[i]->m_thread = std::move(std::thread(&TCPThreaded::threadFunc, this, m_thread[i]));
	}

	void joinBoth()
	{
		m_listen_thread.join();
		for (size_t i = 0; i < m_thread.size(); i++)
			m_thread[i]->m_thread.join();

		try {
			if (m_listen_thread_exc)
				std::rethrow_exception(m_listen_thread_exc);
			for (size_t i = 0; i < m_thread_exc.size(); i++)
				if (m_thread_exc[i])
					std::rethrow_exception(m_thread_exc[i]);
		}
		catch (std::exception &e) {
			throw;
		}
	}

protected:
	void threadFuncListenLoop()
	{
		try {
			threadFuncListenLoop2();
		}
		catch (std::exception &) {
			m_listen_thread_exc = std::current_exception();
		}
	}

	void threadFuncListenLoop2()
	{
		while (true) {
			unique_ptr_fd nsock(tcpthreaded_socket_accept_helper(*m_listen));

			{
				std::unique_lock<std::mutex> lock(m_queue_mutex);
				m_queue_incoming.push_back(std::move(nsock));
			}
			m_queue_cv.notify_one();
		}
	}

	void threadFunc(const std::shared_ptr<ThreadCtx> &ctx)
	{
		try {
			threadFunc2(ctx);
		}
		catch (std::exception &e) {
			m_thread_exc.at(ctx->m_thread_idx) = std::current_exception();
		}
	}

	void threadFunc2(const std::shared_ptr<ThreadCtx> &ctx)
	{
		while (true) {
			std::unique_lock<std::mutex> lock(m_queue_mutex);
			m_queue_cv.wait(lock, [&]() { return !m_queue_incoming.empty(); });
			unique_ptr_fd fd = std::move(m_queue_incoming.front());
			m_queue_incoming.pop_front();
			lock.unlock();

			try {
				while (true) {
					NetworkPacket packet(tcpthreaded_blocking_read_helper(*fd));
					Respond respond(*fd);
					m_framedispatch(&packet, &respond);
				}
			}
			catch (std::runtime_error &e) {
				/* disconnect - resume dequeuing incoming connections */
			}
		}
	}

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

unique_ptr_fd tcpthreaded_socket_helper()
{
	unique_ptr_fd sock(new int(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), TCPSocket::deleteFd);
	if (*sock < 0)
		throw std::runtime_error("socket");
	return sock;
}

unique_ptr_fd tcpthreaded_socket_listen_helper(Address addr)
{
	unique_ptr_fd sock(new int(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), TCPSocket::deleteFd);
	if (*sock < 0)
		throw std::runtime_error("socket");
	struct sockaddr_in sockaddr = {};
	sockaddr.sin_family = addr.getFamily();
	sockaddr.sin_port = htons(addr.getPort());
	sockaddr.sin_addr.s_addr = htonl(addr.getAddr4());
	if (bind(*sock, (struct sockaddr *) &sockaddr, sizeof sockaddr) < 0)
		throw std::runtime_error("bind");
	if (listen(*sock, 5) < 0)
		throw std::runtime_error("listen");
	return sock;
}

unique_ptr_fd tcpthreaded_socket_accept_helper(int fd)
{
	struct sockaddr_in sockaddr = {};
	int socklen = sizeof sockaddr; // FIXME: socklen_t for NIX
	unique_ptr_fd nsock(new int(accept(fd, (struct sockaddr *) &sockaddr, &socklen)), TCPSocket::deleteFd);
	if (*nsock < 0)
		throw std::runtime_error("accept");
	return nsock;
}

void tcpthreaded_socket_connect_helper(int fd, Address addr)
{
	struct sockaddr_in sockaddr = {};

	sockaddr.sin_family = addr.getFamily();
	sockaddr.sin_port = htons(addr.getPort());
	sockaddr.sin_addr.s_addr = htonl(addr.getAddr4());

	if (connect(fd, (struct sockaddr *) &sockaddr, sizeof sockaddr) < 0)
		throw std::runtime_error("connect");
}

NetworkPacket tcpthreaded_blocking_read_helper(int fd)
{
	/* read header */

	uint8_t hdr[9] = {};

	int rcvt = recv(fd, (char *) hdr, 9, MSG_WAITALL);

	if (rcvt < 0 || rcvt == 0 || rcvt != 9)
		throw std::runtime_error("recv rcvt");

	/* validate */

	if (!!memcmp(hdr, "FRAME", 5))
		throw ProtocolExc("frame magic");
	const uint32_t sz = (hdr[5] << 24) | (hdr[6] << 16) | (hdr[7] << 8) | (hdr[8] << 0);

	if (sz > TCPASYNC_FRAME_SIZE_MAX)
		throw std::runtime_error("frame size");

	/* read packet */

	std::vector<uint8_t> buf;
	buf.resize(sz);

	int rcvt2 = recv(fd, (char *) buf.data(), buf.size(), MSG_WAITALL);

	if (rcvt2 < 0 || rcvt2 == 0 || rcvt2 != buf.size())
		throw std::runtime_error("recv rcvt");

	NetworkPacket packet(std::move(buf), networkpacket_vec_steal_tag_t());

	return packet;
}

void tcpthreaded_blocking_write_helper(int fd, NetworkPacket *packet, size_t afterpacket_extra_size)
{
	/* write header */

	const size_t fsz = packet->getDataSize() + afterpacket_extra_size;

	const uint8_t hdr[9] = { 'F', 'R', 'A', 'M', 'E', (fsz >> 24) & 0xFF, (fsz >> 16) & 0xFF, (fsz >> 8) & 0xFF, (fsz >> 0) & 0xFF };

	int sent = send(fd, (char *) hdr, 9, 0);

	if (sent < 0 || sent == 0 || sent != 9)
		throw std::runtime_error("send sent");

	int sent2 = send(fd, (char *) packet->getDataPtr(), packet->getDataSize(), 0);

	if (sent2 < 0 || sent2 == 0 || sent2 != packet->getDataSize())
		throw std::runtime_error("send sent");

}

void tcpthreaded_blocking_sendfile_helper(int fd, int fdfile, size_t size)
{
	std::string buf(size, '\0');
	
	int rcvt = _read(fdfile, (char *) buf.data(), buf.size());

	if (rcvt < 0 || rcvt == 0 || rcvt != buf.size())
		throw std::runtime_error("recv rcvt");

	int sent = send(fd, buf.data(), buf.size(), 0);

	if (sent < 0 || sent == 0 || sent != buf.size())
		throw std::runtime_error("send sent");
}

unique_ptr_fd tcpthreaded_file_open_size_helper(const std::string &filename, size_t *o_size)
{
	unique_ptr_fd fdfile(new int(_open(filename.c_str(), _O_RDONLY | _O_BINARY)), TCPSocket::deleteFdFileNotSocket);

	if (fdfile < 0)
		throw new std::runtime_error("file open");

	struct _stat buf = {};
	if (_fstat(*fdfile, &buf) == -1)
		throw new std::runtime_error("file stat");
	assert((buf.st_mode & _S_IFREG) == _S_IFREG);
	const size_t size = buf.st_size;

	*o_size = size;
	return std::move(fdfile);
}

void tcpthreaded_startup_helper()
{
	WORD versionRequested = MAKEWORD(1, 1);
	WSADATA wsaData;

	if (WSAStartup(versionRequested, &wsaData))
		throw std::runtime_error("wsastartup");
}

#endif /* _TCPASYNC_H_ */
