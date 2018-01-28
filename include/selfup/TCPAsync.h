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

#include <selfup/TCPSocket.h>
#include <selfup/NetworkPacket.h>

#define TCPASYNC_FRAME_SIZE_MAX (256 * 1024 * 1024)

TCPSocket::unique_ptr_fd tcpthreaded_socket_listen_helper(Address addr);
TCPSocket::unique_ptr_fd tcpthreaded_socket_accept_helper(int fd);
NetworkPacket tcpthreaded_blocking_read_helper(int fd);
void tcpthreaded_blocking_write_helper(int fd, NetworkPacket *packet, size_t afterpacket_extra_size);
void tcpthreaded_blocking_sendfile_helper(int fd, int fdfile, size_t size);
TCPSocket::unique_ptr_fd tcpthreaded_file_open_size_helper(const std::string &filename, size_t *o_size);

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
			TCPSocket::unique_ptr_fd fdfile(tcpthreaded_file_open_size_helper(filename, &size));
			tcpthreaded_blocking_write_helper(m_fd, &packet, size);
			tcpthreaded_blocking_sendfile_helper(m_fd, *fdfile, size);
		}

	private:
		int m_fd;
	};

	class ThreadCtx : public std::enable_shared_from_this<ThreadCtx>
	{
	public:
		ThreadCtx(size_t thread_idx) :
			m_thread(),
			m_thread_idx(thread_idx)
		{}

		void start(const std::function<void(TCPThreaded *, const std::shared_ptr<ThreadCtx> &)> &func, TCPThreaded *tcpthr)
		{
			m_thread = std::move(std::thread(func, tcpthr, shared_from_this()));
		}

		void join()
		{
			m_thread.join();
		}

	public:
		std::thread m_thread;
		size_t      m_thread_idx;
	};

	TCPThreaded(Address addr, size_t thread_num) :
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

	void start()
	{
		for (size_t i = 0; i < m_thread.size(); i++)
			m_thread[i]->start(&TCPThreaded::threadFunc, this);
	}

	void startListen()
	{
		m_listen_thread = std::move(std::thread(&TCPThreaded::threadFuncListenLoop, this));
	}

	void joinBoth()
	{
		m_listen_thread.join();
		for (size_t i = 0; i < m_thread.size(); i++)
			m_thread[i]->join();
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
			TCPSocket::unique_ptr_fd nsock(tcpthreaded_socket_accept_helper(*m_listen));

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
		catch (std::exception &) {
			m_thread_exc.at(ctx->m_thread_idx) = std::current_exception();
		}
	}

	void threadFunc2(const std::shared_ptr<ThreadCtx> &ctx)
	{
		while (true) {
			std::unique_lock<std::mutex> lock(m_queue_mutex);
			m_queue_cv.wait(lock, [&]() { return !m_queue_incoming.empty(); });
			TCPSocket::unique_ptr_fd fd = std::move(m_queue_incoming.front());
			m_queue_incoming.pop_front();
			lock.unlock();

			while (true) {
				NetworkPacket packet(tcpthreaded_blocking_read_helper(*fd));
				Respond respond(*fd);
				frameDispatch(&packet, &respond);
			}
		}
	}

	virtual void frameDispatch(NetworkPacket *packet, Respond *respond) = 0;

public:
	std::exception_ptr m_listen_thread_exc;
	std::vector<std::exception_ptr> m_thread_exc;

private:
	TCPSocket::unique_ptr_fd m_listen;
	std::thread m_listen_thread;

	std::vector<std::shared_ptr<ThreadCtx> > m_thread;

	std::mutex m_queue_mutex;
	std::condition_variable m_queue_cv;
	std::deque<TCPSocket::unique_ptr_fd> m_queue_incoming;
};

class TCPThreaded1 : public TCPThreaded
{
public:
	typedef ::std::function<void(NetworkPacket *packet, Respond *respond)> function_framedispatch_t;

	TCPThreaded1(Address addr, size_t thread_num, function_framedispatch_t framedispatch) :
		TCPThreaded(addr, thread_num),
		m_framedispatch(framedispatch)
	{}

protected:
	void frameDispatch(NetworkPacket *packet, Respond *respond) override
	{
		m_framedispatch(packet, respond);
	}

private:
	function_framedispatch_t m_framedispatch;
};

TCPSocket::unique_ptr_fd tcpthreaded_socket_listen_helper(Address addr)
{
	TCPSocket::unique_ptr_fd sock(new int(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), TCPSocket::deleteFd);
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

TCPSocket::unique_ptr_fd tcpthreaded_socket_accept_helper(int fd)
{
	struct sockaddr_in sockaddr = {};
	int socklen = sizeof sockaddr; // FIXME: socklen_t for NIX
	TCPSocket::unique_ptr_fd nsock(new int(accept(fd, (struct sockaddr *) &sockaddr, &socklen)), TCPSocket::deleteFd);
	if (*nsock < 0)
		throw std::runtime_error("accept");
	return nsock;
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

TCPSocket::unique_ptr_fd tcpthreaded_file_open_size_helper(const std::string &filename, size_t *o_size)
{
	TCPSocket::unique_ptr_fd fdfile(new int(_open(filename.c_str(), _O_RDONLY | _O_BINARY)), TCPSocket::deleteFdFileNotSocket);

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

#endif /* _TCPASYNC_H_ */
