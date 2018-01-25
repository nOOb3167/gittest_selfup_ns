#ifndef _TCPASYNC_H_
#define _TCPASYNC_H_

#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <selfup/TCPSocket.h>
#include <selfup/NetworkPacket.h>

#define TCPASYNC_FRAME_SIZE_MAX (256 * 1024 * 1024)

#define TCPASYNC_WRITE_THREAD_NUM 8

class TCPAsync
{
public:
	class SockData;
	typedef ::std::map<TCPSocket::shared_ptr_fd, std::shared_ptr<SockData> > socks_t;

	struct socksend_packet_tag_t {};
	struct socksend_packet_file_tag_t {};

	class SockSend
	{	
	public:
		SockSend(NetworkPacket packet, socksend_packet_tag_t) :
			m_packet(std::move(packet)),
			m_offset(0),
			m_fd(NULL, TCPSocket::deleteFdFileNotSocket),
			m_fd_size(-1),
			m_fd_offset(0)
		{}

		SockSend(NetworkPacket packet, const std::string &filename, socksend_packet_file_tag_t) :
			m_packet(std::move(packet)),
			m_offset(0),
			m_fd(new int(_open(filename.c_str(), _O_RDONLY | _O_BINARY)), TCPSocket::deleteFdFileNotSocket),
			m_fd_size(-1),
			m_fd_offset(0)
		{
#ifndef _WIN32
#error
#endif
			if (*m_fd < 0)
				throw new std::runtime_error("file open");
			struct _stat buf = {};
			if (_fstat(*m_fd, &buf) == -1)
				throw new std::runtime_error("file stat");
			assert((buf.st_mode & _S_IFREG) == _S_IFREG);
			m_fd_size = buf.st_size;
		}

		SockSend(const SockSend &a)            = delete;
		SockSend& operator=(const SockSend &a) = delete;
		SockSend(SockSend &&a)            = default;
		SockSend& operator=(SockSend &&a) = default;

		bool hasFile()
		{
			return (m_fd && *m_fd >= 0);
		}

	public:
		NetworkPacket m_packet;
		size_t        m_offset;
		TCPSocket::unique_ptr_fd m_fd;
		size_t        m_fd_size;
		size_t        m_fd_offset;
	};

	class SockData
	{
	public:
		SockData() :
			m_off(0),
			m_hdr(),
			m_buf(),
			m_queue_recv(),
			m_queue_send()
		{}

	public:
		size_t      m_off;
		uint8_t     m_hdr[9];
		std::vector<uint8_t> m_buf;
		std::deque<NetworkPacket> m_queue_recv;
		std::deque<SockSend> m_queue_send;  /* 0 .. 9+sz */
	};

	class Respond
	{
	public:
		Respond(const std::shared_ptr<SockData> &d) :
			m_d(d)
		{}

		void respondOneshot(NetworkPacket packet)
		{
			m_d->m_queue_send.push_back(SockSend(std::move(packet), socksend_packet_tag_t()));
		}

	private:
		std::shared_ptr<SockData> m_d;
	};

	TCPAsync(Address addr) :
		m_listen(new int(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)), TCPSocket::deleteFd)
	{
		if (*m_listen < 0)
			throw std::runtime_error("TCPAsync socket");
		struct sockaddr_in sockaddr = {};
		sockaddr.sin_family = addr.getFamily();
		sockaddr.sin_port = htons(addr.getPort());
		sockaddr.sin_addr.s_addr = htonl(addr.getAddr4());
		if (bind (*m_listen, (struct sockaddr *) &sockaddr, sizeof sockaddr) < 0)
			throw std::runtime_error("TCPAsync bind");
		if (listen(*m_listen, 5) < 0)
			throw std::runtime_error("TCPAsync listen");

		unsigned long nonblock = 1;
		if (ioctlsocket(*m_listen, FIONBIO, &nonblock) < 0)
			throw std::runtime_error("TCPAsync ioctlsocket");
	}

	void Loop(int timeout_ms)
	{
		fd_set read_set;
		fd_set write_set;

		while (true) {

			FD_ZERO(&read_set);
			FD_ZERO(&write_set);

			FD_SET(*m_listen, &read_set);

			int fdmax = 0;

			for (auto it = m_socks.begin(); it != m_socks.end(); ++it) {
				fdmax = *it->first > fdmax ? *it->first : fdmax;
				if (it->second->m_queue_send.empty())
					FD_SET(*it->first, &read_set);
				else
					FD_SET(*it->first, &write_set);
			}

			struct timeval tv = {};
			tv.tv_sec = 0;
			tv.tv_usec = timeout_ms * 1000;

			int result = select(fdmax + 1, &read_set, &write_set, NULL, &tv);

			if (result < 0)
				throw std::runtime_error("TCPAsync wait");

			if (result == 0)
				continue;

			if (FD_ISSET(*m_listen, &read_set)) {
				struct sockaddr_in sockaddr = {};
				int socklen = sizeof sockaddr; // FIXME: socklen_t for NIX
				TCPSocket::unique_ptr_fd nsock(new int(accept(*m_listen, (struct sockaddr *) &sockaddr, &socklen)), TCPSocket::deleteFd);
				if (*nsock < 0)
					throw std::runtime_error("TCPAsync accept");
				unsigned long nonblock = 1;
				if (ioctlsocket(*m_listen, FIONBIO, &nonblock) < 0)
					throw std::runtime_error("TCPAsync ioctlsocket");
				if (! m_socks.insert(std::make_pair(std::move(nsock), std::shared_ptr<SockData>(new SockData()))).second)
					throw std::runtime_error("TCPAsync insert");
			}

			for (auto it = m_socks.begin(); it != m_socks.end(); ++it) {
				if (FD_ISSET(*it->first, &read_set)) {
					virtualFrameRead(it->first, it->second);
					while (! it->second->m_queue_recv.empty()) {
						NetworkPacket packet = std::move(it->second->m_queue_recv.front());
						it->second->m_queue_recv.pop_front();
						Respond respond(it->second);
						virtualFrameDispatch(&packet, &respond);
					}
				}
			}

			for (auto it = m_socks.begin(); it != m_socks.end(); /*dummy*/) {
				if (FD_ISSET(*it->first, &write_set))
					if (virtualFrameWrite(it->first, it->second))
						it = m_socks.erase(it);
					else
						++it;
			}
		}
	}

	virtual void virtualFrameRead(const TCPSocket::shared_ptr_fd &fd, const std::shared_ptr<SockData> &d) = 0;
	/* callee stealing the entry returns true */
	virtual bool virtualFrameWrite(const TCPSocket::shared_ptr_fd &fd, const std::shared_ptr<SockData> &d) = 0;
	virtual void virtualFrameDispatch(NetworkPacket *packet, Respond *respond) = 0;

protected:
	int getSockError()
	{
		return WSAGetLastError();
	}

private:
	TCPSocket::unique_ptr_fd m_listen;
	socks_t m_socks;
};

class TCPAsync1 : public TCPAsync
{
public:
	typedef ::std::function<void(NetworkPacket *packet, Respond *respond)> function_framedispatch_t;

	struct writequeueentry_exit_tag_t {};

	class WriteQueueEntry
	{
	public:
		WriteQueueEntry(writequeueentry_exit_tag_t) :
			m_is_exit(true),
			m_fd(),
			m_d()
		{}

		WriteQueueEntry(const TCPSocket::shared_ptr_fd &fd, const std::shared_ptr<SockData> &d) :
			m_is_exit(false),
			m_fd(fd),
			m_d(d)
		{}

	public:
		bool m_is_exit;
		TCPSocket::shared_ptr_fd m_fd;
		std::shared_ptr<SockData> m_d;
	};

	TCPAsync1(Address addr, function_framedispatch_t framedispatch) :
		TCPAsync(addr),
		m_framedispatch(framedispatch),
		m_write_thread()
	{
		for (size_t i = 0; i < TCPASYNC_WRITE_THREAD_NUM; i++)
			m_write_thread.push_back(std::move(std::thread(&TCPAsync1::threadFuncWrite, this)));
	}

	void virtualFrameRead(const TCPSocket::shared_ptr_fd &fd, const std::shared_ptr<SockData> &d) override
	{
		bool readmore = true;

		while (readmore) {
			/* decide how much data to wait for */
			size_t wait_for = 0;

			if (d->m_off < 9)
				wait_for = 9 - d->m_off; /* decide to wait_for just header */
			if (d->m_off >= 9) {
				/* validate */
				if (!!memcmp(&d->m_hdr[0], "FRAME", 5))
					throw ProtocolExc("frame magic");
				/* decide to wait_for header+data */
				uint32_t sz = (d->m_hdr[5] << 24) | (d->m_hdr[6] << 16) | (d->m_hdr[7] << 8) | (d->m_hdr[8] << 0);
				if (sz > TCPASYNC_FRAME_SIZE_MAX)
					throw std::runtime_error("frame size");
				wait_for = (9 + sz) - d->m_off;
				/* but we might have enough data already - so see if we can output */
				if (d->m_off >= 9 + sz) {
					assert(d->m_off == 9 + sz);
					NetworkPacket packet(std::move(d->m_buf), networkpacket_vec_steal_tag_t());
					d->m_buf = std::vector<uint8_t>();
					d->m_queue_recv.push_back(std::move(NetworkPacket(std::move(d->m_buf), networkpacket_vec_steal_tag_t())));
					d->m_off = 0;
				}
			}

			/* ensure space for wait_for */
			if (d->m_buf.size() < d->m_off + wait_for)
				d->m_buf.resize(d->m_off + wait_for);

			const uint8_t *wait_ptr = d->m_off < 9 ? d->m_hdr + d->m_off : d->m_buf.data() + (d->m_off - 9);

			int rcvt = recv(*fd, (char *)wait_ptr, wait_for, 0);

			if (rcvt < 0 && getSockError() == WSAEWOULDBLOCK)
				readmore = false;
			else if (rcvt < 0)
				throw std::runtime_error("TCPSocket recv rcvt");
			else if (rcvt == 0)
				readmore = false;  // FIXME: connection has closed in this case
			else {
				d->m_off += rcvt;
			}
		}
	}

	bool virtualFrameWrite(const TCPSocket::shared_ptr_fd &fd, const std::shared_ptr<SockData> &d) override
	{
		bool writemore = true;

		while (writemore && !d->m_queue_send.empty()) {
			/* queue will be pop_front-ed as needed deeper inside the call-graph.
			   maybe even after processing is queued onto a different thread. */
			SockSend &snd = d->m_queue_send.front();

			if (snd.hasFile()) {
				frameWriteFile(fd, d, snd);
				return true;
			}
			else {
				writemore = frameWriteNormal(fd, d, snd);
				continue;
			}
		}
		return false;
	}

	void frameWriteFile(const TCPSocket::shared_ptr_fd &fd, const std::shared_ptr<SockData> &d, SockSend &snd)
	{
		{
			std::unique_lock<std::mutex> lock(m_write_mutex);
			m_write_queue.push_back(WriteQueueEntry(fd, d));
		}
		m_write_cv.notify_one();
	}

	/* @ret: writemore */
	bool frameWriteNormal(const TCPSocket::shared_ptr_fd &fd, const std::shared_ptr<SockData> &d, SockSend &snd)
	{
		assert(snd.m_offset <= (9 + snd.m_packet.getDataSize()));

		size_t sz = snd.m_packet.getDataSize();
		uint8_t hdr[9] = { 'F', 'R', 'A', 'M', 'E', 0, 0, 0, 0 };
		hdr[5] = ((sz >> 24) & 0xFF); hdr[6] = ((sz >> 16) & 0xFF); hdr[7] = ((sz >> 8) & 0xFF); hdr[8] = ((sz >> 0) & 0xFF);

		size_t send_for = 0;

		if (snd.m_offset < 9)
			send_for = 9 - snd.m_offset;
		if (snd.m_offset >= 9)
			send_for = (9 + snd.m_packet.getDataSize()) - snd.m_offset;

		const uint8_t *send_ptr = snd.m_offset < 9 ? hdr + snd.m_offset : snd.m_packet.getDataPtr() + (snd.m_offset - 9);

		int sent = send(*fd, (char *)send_ptr, send_for, 0);

		if (sent < 0 && getSockError() == WSAEWOULDBLOCK)
			return false;
		else if (sent < 0)
			throw std::runtime_error("TCPSocket send sent");
		else {
			assert(sent != 0);

			snd.m_offset += sent;

			if (snd.m_offset == (9 + snd.m_packet.getDataSize()))
				d->m_queue_send.pop_front();
		}
		return true;
	}

	void virtualFrameDispatch(NetworkPacket *packet, Respond *respond) override
	{
		m_framedispatch(packet, respond);
	}

	void threadFuncWrite()
	{
		std::unique_lock<std::mutex> lock(m_write_mutex);
		while (true) {
			m_write_cv.wait(lock, [&]() { return ! m_write_queue.empty(); });
			WriteQueueEntry wqe = m_write_queue.front();
			m_write_queue.pop_front();
			if (wqe.m_is_exit)
				return;
			assert(! wqe.m_d->m_queue_send.empty());
			SockSend &snd = wqe.m_d->m_queue_send.front();
			assert(snd.hasFile());
			wqe.m_d->m_queue_send.pop_front();
		}
	}

private:
	function_framedispatch_t m_framedispatch;
	std::mutex m_write_mutex;
	std::condition_variable m_write_cv;
	std::vector<std::thread> m_write_thread;
	std::deque<WriteQueueEntry> m_write_queue;
};

#endif /* _TCPASYNC_H_ */
