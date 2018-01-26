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
#define TCPASYNC_SELECT_LONGISH_TIMEOUT_MS 15000

int tcpasync_get_sock_error();
bool tcpasync_frame_write_helper_off_isend(
	size_t packet_data_size,
	size_t off);
bool tcpasync_frame_write_helper(
	int fd,
	NetworkPacket *packet,
	size_t forged_frame_size,
	size_t *off);
void tcpasync_sendfile_write_helper_CRUTCH(
	int fd,
	int fd_file_to_send_IGNORED,
	std::string filename_CRUTCH,
	size_t off_size_limit_CRUTCH,
	size_t *off);
bool tcpasync_select_oneshot(int fd, int timeout_ms);

class TCPAsync
{
public:
	class SockData;
	typedef ::std::map<TCPSocket::shared_ptr_fd, std::shared_ptr<SockData> > socks_t;

	struct sendqueueentry_packet_tag_t {};
	struct SendQueueEntry_packet_file_tag_t {};

	class SendQueueEntry
	{	
	public:
		SendQueueEntry(NetworkPacket packet, sendqueueentry_packet_tag_t) :
			m_packet(std::move(packet)),
			m_filename(),
			m_offset(0),
			m_fd(NULL, TCPSocket::deleteFdFileNotSocket),
			m_fd_size(-1),
			m_fd_offset(0)
		{}

		SendQueueEntry(NetworkPacket packet, const std::string &filename, SendQueueEntry_packet_file_tag_t) :
			m_packet(std::move(packet)),
			m_filename(filename),
			m_offset(0),
			m_fd(NULL, TCPSocket::deleteFdFileNotSocket),
			m_fd_size(-1),
			m_fd_offset(0)
		{}

		SendQueueEntry(const SendQueueEntry &a)            = delete;
		SendQueueEntry& operator=(const SendQueueEntry &a) = delete;
		SendQueueEntry(SendQueueEntry &&a)            = default;
		SendQueueEntry& operator=(SendQueueEntry &&a) = default;

		bool hasFile()
		{
			return !m_filename.empty();
		}

		void ensureFile()
		{
			if (!hasFile())
				throw std::runtime_error("file has not");

			if (! m_fd || *m_fd < 0) {
				m_fd = TCPSocket::unique_ptr_fd(new int(_open(m_filename.c_str(), _O_RDONLY | _O_BINARY)), TCPSocket::deleteFdFileNotSocket);

				if (*m_fd < 0)
					throw new std::runtime_error("file open");

				m_fd_size = computeFileSize(*m_fd);
			}
		}

		static size_t computeFileSize(int fd)
		{
#ifndef _WIN32
#error
#endif
			struct _stat buf = {};
			if (_fstat(fd, &buf) == -1)
				throw new std::runtime_error("file stat");
			assert((buf.st_mode & _S_IFREG) == _S_IFREG);
			return buf.st_size;
		}

	public:
		NetworkPacket m_packet;
		std::string   m_filename;
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
		std::deque<SendQueueEntry> m_queue_send;  /* 0 .. 9+sz */
	};

	class Respond
	{
	public:
		Respond(const std::shared_ptr<SockData> &d) :
			m_d(d)
		{}

		void respondOneshot(NetworkPacket packet)
		{
			m_d->m_queue_send.push_back(SendQueueEntry(std::move(packet), sendqueueentry_packet_tag_t()));
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

			if (rcvt < 0 && tcpasync_get_sock_error() == WSAEWOULDBLOCK)
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
			SendQueueEntry &snd = d->m_queue_send.front();

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

	void frameWriteFile(const TCPSocket::shared_ptr_fd &fd, const std::shared_ptr<SockData> &d, SendQueueEntry &snd)
	{
		{
			std::unique_lock<std::mutex> lock(m_write_mutex);
			m_write_queue.push_back(WriteQueueEntry(fd, d));
		}
		m_write_cv.notify_one();
	}

	/* @ret: writemore */
	bool frameWriteNormal(const TCPSocket::shared_ptr_fd &fd, const std::shared_ptr<SockData> &d, SendQueueEntry &snd)
	{
		bool writemore = tcpasync_frame_write_helper(*fd, &snd.m_packet, snd.m_packet.getDataSize(), &snd.m_offset);
		if (tcpasync_frame_write_helper_off_isend(snd.m_packet.getDataSize(), snd.m_offset))
			d->m_queue_send.pop_front();
		return writemore;
	}

	void virtualFrameDispatch(NetworkPacket *packet, Respond *respond) override
	{
		m_framedispatch(packet, respond);
	}

	void threadFuncWrite()
	{
		while (true) {
			std::unique_lock<std::mutex> lock(m_write_mutex);
			m_write_cv.wait(lock, [&]() { return ! m_write_queue.empty(); });
			WriteQueueEntry wqe = m_write_queue.front();
			m_write_queue.pop_front();
			lock.unlock();
			if (wqe.m_is_exit)
				return;
			while (! wqe.m_d->m_queue_send.empty()) {
				threadfuncHelperWriteOneEntry(wqe, wqe.m_d->m_queue_send.front());
				wqe.m_d->m_queue_send.pop_front();
			}
		}
	}

	void threadfuncHelperWriteOneEntry(const WriteQueueEntry &wqe, SendQueueEntry &snd)
	{
		if (snd.hasFile()) {
			// FIXME: here you would use the write->TCP_CORK/MSG_MORE->sendfile combo
			/* prep write */
			snd.ensureFile();
			size_t off = 0;
			/* packet portion write */
			tcpasync_general_write_helper(*wqe.m_fd, &snd.m_packet, snd.m_fd_size, &off);
			assert(tcpasync_frame_write_helper_off_isend(snd.m_packet.getDataSize(), off));
			/* file portion write */
			tcpasync_sendfile_write_helper_CRUTCH(*wqe.m_fd, *snd.m_fd, snd.m_filename, snd.m_fd_size, &snd.m_fd_offset);
			assert(snd.m_fd_offset == snd.m_fd_size);
		}
		else {
			size_t off = 0;
			/* packet portion write */
			tcpasync_general_write_helper(*wqe.m_fd, &snd.m_packet, 0, &off);
			assert(tcpasync_frame_write_helper_off_isend(snd.m_packet.getDataSize(), off));
		}
	}

private:
	function_framedispatch_t m_framedispatch;
	std::mutex m_write_mutex;
	std::condition_variable m_write_cv;
	std::vector<std::thread> m_write_thread;
	std::deque<WriteQueueEntry> m_write_queue;
};

int tcpasync_get_sock_error()
{
	return WSAGetLastError();
}

bool tcpasync_frame_write_helper_off_isend(
	size_t packet_data_size,
	size_t off)
{
	const size_t off_end_hdr = 9;
	const size_t off_end_buf = packet_data_size;
	
	assert(!(off > off_end_hdr + off_end_buf)); /* overrun ? */

	return off >= off_end_hdr + off_end_buf;
}

bool tcpasync_frame_write_helper(
	int fd,
	NetworkPacket *packet,
	size_t afterpacket_extra_size,
	size_t *off)
{
	const size_t sz = packet->getDataSize();
	const size_t fsz = sz + afterpacket_extra_size;
	const uint8_t hdr[9] = { 'F', 'R', 'A', 'M', 'E', (fsz >> 24) & 0xFF, (fsz >> 16) & 0xFF, (fsz >> 8) & 0xFF, (fsz >> 0) & 0xFF };

	const size_t off_end_hdr = 9;
	const size_t off_end_buf = sz;

	assert(!tcpasync_frame_write_helper_off_isend(sz, *off));
	
	const bool off_hdr_is = *off < off_end_hdr;

	const size_t off_hdr = *off;                /* used while sending hdr (off_hdr_is) */
	const size_t off_buf = *off - off_end_hdr;  /* used while sending buf (!off_hdr_is) */

	const size_t rem_hdr = off_end_hdr - off_hdr;
	const size_t rem_buf = off_end_buf - off_buf;

	const size_t   send_for = off_hdr_is ? rem_hdr : rem_buf;
	const uint8_t *send_ptr = off_hdr_is ? hdr + off_hdr : packet->getDataPtr() + off_buf;

	int sent = send(fd, (char *) send_ptr, send_for, 0);

	if (sent == 0)
		throw std::runtime_error("send sent zero");
	else if (sent < 0 && tcpasync_get_sock_error() != WSAEWOULDBLOCK)
		throw std::runtime_error("TCPSocket send sent");
	else if (sent < 0)
		return false;

	*off += sent;

	return true;
}

void tcpasync_general_write_helper(
	int fd,
	NetworkPacket *packet,
	size_t afterpacket_extra_size,
	size_t *off)
{
	while (!tcpasync_frame_write_helper_off_isend(packet->getDataSize(), *off)) {
		while (tcpasync_frame_write_helper(fd, packet, afterpacket_extra_size, off))
		{}
		if (tcpasync_frame_write_helper_off_isend(packet->getDataSize(), *off))
			break;
		while (!tcpasync_select_oneshot(fd, TCPASYNC_SELECT_LONGISH_TIMEOUT_MS))
		{}
	}
}

void tcpasync_sendfile_write_helper_CRUTCH(
	int fd,
	int fd_file_to_send_IGNORED,
	std::string filename_CRUTCH,
	size_t off_size_limit_CRUTCH,
	size_t *off)
{
	std::string data(ns_filesys::file_read(filename_CRUTCH));
	if (data.size() != off_size_limit_CRUTCH)
		throw std::runtime_error("size limit CRUTCH");
	size_t writeoff = 0;
	while (!(writeoff == data.size())) {
		int sent = send(fd, data.data() + writeoff, data.size() - writeoff, 0);

		if (sent == 0)
			throw std::runtime_error("send sent zero");
		else if (sent < 0 && tcpasync_get_sock_error() != WSAEWOULDBLOCK)
			throw std::runtime_error("send sent");
		else if (sent < 0) {
			while (!tcpasync_select_oneshot(fd, TCPASYNC_SELECT_LONGISH_TIMEOUT_MS))
			{}
			continue;
		}

		writeoff += sent;
	}

	*off + writeoff;
}

bool tcpasync_select_oneshot(int fd, int timeout_ms)
{
	fd_set write_set;

	FD_ZERO(&write_set);
	FD_SET(fd, &write_set);

	struct timeval tv = {};
	tv.tv_sec = 0;
	tv.tv_usec = timeout_ms * 1000;

	int result = select(fd + 1, NULL, &write_set, NULL, &tv);

	if (result < 0)
		throw std::runtime_error("TCPAsync wait");

	if (result == 0)
		return false;

	return FD_ISSET(fd, &write_set);
}

#endif /* _TCPASYNC_H_ */
