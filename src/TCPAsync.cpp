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
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <selfup/ns_helpers.h>
#include <selfup/ns_log.h>

#include <selfup/NetworkPacket.h>
#include <selfup/TCPAddress.h>
#include <selfup/TCPAsync.h>

int g_tcpasync_disable_timeout = 0;

TimeoutExc::TimeoutExc(const char * msg) :
	std::runtime_error(msg)
{}

NsLogTlsServ::NsLogTlsServ(size_t thread_idx) :
	m_thread_idx_s()
{
	m_thread_idx_s.append("[");
	m_thread_idx_s.append(std::to_string(thread_idx));
	m_thread_idx_s.append("] ");
}

std::string & NsLogTlsServ::virtualGetIdent()
{
	return m_thread_idx_s;
}

TCPSocket::TCPSocket() :
	m_handle(tcpthreaded_socket_helper())
{}

void TCPSocket::Connect(Address addr)
{
	if (addr.getFamily() != AF_INET)
		throw std::runtime_error("TCPSocket connect family");

	tcpthreaded_socket_connect_helper(*m_handle, addr);
}

void TCPSocket::Send(NetworkPacket * packet)
{
	tcpthreaded_blocking_write_helper(*m_handle, packet, 0);
}

NetworkPacket TCPSocket::Recv()
{
	return tcpthreaded_blocking_read_helper(*m_handle);
}

void TCPSocket::deleteFd(int * fd)
{
	tcpthreaded_socket_close_helper(fd);
}

void TCPSocket::deleteFdFileNotSocket(int * fd)
{
	tcpthreaded_file_close_helper(fd);
}

TCPThreaded::Respond::Respond(int fd) :
	m_fd(fd)
{}

void TCPThreaded::Respond::respondOneshot(NetworkPacket packet)
{
	tcpthreaded_blocking_write_helper(m_fd, &packet, 0);
}

void TCPThreaded::Respond::respondOneshotSendfile(NetworkPacket packet, const std::string & filename)
{
	size_t size = 0;
	unique_ptr_fd fdfile(tcpthreaded_file_open_size_helper(filename, &size));
	tcpthreaded_blocking_write_helper(m_fd, &packet, size);
	tcpthreaded_blocking_sendfile_helper(m_fd, *fdfile, size);
}

TCPThreaded::ThreadCtx::ThreadCtx(size_t thread_idx) :
	m_thread(),
	m_thread_idx(thread_idx)
{}

TCPThreaded::TCPThreaded(Address addr, size_t thread_num) :
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

void TCPThreaded::setFrameDispatch(const function_framedispatch_t & framedispatch)
{
	m_framedispatch = framedispatch;
}

void TCPThreaded::startBoth()
{
	m_listen_thread = std::move(std::thread(&TCPThreaded::threadFuncListenLoop, this));
	for (size_t i = 0; i < m_thread.size(); i++)
		m_thread[i]->m_thread = std::move(std::thread(&TCPThreaded::threadFunc, this, m_thread[i]));
}

void TCPThreaded::joinBoth()
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

void TCPThreaded::threadFuncListenLoop()
{
	try {
		g_log->threadInitTls(new NsLogTlsServ(0xFFFFFFFF));

		threadFuncListenLoop2();
	}
	catch (std::exception &) {
		m_listen_thread_exc = std::current_exception();
	}
}

void TCPThreaded::threadFuncListenLoop2()
{
	while (true) {
		unique_ptr_fd nsock(tcpthreaded_socket_accept_helper(*m_listen));

		Address peer = tcpthreaded_socket_peer_helper(*nsock);

		NS_SOG_PF("accept [%#.8X:%h.4u]", peer.getAddr4(), peer.getPort());

		{
			std::unique_lock<std::mutex> lock(m_queue_mutex);
			m_queue_incoming.push_back(std::move(nsock));
		}
		m_queue_cv.notify_one();
	}
}

void TCPThreaded::threadFunc(const std::shared_ptr<ThreadCtx>& ctx)
{
	try {
		g_log->threadInitTls(new NsLogTlsServ(ctx->m_thread_idx));

		threadFunc2(ctx);
	}
	catch (std::exception &e) {
		m_thread_exc.at(ctx->m_thread_idx) = std::current_exception();
	}
}

void TCPThreaded::threadFunc2(const std::shared_ptr<ThreadCtx>& ctx)
{
	while (true) {
		std::unique_lock<std::mutex> lock(m_queue_mutex);
		m_queue_cv.wait(lock, [&]() { return !m_queue_incoming.empty(); });
		unique_ptr_fd fd = std::move(m_queue_incoming.front());
		m_queue_incoming.pop_front();
		lock.unlock();

		Address peer = tcpthreaded_socket_peer_helper(*fd);

		NS_SOG_PF("connect [%#.8X:%h.4u]", peer.getAddr4(), peer.getPort());

		try {
			while (true) {
				NetworkPacket packet(tcpthreaded_blocking_read_helper(*fd));
				Respond respond(*fd);
				m_framedispatch(&packet, &respond);
			}
		}
		catch (std::runtime_error &e) {
			/* disconnect - resume dequeuing incoming connections */
			NS_SOG_PF("disconnect [what=[%s]]", e.what());
		}
	}
}

void TCPLogDump::dump(Address addr, uint32_t magic, const char * data, size_t data_len)
{
	NetworkPacket packet(SELFUP_CMD_LOGDUMP, networkpacket_cmd_tag_t());
	packet << magic;
	packet << (uint32_t)data_len;
	packet.outSizedStr(data, data_len);
	unique_ptr_fd sock = tcpthreaded_socket_helper();
	tcpthreaded_socket_connect_helper(*sock, addr);
	tcpthreaded_blocking_write_helper(*sock, &packet, 0);
}

#ifdef _WIN32

void tcpthreaded_aux_recv(int fd, char *buf, int len)
{
	int off = 0;
	while (off < len) {
		int rcvt = recv(fd, buf + off, len - off, 0);
		/* https://stackoverflow.com/a/36913250
		     wtf does recv actually _return_ WSAETIMEOUT? */
		/* SO_RCVTIMEO can cause WSAGetLastError WSAETIMEOUT */
		/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms740476(v=vs.85).aspx
		     but indeterminate state on WSAETIMEDOUT - therefore no special handling */
		if (rcvt == 0 || rcvt < 0)
			throw std::runtime_error("recv rcvt");
		off += rcvt;
	}
}

void tcpthreaded_socket_close_helper(int *fd)
{
	if (fd && *fd != INVALID_SOCKET) {
		closesocket(*fd);
		*fd = INVALID_SOCKET;
	}
}

unique_ptr_fd tcpthreaded_socket_helper()
{
	unique_ptr_fd sock(new int(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), TCPSocket::deleteFd);
	if (*sock < 0)
		throw std::runtime_error("socket");
	return sock;
}

Address tcpthreaded_socket_peer_helper(int fd)
{
	struct sockaddr_in sockaddr = {};
	int socklen = sizeof sockaddr;
	if (getpeername(fd, (struct sockaddr *) &sockaddr, &socklen) < 0)
		throw std::runtime_error("getpeername");
	if (sockaddr.sin_family != AF_INET)
		throw std::runtime_error("getpeername family");
	Address addr(sockaddr.sin_family, ntohs(sockaddr.sin_port), ntohl(sockaddr.sin_addr.s_addr), address_ipv4_tag_t());
	return addr;
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
	int socklen = sizeof sockaddr;
	unique_ptr_fd nsock(new int(accept(fd, (struct sockaddr *) &sockaddr, &socklen)), TCPSocket::deleteFd);
	if (*nsock < 0)
		throw std::runtime_error("accept");
	if (! g_tcpasync_disable_timeout) {
		int val = TCPASYNC_ACCEPT_RCVTIMEO_MSEC;
		if (setsockopt(*nsock, SOL_SOCKET, SO_RCVTIMEO, (char *) &val, sizeof val) < 0)
			throw std::runtime_error("setsockopt");
	}
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

	tcpthreaded_aux_recv(fd, (char *) hdr, 9);

	/* validate */

	if (!! memcmp(hdr, "FRAME", 5))
		throw ProtocolExc("frame magic");
	const uint32_t sz = (hdr[5] << 24) | (hdr[6] << 16) | (hdr[7] << 8) | (hdr[8] << 0);

	if (sz > TCPASYNC_FRAME_SIZE_MAX)
		throw std::runtime_error("frame size");

	/* read packet */

	std::vector<uint8_t> buf;
	buf.resize(sz);

	tcpthreaded_aux_recv(fd, (char *) buf.data(), buf.size());

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
		throw std::runtime_error("read rcvt");

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

void tcpthreaded_file_close_helper(int *fd)
{
	if (fd && *fd != -1) {
		_close(*fd);
		*fd = -1;
	}
}

void tcpthreaded_startup_helper()
{
	WORD versionRequested = MAKEWORD(1, 1);
	WSADATA wsaData;

	if (WSAStartup(versionRequested, &wsaData))
		throw std::runtime_error("wsastartup");
}

#else  /* _WIN32 */

void tcpthreaded_aux_recv(int fd, char *buf, int len)
{
	size_t off = 0;
	while (off < len) {
		int rcvt = -1;
		while ((rcvt = recv(fd, (char *) buf + off, len - off, 0)) < 0)
		{
			/* SO_RCVTIMEO can cause errno EAGAIN or EWOULDBLOCK */
			if (g_tcpasync_disable_timeout && (errno == EAGAIN || errno == EWOULDBLOCK))
				continue;
			if (errno == EINTR)
				continue;
			throw std::runtime_error("recv rcvt");
		}
		if (rcvt == 0)
			throw std::runtime_error("recv rcvt");
		off += rcvt;
	}
}

void tcpthreaded_socket_close_helper(int *fd)
{
	if (fd && *fd != -1) {
		close(*fd);
		*fd = -1;
	}
}

unique_ptr_fd tcpthreaded_socket_helper()
{
	unique_ptr_fd sock(new int(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), TCPSocket::deleteFd);
	if (*sock < 0)
		throw std::runtime_error("socket");
	return sock;
}

Address tcpthreaded_socket_peer_helper(int fd)
{
	struct sockaddr_in sockaddr = {};
	socklen_t socklen = sizeof sockaddr;
	if (getpeername(fd, (struct sockaddr *) &sockaddr, &socklen) < 0)
		throw std::runtime_error("getpeername");
	if (sockaddr.sin_family != AF_INET)
		throw std::runtime_error("getpeername family");
	Address addr(sockaddr.sin_family, ntohs(sockaddr.sin_port), ntohl(sockaddr.sin_addr.s_addr), address_ipv4_tag_t());
	return addr;
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
	int ret = 0;
	struct sockaddr_in sockaddr = {};
	socklen_t socklen = sizeof sockaddr; // FIXME: socklen_t for NIX
	while ((ret = accept(fd, (struct sockaddr *) &sockaddr, &socklen)) < 0)
	{
		if (errno == EINTR)
			continue;
		throw std::runtime_error("accept");
	}
	unique_ptr_fd nsock(new int(ret), TCPSocket::deleteFd);
	if (! g_tcpasync_disable_timeout) {
		struct timeval val = {};
		val.tv_sec = TCPASYNC_ACCEPT_RCVTIMEO_MSEC / 1000;
		val.tv_usec = (TCPASYNC_ACCEPT_RCVTIMEO_MSEC % 1000) * 1000;
		if (setsockopt(*nsock, SOL_SOCKET, SO_RCVTIMEO, (char *) &val, sizeof val) < 0)
			throw std::runtime_error("setsockopt");
	}
	return nsock;
}

void tcpthreaded_socket_connect_helper(int fd, Address addr)
{
	int ret = 0;
	struct sockaddr_in sockaddr = {};
	sockaddr.sin_family = addr.getFamily();
	sockaddr.sin_port = htons(addr.getPort());
	sockaddr.sin_addr.s_addr = htonl(addr.getAddr4());
	while ((ret = connect(fd, (struct sockaddr *) &sockaddr, sizeof sockaddr)) < 0)
	{
		if (errno == EINTR)
			continue;
		throw std::runtime_error("connect");
	}
}

NetworkPacket tcpthreaded_blocking_read_helper(int fd)
{
	int rcvt = 0;

	/* read header */

	uint8_t hdr[9] = {};

	tcpthreaded_aux_recv(fd, (char *) hdr, 9);

	/* validate */

	if (!!memcmp(hdr, "FRAME", 5))
		throw ProtocolExc("frame magic");
	const uint32_t sz = (hdr[5] << 24) | (hdr[6] << 16) | (hdr[7] << 8) | (hdr[8] << 0);

	if (sz > TCPASYNC_FRAME_SIZE_MAX)
		throw std::runtime_error("frame size");

	/* read packet */

	std::vector<uint8_t> buf;
	buf.resize(sz);

	tcpthreaded_aux_recv(fd, (char *) buf.data(), buf.size());

	NetworkPacket packet(std::move(buf), networkpacket_vec_steal_tag_t());

	return packet;
}

void tcpthreaded_blocking_write_helper(int fd, NetworkPacket *packet, size_t afterpacket_extra_size)
{
	/* write header */

	const size_t fsz = packet->getDataSize() + afterpacket_extra_size;

	uint8_t hdr[9] = {
		'F', 'R', 'A', 'M', 'E',
		(uint8_t)(fsz >> 24 & 0xFF),
		(uint8_t)(fsz >> 16 & 0xFF),
		(uint8_t)(fsz >> 8 & 0xFF),
		(uint8_t)(fsz >> 0 & 0xFF) };

	const size_t iov_len = 2;
	struct iovec iov[2] = {};
	iov[0].iov_base = hdr;
	iov[0].iov_len  = 9;
	iov[1].iov_base = packet->getDataPtr();
	iov[1].iov_len  = packet->getDataSize();

	while (iov[iov_len - 1].iov_len != 0) {
		ssize_t nwritten = 0;
		while ((nwritten = writev(fd, iov, 2)) < 0) {
			if (errno == EINTR)
				continue;
			throw std::runtime_error("writev");
		}
		if (nwritten == 0)
			throw std::runtime_error("writev zero");

		/* account for nwritten bytes */
		size_t iovidx = 0;
		while (nwritten && iovidx < iov_len) {
			size_t take = GS_MIN(nwritten, iov[iovidx].iov_len);
			uint8_t * inc = (uint8_t*) iov[iovidx].iov_base + take;
			iov[iovidx].iov_base  = inc;
			iov[iovidx].iov_len  -= take;
			nwritten -= take;
			if (iov[iovidx].iov_len == 0)
				iovidx++;
		}
		/* call indicates more written more bytes than available in iov - WTF */
		if (nwritten)
			throw std::runtime_error("writev nwritten");
	}
}

void tcpthreaded_blocking_sendfile_helper(int fd, int fdfile, size_t size)
{
	off_t offset = 0;
	while (offset < size) {
		ssize_t nwritten = 0;
		while ((nwritten = sendfile(fd, fdfile, &offset, size - offset)) < 0)
		{
			if (errno == EINTR)
				continue;
			throw std::runtime_error("sendfile");
		}
		if (nwritten == 0)
			throw std::runtime_error("sendfile zero");

		offset += nwritten;
	}
}

unique_ptr_fd tcpthreaded_file_open_size_helper(const std::string &filename, size_t *o_size)
{
	/* FIXME: does open require handling EINTR ? */
	unique_ptr_fd fdfile(new int(open(filename.c_str(), O_RDONLY)), TCPSocket::deleteFdFileNotSocket);
	if (fdfile < 0)
		throw new std::runtime_error("file open");

	struct stat buf = {};
	if (fstat(*fdfile, &buf) == -1)
		throw new std::runtime_error("file stat");
	assert((buf.st_mode & S_IFREG) == S_IFREG);
	const size_t size = buf.st_size;

	*o_size = size;
	return fdfile;
}

void tcpthreaded_file_close_helper(int *fd)
{
	if (fd && *fd != -1) {
		close(*fd);
		*fd = -1;
	}
}

void tcpthreaded_startup_helper()
{
	/* nothing - windows needs WSAStartup for example */
}

#endif /* _WIN32 */
