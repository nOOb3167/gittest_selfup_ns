#include <selfup/TCPSocket.h>

int g_tcpsocket_disable_timeout = 0;

TCPSocket::TCPSocket(const char *node, const char *service, tcpsocket_connect_tag_t) :
	m_handle(tcpsocket_socket_connecting_helper(node, service))
{}

void TCPSocket::Send(NetworkPacket * packet)
{
	tcpsocket_blocking_write_helper(*m_handle, packet, 0);
}

NetworkPacket TCPSocket::Recv()
{
	return tcpsocket_blocking_read_helper(*m_handle);
}

void TCPSocket::deleteFd(int * fd)
{
	tcpsocket_socket_close_helper(fd);
}

void TCPSocket::deleteFdFileNotSocket(int * fd)
{
	tcpsocket_file_close_helper(fd);
}

#ifdef _WIN32

void tcpsocket_aux_recv(int fd, char *buf, int len)
{
	int off = 0;
	while (off < len) {
		int rcvt = recv(fd, buf + off, len - off, 0);
		/* https://stackoverflow.com/a/36913250
		     wtf does recv actually _return_ WSAETIMEDOUT? */
		/* SO_RCVTIMEO can cause WSAGetLastError WSAETIMEDOUT */
		/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms740476(v=vs.85).aspx
		     but indeterminate state on WSAETIMEDOUT - therefore no special handling */
		if (rcvt == 0 || rcvt < 0)
			throw std::runtime_error("recv rcvt");
		off += rcvt;
	}
}

void tcpsocket_socket_close_helper(int *fd)
{
	if (fd && *fd != INVALID_SOCKET) {
		closesocket(*fd);
		*fd = INVALID_SOCKET;
	}
}

unique_ptr_fd tcpsocket_socket_connecting_helper_gai(addrinfo *addr)
{
	for (addrinfo *r = addr; r != NULL; r = r->ai_next) {
		unique_ptr_fd sock(new int(socket(r->ai_family, r->ai_socktype, r->ai_protocol)), TCPSocket::deleteFd);
		if (*sock < 0)
			continue;
		if (connect(*sock, r->ai_addr, r->ai_addrlen) < 0)
			continue;
		return sock;
	}

	throw std::runtime_error("socket connecting helper");
}

unique_ptr_fd tcpsocket_socket_connecting_helper(const char *node, const char *service)
{
	return tcpsocket_socket_connecting_helper_gai(do_getaddrinfo_tcp(node, service).get());
}

Address tcpsocket_socket_peer_helper(int fd)
{
	struct sockaddr_storage sockaddr = {};
	int socklen = sizeof sockaddr;
	if (getpeername(fd, (struct sockaddr *) &sockaddr, &socklen) < 0)
		throw std::runtime_error("getpeername");
	Address addr(&sockaddr, address_storage_tag_t());
	return addr;
}

unique_ptr_fd tcpsocket_socket_listen_helper(const char *node, const char *service)
{
	unique_ptr_addrinfo res(do_getaddrinfo_tcp_listen(node, service));

	for (addrinfo *r = res.get(); r != NULL; r = r->ai_next) {
		unique_ptr_fd sock(new int(socket(r->ai_family, r->ai_socktype, r->ai_protocol)), TCPSocket::deleteFd);
		if (*sock < 0)
			continue;
		if (bind(*sock, r->ai_addr, r->ai_addrlen) < 0)
			continue;
		if (listen(*sock, 5) < 0)
			continue;
		return sock;
	}

	throw std::runtime_error("socket listen helper");
}

unique_ptr_fd tcpsocket_socket_accept_helper(int fd)
{
	struct sockaddr_storage sockaddr = {};
	int socklen = sizeof sockaddr;
	unique_ptr_fd nsock(new int(accept(fd, (struct sockaddr *) &sockaddr, &socklen)), TCPSocket::deleteFd);
	if (*nsock < 0)
		throw std::runtime_error("accept");
	if (! g_tcpsocket_disable_timeout) {
		int val = TCPSOCKET_ACCEPT_RCVTIMEO_MSEC;
		if (setsockopt(*nsock, SOL_SOCKET, SO_RCVTIMEO, (char *) &val, sizeof val) < 0)
			throw std::runtime_error("setsockopt");
	}
	return nsock;
}

NetworkPacket tcpsocket_blocking_read_helper(int fd)
{
	/* read header */

	uint8_t hdr[9] = {};

	tcpsocket_aux_recv(fd, (char *) hdr, 9);

	/* validate */

	if (!! memcmp(hdr, "FRAME", 5))
		throw ProtocolExc("frame magic");
	const uint32_t sz = (hdr[5] << 24) | (hdr[6] << 16) | (hdr[7] << 8) | (hdr[8] << 0);

	if (sz > TCPSOCKET_FRAME_SIZE_MAX)
		throw std::runtime_error("frame size");

	/* read packet */

	std::vector<uint8_t> buf;
	buf.resize(sz);

	tcpsocket_aux_recv(fd, (char *) buf.data(), buf.size());

	NetworkPacket packet(std::move(buf), networkpacket_vec_steal_tag_t());

	return packet;
}

void tcpsocket_blocking_write_helper(int fd, NetworkPacket *packet, size_t afterpacket_extra_size)
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

void tcpsocket_blocking_sendfile_helper(int fd, int fdfile, size_t size)
{
	std::string buf(size, '\0');
	
	int rcvt = _read(fdfile, (char *) buf.data(), buf.size());

	if (rcvt < 0 || rcvt == 0 || rcvt != buf.size())
		throw std::runtime_error("read rcvt");

	int sent = send(fd, buf.data(), buf.size(), 0);

	if (sent < 0 || sent == 0 || sent != buf.size())
		throw std::runtime_error("send sent");
}

unique_ptr_fd tcpsocket_file_open_size_helper(const std::string &filename, size_t *o_size)
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

void tcpsocket_file_close_helper(int *fd)
{
	if (fd && *fd != -1) {
		_close(*fd);
		*fd = -1;
	}
}

void tcpsocket_startup_helper()
{
	WORD versionRequested = MAKEWORD(1, 1);
	WSADATA wsaData;

	if (WSAStartup(versionRequested, &wsaData))
		throw std::runtime_error("wsastartup");
}

#else  /* _WIN32 */

void tcpsocket_aux_recv(int fd, char *buf, int len)
{
	size_t off = 0;
	while (off < len) {
		int rcvt = -1;
		while ((rcvt = recv(fd, (char *) buf + off, len - off, 0)) < 0)
		{
			/* SO_RCVTIMEO can cause errno EAGAIN or EWOULDBLOCK */
			if (g_tcpsocket_disable_timeout && (errno == EAGAIN || errno == EWOULDBLOCK))
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

void tcpsocket_socket_close_helper(int *fd)
{
	if (fd && *fd != -1) {
		close(*fd);
		*fd = -1;
	}
}

unique_ptr_fd tcpsocket_socket_connecting_helper_gai(addrinfo *addr)
{
	int ret = 0;

	for (addrinfo *r = addr; r != NULL; r = r->ai_next) {
		unique_ptr_fd sock(new int(socket(r->ai_family, r->ai_socktype, r->ai_protocol)), TCPSocket::deleteFd);
		if (*sock < 0)
			continue;
		while ((ret = connect(*sock, r->ai_addr, r->ai_addrlen)) < 0 && errno == EINTR)
		{}
		if (ret < 0)
			continue;
		return sock;
	}

	throw std::runtime_error("socket");
}

unique_ptr_fd tcpsocket_socket_connecting_helper(const char *node, const char *service)
{
	return tcpsocket_socket_connecting_helper_gai(do_getaddrinfo_tcp(node, service).get());
}

Address tcpsocket_socket_peer_helper(int fd)
{
	struct sockaddr_storage sockaddr = {};
	socklen_t socklen = sizeof sockaddr;
	if (getpeername(fd, (struct sockaddr *) &sockaddr, &socklen) < 0)
		throw std::runtime_error("getpeername");
	Address addr(&sockaddr, address_storage_tag_t());
	return addr;
}

unique_ptr_fd tcpsocket_socket_listen_helper(const char *node, const char *service)
{
	unique_ptr_addrinfo res(do_getaddrinfo_tcp_listen(node, service));

	for (addrinfo *r = res.get(); r != NULL; r = r->ai_next) {
		unique_ptr_fd sock(new int(socket(r->ai_family, r->ai_socktype, r->ai_protocol)), TCPSocket::deleteFd);
		if (*sock < 0)
			continue;
		if (bind(*sock, r->ai_addr, r->ai_addrlen) < 0)
			continue;
		if (listen(*sock, 5) < 0)
			continue;
		return sock;
	}

	throw std::runtime_error("socket listen helper");
}

unique_ptr_fd tcpsocket_socket_accept_helper(int fd)
{
	int ret = 0;
	struct sockaddr_storage sockaddr = {};
	socklen_t socklen = sizeof sockaddr; // FIXME: socklen_t for NIX
	while ((ret = accept(fd, (struct sockaddr *) &sockaddr, &socklen)) < 0)
	{
		if (errno == EINTR)
			continue;
		throw std::runtime_error("accept");
	}
	unique_ptr_fd nsock(new int(ret), TCPSocket::deleteFd);
	if (! g_tcpsocket_disable_timeout) {
		struct timeval val = {};
		val.tv_sec = TCPSOCKET_ACCEPT_RCVTIMEO_MSEC / 1000;
		val.tv_usec = (TCPSOCKET_ACCEPT_RCVTIMEO_MSEC % 1000) * 1000;
		if (setsockopt(*nsock, SOL_SOCKET, SO_RCVTIMEO, (char *) &val, sizeof val) < 0)
			throw std::runtime_error("setsockopt");
	}
	return nsock;
}

NetworkPacket tcpsocket_blocking_read_helper(int fd)
{
	int rcvt = 0;

	/* read header */

	uint8_t hdr[9] = {};

	tcpsocket_aux_recv(fd, (char *) hdr, 9);

	/* validate */

	if (!!memcmp(hdr, "FRAME", 5))
		throw ProtocolExc("frame magic");
	const uint32_t sz = (hdr[5] << 24) | (hdr[6] << 16) | (hdr[7] << 8) | (hdr[8] << 0);

	if (sz > TCPSOCKET_FRAME_SIZE_MAX)
		throw std::runtime_error("frame size");

	/* read packet */

	std::vector<uint8_t> buf;
	buf.resize(sz);

	tcpsocket_aux_recv(fd, (char *) buf.data(), buf.size());

	NetworkPacket packet(std::move(buf), networkpacket_vec_steal_tag_t());

	return packet;
}

void tcpsocket_blocking_write_helper(int fd, NetworkPacket *packet, size_t afterpacket_extra_size)
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

void tcpsocket_blocking_sendfile_helper(int fd, int fdfile, size_t size)
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

unique_ptr_fd tcpsocket_file_open_size_helper(const std::string &filename, size_t *o_size)
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

void tcpsocket_file_close_helper(int *fd)
{
	if (fd && *fd != -1) {
		close(*fd);
		*fd = -1;
	}
}

void tcpsocket_startup_helper()
{
	/* nothing - windows needs WSAStartup for example */
}

#endif /* _WIN32 */
