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
#include <selfup/ns_thread.h>

TimeoutExc::TimeoutExc(const char * msg) :
	std::runtime_error(msg)
{}

NsLogTlsServ::NsLogTlsServ(const std::string &thread_idx_s) :
  m_thread_idx_s(thread_idx_s)
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

TCPThreaded::Respond::Respond(int fd) :
	m_fd(fd)
{}

void TCPThreaded::Respond::respondOneshot(NetworkPacket packet)
{
	tcpsocket_blocking_write_helper(m_fd, &packet, 0);
}

void TCPThreaded::Respond::respondOneshotSendfile(NetworkPacket packet, const std::string & filename)
{
	size_t size = 0;
	unique_ptr_fd fdfile(tcpsocket_file_open_size_helper(filename, &size));
	tcpsocket_blocking_write_helper(m_fd, &packet, size);
	tcpsocket_blocking_sendfile_helper(m_fd, *fdfile, size);
}

TCPThreaded::ThreadCtx::ThreadCtx(size_t thread_idx) :
	m_thread(),
	m_thread_idx(thread_idx)
{}

TCPThreaded::TCPThreaded(const char *node, const char *service, size_t thread_num) :
	m_framedispatch(),
	m_listen(tcpsocket_socket_listen_helper(node, service)),
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
	std::string name("[-] ");

	ns_thread_name_set_current(name);

	try {
		g_log->threadInitTls(new NsLogTlsServ(name));

		threadFuncListenLoop2();
	}
	catch (std::exception &) {
		m_listen_thread_exc = std::current_exception();
	}
}

void TCPThreaded::threadFuncListenLoop2()
{
	while (true) {
		unique_ptr_fd nsock(tcpsocket_socket_accept_helper(*m_listen));

		Address peer = tcpsocket_socket_peer_helper(*nsock);

		NS_SOG_PF("accept [%s]", peer.getStr().c_str());

		{
			std::unique_lock<std::mutex> lock(m_queue_mutex);
			m_queue_incoming.push_back(std::move(nsock));
		}
		m_queue_cv.notify_one();
	}
}

void TCPThreaded::threadFunc(const std::shared_ptr<ThreadCtx>& ctx)
{
	std::string name = std::string("[") + std::to_string(ctx->m_thread_idx) + std::string("] ");

	ns_thread_name_set_current(name);

	try {
		g_log->threadInitTls(new NsLogTlsServ(name));

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

		Address peer = tcpsocket_socket_peer_helper(*fd);

		NS_SOG_PF("connect [%s]", peer.getStr().c_str());

		try {
			while (true) {
				NetworkPacket packet(tcpsocket_blocking_read_helper(*fd));
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

void TCPLogDump::dump(addrinfo *addr, uint32_t magic, const char * data, size_t data_len)
{
	NetworkPacket packet(SELFUP_CMD_LOGDUMP, networkpacket_cmd_tag_t());
	packet << magic;
	packet << (uint32_t)data_len;
	packet.outSizedStr(data, data_len);

	unique_ptr_fd sock(tcpsocket_socket_connecting_helper_gai(addr));
	tcpsocket_blocking_write_helper(*sock, &packet, 0);
}
