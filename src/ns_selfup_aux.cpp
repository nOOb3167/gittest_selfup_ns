#include <cassert>
#include <cstdint>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include <selfup/NetworkPacket.h>
#include <selfup/ns_selfup_aux.h>
#include <selfup/TCPAsync.h>

void SelfupRespond::respondOneshot(NetworkPacket packet)
{
	virtualRespond(std::move(packet));
}

NetworkPacket SelfupRespond::waitFrame()
{
	return std::move(virtualWaitFrame());
}

SelfupRespondWork::SelfupRespondWork(const std::shared_ptr<TCPSocket>& sock) :
	m_sock(sock)
{}

void SelfupRespondWork::virtualRespond(NetworkPacket packet)
{
	m_sock->Send(&packet);
}

NetworkPacket SelfupRespondWork::virtualWaitFrame()
{
	/* FIXME: timeout support */
	return m_sock->Recv();
}

SelfupWork::SelfupWork(const char * node, const char * service) :
	m_sock(new TCPSocket(node, service, tcpsocket_connect_tag_t())),
	m_respond(new SelfupRespondWork(m_sock)),
	m_thread(),
	m_thread_exc()
{}

void SelfupWork::threadFunc()
{
	try {
		virtualThreadFunc();
	}
	catch (std::exception &e) {
		m_thread_exc = std::current_exception();
	}
}

void SelfupWork::start()
{
	m_thread.reset(new std::thread(&SelfupWork::threadFunc, this));
}

void SelfupWork::join()
{
	m_thread->join();

	if (m_thread_exc) {
		try {
			std::rethrow_exception(m_thread_exc);
		}
		catch (std::exception &e) {
			throw;
		}
	}
}

void SelfupWork::readEnsureCmd(NetworkPacket * packet, uint8_t cmdid)
{
	if (cmdid != readGetCmd(packet))
		throw ProtocolExc("cmd");
}

uint8_t SelfupWork::readGetCmd(NetworkPacket * packet)
{
	assert(packet->isReset());
	uint8_t c;
	(*packet) >> c;
	return c;
}
