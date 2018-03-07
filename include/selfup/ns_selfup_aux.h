#ifndef _NS_SELFUP_AUX_H_
#define _NS_SELFUP_AUX_H_

#include <cassert>
#include <cstdint>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include <selfup/NetworkPacket.h>
#include <selfup/TCPAsync.h>

#define NS_STATUS(cstr) do { NS_LOG_SZ(cstr, strlen(cstr)); NS_GUI_STATUS(cstr); } while (0)

/* NOTE: attempting to exit with non-joined std::threads causes abort() */
/* NOTE: main() must not leak exceptions due to reliance on stack unwinding (see RefKill) */
#define NS_TOPLEVEL_CATCH_SELFUP(retname, funcname, ...)	\
	do {											\
		try {										\
			funcname(__VA_ARGS__);					\
		} catch (const std::exception &e) {			\
			retname = 1;							\
			std::string msg(e.what());				\
			NS_LOG_SZ(msg.data(), msg.size());		\
		}											\
	} while(0)

class SelfupRespond
{
public:
	SelfupRespond(const std::shared_ptr<TCPSocket>& sock);

	void respondOneshot(NetworkPacket packet);
	NetworkPacket waitFrame();

private:
	std::shared_ptr<TCPSocket> m_sock;
};

class SelfupWork
{
public:
	SelfupWork(const char *node, const char *service);

	virtual ~SelfupWork() = default;

	void threadFunc();

	virtual void virtualThreadFunc() = 0;

	void start();

	void join();

	void readEnsureCmd(NetworkPacket *packet, uint8_t cmdid);

	uint8_t readGetCmd(NetworkPacket *packet);

protected:
	std::shared_ptr<TCPSocket>     m_sock;
	std::unique_ptr<SelfupRespond> m_respond;
	std::unique_ptr<std::thread> m_thread;
	std::exception_ptr           m_thread_exc;
};

#endif /* _NS_SELFUP_AUX_H_ */
