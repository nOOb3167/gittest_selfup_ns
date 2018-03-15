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

#include <selfup/ns_log.h>
#include <selfup/NetworkPacket.h>
#include <selfup/TCPAddress.h>
#include <selfup/TCPSocket.h>

#define TCPASYNC_LOGDUMP(the_addrinfo, magic) do { std::unique_lock<std::mutex>(g_log->getMutex()); TCPLogDump::dump((the_addrinfo), (magic), g_log->getBuf().data(), g_log->getBuf().size()); } while (0)

class NsLogTlsServ : public ns_log::NsLogTls
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

#endif /* _TCPASYNC_H_ */
