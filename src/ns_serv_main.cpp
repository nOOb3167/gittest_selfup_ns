#include <exception>
#include <memory>
#include <stdexcept>
#include <thread>

#include <git2.h>  // FIXME: provides socket includes

#include <selfup/ns_helpers.h>
#include <selfup/TCPAsync.h>

#define SERVUP_ASYNC_TIMEOUT_MS 10000

typedef TCPAsync::Respond Respond;

class ServupWork
{
public:
	ServupWork(Address addr) :
		m_async(new TCPAsync1(addr, std::bind(&ServupWork::virtualFrameDispatch, this, std::placeholders::_1, std::placeholders::_2))),
		m_thread(),
		m_thread_exc()
	{
		m_thread.reset(new std::thread(&ServupWork::threadFunc, this));
	}

	void threadFunc()
	{
		try {
			m_async->Loop(SERVUP_ASYNC_TIMEOUT_MS);
		}
		catch (std::exception &) {
			m_thread_exc = std::current_exception();
		}
	}

	void join()
	{
		if (m_thread_exc)
			std::rethrow_exception(m_thread_exc);
	}

protected:
	virtual void virtualFrameDispatch(NetworkPacket *packet, Respond *respond) = 0;

private:
	std::unique_ptr<TCPAsync1>    m_async;
	std::unique_ptr<std::thread>  m_thread;
	std::exception_ptr            m_thread_exc;
};

class ServupConExt2
{
public:
};

class ServupWork2 : public ServupWork
{
public:
	ServupWork2(Address addr, std::shared_ptr<ServupConExt2> ext) :
		ServupWork(addr),
		m_ext(ext)
	{}

	void virtualFrameDispatch(NetworkPacket *packet, Respond *respond) override
	{
		throw std::runtime_error("unimplemented");
	}

private:
	std::shared_ptr<ServupConExt2> m_ext;
};

void servup_start_crank(Address addr)
{
	std::shared_ptr<ServupConExt2> ext(new ServupConExt2());
	std::unique_ptr<ServupWork2> work(new ServupWork2(addr, ext));
	work->join();
}

int main(int argc, char **argv)
{
	if (git_libgit2_init() < 0)
		throw std::runtime_error("libgit2 init");

	return EXIT_SUCCESS;
}
