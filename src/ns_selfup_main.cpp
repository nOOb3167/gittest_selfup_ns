#include <cassert>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>

#include <selfup/NetworkPacket.h>
#include <selfup/TCPSocket.h>

#define GS_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define GS_MIN(x, y) (((x) < (y)) ? (x) : (y))

#define SELFUP_FRAME_SIZE_MAX (256 * 1024 * 1024)
#define SELFUP_LONG_TIMEOUT_MS (30 * 1000)

#define SELFUP_CMD_REQUEST_LATEST_SELFUPDATE_BLOB 11
#define SELFUP_CMD_RESPONSE_LATEST_SELFUPDATE_BLOB 12

long long selfup_timestamp()
{
	struct timespec tspec = {};

#ifdef _WIN32
	/* supposedly not available in VS2013 - switch to something else */
	if (! timespec_get(&tspec, TIME_UTC))
		throw std::runtime_error("timestamp get");
#else
	if (!! clock_gettime(CLOCK_MONOTONIC, &tspec))
		throw std::runtime_error("timestamp get");
#endif
	return (tspec.tv_sec * 1000) + (tspec.tv_nsec / (1000 * 1000));
}

class SelfupConExt
{
public:
};

class SelfupRespond
{
public:
	void respondOneshot(NetworkPacket packet)
	{
		virtualRespond(std::move(packet));
	}

	NetworkPacket waitFrame()
	{
		return std::move(virtualWaitFrame());
	}

protected:
	virtual void virtualRespond(NetworkPacket packet) = 0;
	virtual NetworkPacket virtualWaitFrame() = 0;
};

class SelfupRespondWork : public SelfupRespond
{
public:
	SelfupRespondWork(const std::shared_ptr<TCPSocket> &sock) :
		m_sock(sock),
		m_buf_part()
	{}

protected:
	void virtualRespond(NetworkPacket packet) override
	{
		uint32_t sz = packet.getDataSize();
		uint8_t buf[4] = { (sz >> 24) & 0xFF, (sz >> 16) & 0xFF, (sz >> 8) & 0xFF, (sz >> 0) & 0xFF };

		// FIXME: use writev / WSASend multibuffer

		m_sock->Send("FRAME", 5);
		m_sock->Send(buf, sizeof buf);

		m_sock->Send(packet.getDataPtr(), packet.getDataSize());
	}

	NetworkPacket virtualWaitFrame() override
	{
		long long timestamp = selfup_timestamp();
		const long long deadline = timestamp + SELFUP_LONG_TIMEOUT_MS;
		long long buf_off = 0;
		std::string buf(m_buf_part);
		int rcvt = 0;
		while (timestamp <= deadline) {
			/* decide how much data to wait for*/
			size_t wait_for = 0;

			if (buf_off < 9)
				wait_for = 9 - buf_off; /* decide to wait_for just header */
			if (buf_off >= 9) {
				/* validate */
				if (!! memcmp(&buf[0], "FRAME", 5))
					throw ProtocolExc("waitFrame frame");
				/* decide to wait_for header+data */
				uint32_t sz = (buf[5] << 24) | (buf[6] << 16) | (buf[7] << 8) | (buf[8] << 0);
				if (sz > SELFUP_FRAME_SIZE_MAX)
					throw std::runtime_error("waitFrame size");
				wait_for = (9 + sz) - buf_off;
				/* but we might have enough data already - so see if we can output */
				if (buf_off >= 9 + sz) {
					NetworkPacket packet((uint8_t *)&buf[9], sz, networkpacket_buf_len_tag_t());
					m_buf_part = buf.substr(9 + sz, std::string::npos);
					return std::move(packet);
				}
			}

			/* ensure space for wait_for */
			if (buf.size() < buf_off + wait_for)
				buf.resize(buf_off + wait_for);

			if (-1 == (rcvt = m_sock->ReceiveWaiting(((uint8_t *) buf.data()) + buf_off, wait_for, deadline - timestamp)))
				throw std::runtime_error("waitFrame time");
			buf_off += rcvt;

			timestamp = selfup_timestamp();
		}
		assert(! (timestamp <= deadline));
		throw std::runtime_error("waitFrame time");
	}

private:
	std::shared_ptr<TCPSocket> m_sock;
	std::string m_buf_part;
};

class SelfupWork
{
public:
	SelfupWork(Address addr) :
		m_sock(new TCPSocket()),
		m_respond(new SelfupRespondWork(m_sock)),
		m_thread(),
		m_thread_exc(),
		m_ext(new SelfupConExt())
	{
		m_sock->Connect(addr);
		m_thread.reset(new std::thread(&SelfupWork::threadFunc, this));
	}

	void threadFunc()
	{
		try {
			threadFunc2();
		}
		catch (std::exception &) {
			m_thread_exc = std::current_exception();
		}
	}

	void threadFunc2()
	{
		NetworkPacket packet_req_latest(SELFUP_CMD_REQUEST_LATEST_SELFUPDATE_BLOB, networkpacket_cmd_tag_t());

		m_respond->respondOneshot(std::move(packet_req_latest));

		NetworkPacket packet_res_latest = m_respond->waitFrame();
		uint8_t id_res_latest = 0;
		packet_res_latest >> id_res_latest;
		if (id_res_latest != SELFUP_CMD_RESPONSE_LATEST_SELFUPDATE_BLOB)
			throw ProtocolExc("id_res_latest");
	}

	void join()
	{
		if (m_thread_exc)
			std::rethrow_exception(m_thread_exc);
	}

private:
	std::shared_ptr<TCPSocket>     m_sock;
	std::unique_ptr<SelfupRespond> m_respond;
	std::unique_ptr<std::thread> m_thread;
	std::exception_ptr           m_thread_exc;
	std::unique_ptr<SelfupConExt> m_ext;
};

void selfup_start_crank(Address addr)
{
	std::unique_ptr<SelfupWork> work(new SelfupWork(addr));
	work->join();
}

int main(int argc, char **argv)
{
	return EXIT_SUCCESS;
}
