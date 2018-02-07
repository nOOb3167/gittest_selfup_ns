#ifdef _WIN32

#include <cstdio>
#include <string>

void ns_sd_notify(int unset_environment, const std::string &state)
{
	/* empty */
}

void ns_sd_journal_send_fd(int fd, const char *msg, size_t msg_len)
{
	fprintf(stdout, "%.*s\n", (int) msg_len, msg);
}

void ns_sd_journal_send_oneshot(const char *msg, size_t msg_len)
{
	fprintf(stdout, "%.*s\n", (int) msg_len, msg);
}

#else /* _WIN32 */

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <selfup/ns_systemd.h>

// https://www.freedesktop.org/software/systemd/man/sd_notify.html
// see for possible state values
//   gs_sd_notify(0, "READY=1");

// https://github.com/systemd/systemd/blob/master/src/libsystemd/sd-daemon/sd-daemon.c
//   sd_pid_notify_with_fds

// https://davejingtian.org/2015/02/17/retrieve-pid-from-the-packet-in-unix-domain-socket-a-complete-use-case-for-recvmsgsendmsg/
//   """Don't construct an explicit credentials structure. (It
//      is not necessary to do so, if we just want the receiver to
//      receive our real credentials.)"""

// printing env vars
//  extern char**environ;
//  for (char **env = environ; *env; env++)
//    printf("e %s\n", *env);


// https://coreos.com/blog/eliminating-journald-delays-part-1.html
// https://github.com/systemd/systemd/blob/master/src/journal/cat.c
// https://www.freedesktop.org/software/systemd/man/sd_journal_stream_fd.html
// https://github.com/systemd/systemd/blob/master/src/journal/journal-send.c
//   systemd-cat
//   """I'll be using the systemd-cat utility, which logs stdin via the "stream" journald source,
//      analogous to how a systemd-managed service's output may be logged."""
//   """sd_journal_stream_fd() may be used to create a log stream file descriptor.
//      Log messages written to this file descriptor as simple newline-separated text strings are written to the journal. """
// wrt sd_journal_stream_fd also see the journal_fd function (AF_UNIX of SOCK_DGRAM with increased sndbuf)

#define NS_SYSTEMD_SNDBUF_SIZE (8 * 1024 * 1024)  // matching journal-send.c

typedef ::std::unique_ptr<int, void(*)(int *p)> ns_systemd_fd;

static void close_helper(int *p)
{
	if (p && *p != -1)
		close(*p);
}

static ns_systemd_fd journal_fd()
{
	ns_systemd_fd fd(new int(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)), close_helper);

	if (*fd < 0)
		throw std::runtime_error("journal_fd socket");

	int val = 0;
	socklen_t len = sizeof val;

	int r = getsockopt(*fd, SOL_SOCKET, SO_SNDBUF, &val, &len);
	if (r >= 0 && len == sizeof val && val >= NS_SYSTEMD_SNDBUF_SIZE)
		return fd;

	val = NS_SYSTEMD_SNDBUF_SIZE;
	if (setsockopt(*fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof val) < 0)
		throw std::runtime_error("journal_fd setsockopt");

	return fd;
}

static uint64_t ns_htole64(uint64_t h)
{
	uint64_t u = 0;
	uint8_t *p = (uint8_t *) &u;
	p[0] = h >>  0 & 0xFF;
	p[1] = h >>  8 & 0xFF;
	p[2] = h >> 16 & 0xFF;
	p[3] = h >> 24 & 0xFF;
	p[4] = h >> 32 & 0xFF;
	p[5] = h >> 40 & 0xFF;
	p[6] = h >> 48 & 0xFF;
	p[7] = h >> 56 & 0xFF;
	return u;
}

void ns_sd_notify(int unset_environment, const std::string &state)
{
	char *envptr = getenv("NOTIFY_SOCKET");

	if (! envptr)
		return;

	std::string en(envptr);

	if (en.size() < 2 || ! (en[0] == '@' || en[0] == '/'))
		throw std::runtime_error("NOTIFY_SOCKET format");

	/* abstract socket address indicated by starting @ in env var
	   abstract socket address indicated by starting 0 in sun_path
	   see unix(7) */
	if (en[0] == '@')
		en[0] = '\0';

	/* fill sockaddr_un */

	struct sockaddr_un sockaddr = {};

	if (en.size() + 1 > sizeof sockaddr.sun_path)
		throw std::runtime_error("NOTIFY_SOCKET oversize");

	memmove(sockaddr.sun_path, en.c_str(), en.size() + 1);
	sockaddr.sun_family = AF_UNIX;

	/* send message */

	ns_systemd_fd fd(new int(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)), close_helper);

	if (*fd < 0)
		throw std::runtime_error("NOTIFY_SOCKET socket");

	if (sendto(*fd, state.data(), state.size(), 0, (struct sockaddr *) &sockaddr, sizeof sockaddr) != state.size())
		throw std::runtime_error("NOTIFY_SOCKET sendto");

	/* match behavior of libsystemd */

	if (unset_environment)
		unsetenv("NOTIFY_SOCKET");
}

static void ns_sd_journal_send_fd_iov(int fd, struct iovec *iov, int n)
{
	const char path[] = "/run/systemd/journal/socket";
	struct sockaddr_un sa = {};
	memmove(sa.sun_path, path, sizeof path - 1);
	sa.sun_family = AF_UNIX;
	struct msghdr mh = {};
	mh.msg_name = (struct sockaddr *) &sa;
	mh.msg_namelen = offsetof(struct sockaddr_un, sun_path) + strnlen(sa.sun_path, sizeof (sa.sun_path));
	mh.msg_iov = iov;
	mh.msg_iovlen = n;

	ssize_t k = sendmsg(fd, &mh, MSG_NOSIGNAL);
	/* enoent aka journal not available */
	if (k < 0 && errno == ENOENT)
		return;
	if (k < 0 && (errno == EMSGSIZE || errno == ENOBUFS))
		throw std::runtime_error("journal_send write size");
	if (k < 0)
		throw std::runtime_error("journal_send write");
}

void ns_sd_journal_send_fd(int fd, const char *msg, size_t msg_len)
{
	struct iovec iov[5 * 1] = {};
	size_t j = 0;
	iov[j]  .iov_base = (void *) "MESSAGE";
	iov[j++].iov_len  = sizeof "MESSAGE" - 1;
	char *nl = (char *) memchr(msg, '\n', msg_len);
	uint64_t le = ns_htole64(msg_len);
	if (nl) {
		iov[j]  .iov_base = (void *) "\n";
		iov[j++].iov_len  = 1;
		iov[j]  .iov_base = &le;
		iov[j++].iov_len  = sizeof (uint64_t);
	}
	else {
		iov[j]  .iov_base = (void *) "=";
		iov[j++].iov_len  = 1;
	}
	iov[j]  .iov_base = (void *) msg;
	iov[j++].iov_len  = msg_len;
	iov[j]  .iov_base = (void *) "\n";
	iov[j++].iov_len  = 1;

	assert(j <= sizeof iov / sizeof *iov);

	ns_sd_journal_send_fd_iov(fd, iov, j);
}

void ns_sd_journal_send_oneshot(const char *msg, size_t msg_len)
{
	ns_systemd_fd fd(journal_fd());
	ns_sd_journal_send_fd(*fd, msg, msg_len);
}

#endif /* _WIN32 */
