#ifdef _WIN32

#include <string>

void ns_sd_notify(int unset_environment, const std::string &state)
{
	/* empty */
}

#else /* _WIN32 */

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

static void close_helper(int *p)
{
	if (p && *p != -1)
		close(*p);
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

	std::unique_ptr<int, void(*)(int *p)> fd(new int(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)), close_helper);

	if (*fd < 0)
		throw std::runtime_error("NOTIFY_SOCKET socket");

	if (sendto(*fd, state.data(), state.size(), 0, (struct sockaddr *) &sockaddr, sizeof sockaddr) != state.size())
		throw std::runtime_error("NOTIFY_SOCKET sendto");

	/* match behavior of libsystemd */

	if (unset_environment)
		unsetenv("NOTIFY_SOCKET");
}

#endif /* _WIN32 */
