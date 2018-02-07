#ifndef _NS_SYSTEMD_H_
#define _NS_SYSTEMD_H_

#include <string>

struct nsiovec
{
	void  *iov_base;
	size_t iov_len;
};

typedef ::std::unique_ptr<int, void(*)(int *p)> ns_systemd_fd;

void ns_sd_notify(int unset_environment, const std::string &state);

ns_systemd_fd ns_sd_journal_create_fd();
void ns_sd_journal_send_fd_iov(int fd, struct nsiovec *nsiov, size_t n);
void ns_sd_journal_send_fd(int fd, const char *msg, size_t msg_len);
void ns_sd_journal_send_oneshot_iov(struct nsiovec *iov, size_t n);
void ns_sd_journal_send_oneshot(const char *msg, size_t msg_len);

#endif /* _NS_SYSTEMD_H_ */
