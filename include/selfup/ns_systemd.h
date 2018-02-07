#ifndef _NS_SYSTEMD_H_
#define _NS_SYSTEMD_H_

#include <string>

void ns_sd_notify(int unset_environment, const std::string &state);

void ns_sd_journal_send_fd(int fd, const char *msg, size_t msg_len);
void ns_sd_journal_send_oneshot(const char *msg, size_t msg_len);

#endif /* _NS_SYSTEMD_H_ */
