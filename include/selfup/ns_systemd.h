#ifndef _NS_SYSTEMD_H_
#define _NS_SYSTEMD_H_

#include <string>

void ns_sd_notify(int unset_environment, const std::string &state);

#endif /* _NS_SYSTEMD_H_ */
