#ifndef _NS_EX_H_
#define _NS_EX_H_

#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include <git2.h>

#include <selfup/TCPSocket.h>

#define SELFUP_ARG_CHILD "--xchild"
#define SELFUP_ARG_VERSUB "--xversub"
#define SELFUP_ARG_VERSUB_SUCCESS_CODE 42

class SelfupUpdater
{
public:
	SelfupUpdater(const char *node, const char *service, const std::string &repopath, const std::string &refname);

	static bool updateOneshot(const char *node, const char *service, const std::string &repopath, const std::string &refname);

protected:
	bool doUpdate();

	void requestAndRecvAndWriteObjs(git_repository *repo, std::deque<git_oid> *missing_obj_oids);
	std::vector<git_oid> recvAndWriteObjsUntilDone(git_repository *repo, size_t gui_missing_initial_size, size_t *gui_received_count);

private:
	std::string m_repopath;
	std::string m_refname;
	TCPSocket m_socket;
};

class SelfupFileOps
{
public:
	static bool selfCheckIsOutdated(std::string repopath, std::string refname, std::string cur_exe_filename);
	static void selfOverwriteAndReExec(std::string repopath, std::string refname, std::string cur_exe_filename);
	static void checkout(const std::string &repopath, const std::string &refname, const std::string &checkoutpath);

private:
	static void dryrun(std::string exe_filename);
	static void reexec(std::string exe_filename);
};

#endif /* _NS_EX_H_ */
