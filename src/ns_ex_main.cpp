#include <stdexcept>
#include <string>

#include <selfup/ns_ex.h>
#include <selfup/ns_filesys.h>

int main(int argc, char **argv)
{
	if (argc >= 2 && std::string(argv[1]) == SELFUP_ARG_VERSUB)
		return SELFUP_ARG_VERSUB_SUCCESS_CODE;

	tcpsocket_startup_helper();

	if (git_libgit2_init() < 0)
		throw std::runtime_error("libgit2 init");

	std::string cur_exe_filename = ns_filesys::current_executable_filename();
	std::string repopath = ns_filesys::current_executable_relative_filename("clnt_repo/.git");
	std::string refname_selfup = "refs/heads/selfup";
	std::string refname_mainup = "refs/heads/mainup";
	std::string refname_stage2 = "refs/heads/stage2";
	std::string chkoutpath_mainup = ns_filesys::current_executable_relative_filename("clnt_chkout");
	std::string chkoutpath_stage2 = ns_filesys::current_executable_relative_filename("stage2_chkout");

	const char *node = "10.55.1.6";
	const char *service = "6757";

	SelfupUpdater::updateOneshot(node, service, repopath, refname_selfup);

	if (SelfupFileOps::selfCheckIsOutdated(repopath, refname_selfup, cur_exe_filename)) {
		SelfupFileOps::selfOverwriteAndReExec(repopath, refname_selfup, cur_exe_filename);
		return EXIT_SUCCESS;
	}

	SelfupUpdater::updateOneshot(node, service, repopath, refname_mainup);
	SelfupUpdater::updateOneshot(node, service, repopath, refname_stage2);

	SelfupFileOps::checkout(repopath, refname_mainup, chkoutpath_mainup);
	SelfupFileOps::checkout(repopath, refname_stage2, chkoutpath_stage2);

	return EXIT_SUCCESS;
}
