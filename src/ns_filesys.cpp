#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <shlwapi.h> // PathAppend etc

/* headers for the posix-style msvc CRT functions (ex _open, _fstat, _close) */
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

#include <selfup/ns_filesys.h>
#include <selfup/ns_helpers.h>

#define NS_PROCESS_WAIT_MSEC 10000

namespace ns_filesys
{

std::string build_modified_filename(
	std::string base_filename,
	std::string expected_suffix,
	std::string expected_extension,
	std::string replacement_suffix,
	std::string replacement_extension)
{
	std::stringstream ss;
	std::string out;

	size_t extension_cutoff_offset = GS_MAX(base_filename.size() - expected_extension.size(), 0);
	size_t suffix_check_offset = GS_MAX(base_filename.size() - expected_extension.size() - expected_suffix.size(), 0);

	if (base_filename.substr(extension_cutoff_offset) != expected_extension ||
		base_filename.substr(suffix_check_offset, extension_cutoff_offset - suffix_check_offset) != expected_suffix)
	{
		throw FilesysExc("modified filename check");
	}

	ss << base_filename.substr(0, extension_cutoff_offset) << replacement_suffix << replacement_extension;
	out = ss.str();

	return out;
}

std::string file_read(
	std::string filename)
{
	std::ifstream ff(filename, std::ios::in | std::ios::binary);

	if (! ff.good())
		throw FilesysExc("ifstream open");

	std::stringstream ss;

	ss << ff.rdbuf();

	if (! ff.good() || ! ss.good())
		throw FilesysExc("ifstream/stringstream read");

	ff.close();

	if (! ff.good())
		throw FilesysExc("ifstream close");

	return std::move(ss.str());
}


void file_write_frombuffer(
	std::string filename,
	const char *buf, size_t buf_len)
{
	std::ofstream ff(filename, std::ios::out | std::ios::trunc | std::ios::binary);

	if (! ff.good())
		throw FilesysExc("ofstream open");

	ff.write(buf, buf_len);

	if (! ff.good())
		throw FilesysExc("ofstream write");

	ff.flush();

	if (! ff.good())
		throw FilesysExc("ofstream flush");

	ff.close();

	if (! ff.good())
		throw FilesysExc("ofstream close");
}

std::string current_executable_relative_filename(std::string relative)
{
	std::string cur_exe_dir = current_executable_directory();
	std::string combined = path_append_abs_rel(cur_exe_dir, relative);
	return combined;
}

std::string current_executable_directory()
{

	std::string cur_exe_filename = current_executable_filename();
	std::string dir = path_directory(cur_exe_filename);
	return dir;
}

#ifdef _WIN32

std::string current_executable_filename()
{
	std::string fname(1024, '\0');

	DWORD LenFileName = GetModuleFileName(NULL, (char *) fname.data(), fname.size());
	if (!(LenFileName != 0 && LenFileName < fname.size()))
		throw FilesysExc("current executable filename");
	fname.resize(LenFileName);

	return fname;
}

std::string path_directory(std::string path)
{
	char Drive[_MAX_DRIVE] = {};
	char Dir[_MAX_DIR] = {};
	char FName[_MAX_FNAME] = {};
	char Ext[_MAX_EXT] = {};

	/* http://www.flounder.com/msdn_documentation_errors_and_omissions.htm
	*    see for _splitpath: """no more than this many characters will be written to each buffer""" */
	_splitpath(path.c_str(), Drive, Dir, FName, Ext);

	std::string ret(_MAX_PATH, '\0');

	if (!! _makepath_s((char *) ret.data(), ret.size(), Drive, Dir, NULL, NULL))
		throw FilesysExc("makepath");

	std::string ret2(ret.c_str());

	return ret2;
}

std::string path_append_abs_rel(
	std::string absolute,
	std::string relative)
{
	int r = 0;

	if (relative.find("..") != std::string::npos)
		throw FilesysExc("path doubledots");

	/** maximum length for PathIsRelative and PathAppend **/
	if (absolute.size() > MAX_PATH || relative.size() > MAX_PATH)
		throw FilesysExc("path length");

	if (PathIsRelative(absolute.c_str()))
		throw FilesysExc("path rel");

	if (! PathIsRelative(relative.c_str()))
		throw FilesysExc("path notrel");

	/* prep output buffer with absolute path */

	std::string out(absolute);
	out.append(1, '\0');
	out.resize(GS_MAX(out.size(), MAX_PATH));

	/* append */

	if (! PathAppend((char *) out.data(), relative.c_str()))
		throw FilesysExc("path append");

	std::string out2(out.c_str());

	return out2;
}

void rename_file_file(
	std::string src_filename,
	std::string dst_filename)
{
	BOOL ok = MoveFileEx(src_filename.c_str(), dst_filename.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);

	if (!ok)
		throw FilesysExc("rename");
}

void directory_create_unless_exist(std::string dirname)
{
	if (! CreateDirectory(dirname.c_str(), NULL)) {
		DWORD Error = GetLastError();
		if (Error == ERROR_ALREADY_EXISTS)
			return;
		throw FilesysExc("directory create");
	}
}

void process_start(
	const std::string &filename,
	const std::vector<std::string> &args,
	long long *retcode_blocking_opt)
{
	std::stringstream ss;
	
	ss << "\"" << filename << "\"";

	for (size_t i = 0; i < args.size(); i++)
		ss << " " << "\"" << args[i] << "\"";

	std::string argv = ss.str();
	argv.append(1, '\0');

	PROCESS_INFORMATION pi = {};
	STARTUPINFO si = {};
	si.cb = sizeof si;

	if (! CreateProcess(
		filename.c_str(), (LPSTR) argv.data(),
		NULL, NULL,
		TRUE, 0,
		NULL, NULL,
		&si, &pi))
	{
		throw FilesysExc("process create");
	}

	if (retcode_blocking_opt) {
		try {
			DWORD exitcode = 0;
			if (WAIT_OBJECT_0 != WaitForSingleObject(pi.hProcess, NS_PROCESS_WAIT_MSEC))
				throw FilesysExc("process wait");
			if (! GetExitCodeProcess(pi.hProcess, &exitcode))
				throw FilesysExc("create exit code");;
			*retcode_blocking_opt = exitcode;
		} catch (const std::exception &e) {
			if (pi.hThread && ! CloseHandle(pi.hThread))
				assert(0);
			if (pi.hProcess && ! CloseHandle(pi.hProcess))
				assert(0);
			throw;
		}
	}

	if (pi.hThread && ! CloseHandle(pi.hThread))
		assert(0);
	if (pi.hProcess && ! CloseHandle(pi.hProcess))
		assert(0);
}

#else /* _WIN32 */

static bool gs_nix_path_is_absolute(const std::string &path)
{
	return path.size() > 0 && path[0] == '/';
}

static std::string gs_nix_path_eat_trailing_slashes(const std::string &path)
{
	size_t off = path.size() - 1;
	while (off < path.size() && path[off] == '/')
		off--;
	return path.substr(0, off + 1);
}

static std::string gs_nix_path_eat_trailing_nonslashes(const std::string &path)
{
	size_t off = path.size() - 1;
	while (off < path.size() && path[off] != '/')
		off--;
	return path.substr(0, off + 1);
}

static void gs_nix_path_add_trailing_slash_cond_inplace(std::string *io_path)
{
	if (! (io_path->size() > 0 && (*io_path)[io_path->size() - 1] == '/'))
		io_path->append(1, '/');
}

std::string current_executable_filename()
{
	/* http://man7.org/linux/man-pages/man5/proc.5.html
	*    /proc/[pid]/exe:
	*    If the pathname has been
	*         unlinked, the symbolic link will contain the string
	*         '(deleted)' appended to the original pathname. */
	// FIXME: does move count as unlinking? (probably so)
	//   so if the process has moved itself (during selfupdate)
	//   this call will basically fail (or at least return a weirder name

	const char MAGIC_PROC_PATH_NAME[] = "/proc/self/exe";

	std::string ret(1024, '\0');

	ssize_t count = 0;

	if ((count = readlink(MAGIC_PROC_PATH_NAME, (char *) ret.data(), ret.size())) < 0)
		throw FilesysExc("readlink");

	if (count >= ret.size())
		throw FilesysExc("readlink count");

	ret.resize(count);

	if (! gs_nix_path_is_absolute(ret))
		throw FilesysExc("path not absolute");

	return ret;
}

std::string path_directory(std::string path)
{
	/* async-signal-safe functions: safe */
	int r = 0;

	size_t LenOutputPath = 0;

	const char OnlySlash[] = "/";

	const char *ToOutputPtr = NULL;
	size_t ToOutputLen = 0;

	/* absolute aka starts with a slash */
	if (! gs_nix_path_is_absolute(path))
		throw FilesysExc("path not absolute");

	/* eat trailing slashes */

	path = gs_nix_path_eat_trailing_slashes(path);

	if (path.size() > 0) {
		/* because of ensure absolute we know it starts with a slash.
		*  since eat_trailing_slashes did not eat the whole path,
		*  what remains must be of the form "/XXX(/XXX)*" (regex).
		*  there might be redundant slashes. */
		/* eat an XXX part */
		path = gs_nix_path_eat_trailing_nonslashes(path);
		/* eat an / part */
		path = gs_nix_path_eat_trailing_slashes(path);
		/* two possibilities: we were on the last /XXX part or not.
		*  path is now empty or of the form /XXX */
	}

	if (path.size() == 0) {
		/* handle the 'path is now empty' possibility: output just /, as per dirname(3) */
		return std::string("/");
	}
	else {
		/* handle the 'path is now of the form /XXX' possibility: output verbatim */
		return path;
	}
}

std::string path_append_abs_rel(
	std::string absolute,
	std::string relative)
{
	if (! gs_nix_path_is_absolute(absolute))
		throw FilesysExc("path not absolute");

	if (gs_nix_path_is_absolute(relative))
		throw FilesysExc("path absolute");

	std::string ret;

	ret.reserve(512);
	ret.append(absolute);
	gs_nix_path_add_trailing_slash_cond_inplace(&ret);
	ret.append(relative);

	return ret;
}

void rename_file_file(
	std::string src_filename,
	std::string dst_filename)
{
	/* see renameat2(2) for call with extra flags (eg RENAME_EXCHANGE) */
	if (rename(src_filename.c_str(), dst_filename.c_str()) < 0)
		throw FilesysExc("rename");
}

void directory_create_unless_exist(std::string dirname)
{
	/* 0777 aka default for linux - remember umask applies */
	mode_t mode = S_IRUSR | S_IWUSR | S_IXUSR |
		S_IRGRP | S_IWGRP | S_IXGRP |
		S_IROTH | S_IWOTH | S_IXOTH;

	if (mkdir(dirname.c_str(), mode) < 0) {
		if (errno == EEXIST)
			return;
		throw FilesysExc("mkdir");
	}
}

void process_start(
	const std::string &filename,
	const std::vector<std::string> &args,
	long long *retcode_blocking_opt)
{
	std::vector<const char *> argv;

	argv.push_back(filename.c_str());

	for (size_t i = 0; i < args.size(); i++)
		argv.push_back(args[i].c_str());

	/* argv must be terminated by NULL, see execv(2) */
	argv.push_back(NULL);

	pid_t pidchild = -1;

	if ((pidchild = fork()) == -1)
		throw FilesysExc("fork");
	if (pidchild == 0) {
		/* consider calling _Exit (C99) on failure */
		if (!! execv(filename.c_str(), (char * const *) argv.data()))
			exit(EXIT_FAILURE);
	}
	else {
		if (retcode_blocking_opt) {
			int statuschild = 0;
			pid_t pidwait = -1;
			if ((pidwait = waitpid(pidchild, &statuschild, 0)) == -1)
				throw FilesysExc("waitpid");
			if (! WIFEXITED(statuschild))
				throw FilesysExc("WIFEXITED");
			*retcode_blocking_opt = WEXITSTATUS(statuschild);
		}
	}
}

#endif /* _WIN32 */

}
