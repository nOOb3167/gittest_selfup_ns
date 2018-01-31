#include <fstream>
#include <sstream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <shlwapi.h> // PathAppend etc

/* headers for the posix-style msvc CRT functions (ex _open, _fstat, _close) */
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#  error implement
#endif

#include <selfup/ns_filesys.h>
#include <selfup/ns_helpers.h>

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

std::string current_executable_filename()
{
	std::string fname(1024, '\0');

	DWORD LenFileName = GetModuleFileName(NULL, (char *) fname.data(), fname.size());
	if (!(LenFileName != 0 && LenFileName < fname.size()))
		throw FilesysExc("current executable filename");
	fname.resize(LenFileName);

	return fname;
}

std::string current_executable_directory()
{

	std::string cur_exe_filename = current_executable_filename();
	std::string dir = path_directory(cur_exe_filename);
	return dir;
}

void rename_file_file(
	std::string src_filename,
	std::string dst_filename)
{
	int r = 0;

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

}
