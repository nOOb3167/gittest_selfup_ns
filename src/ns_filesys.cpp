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

std::string current_executable_filename()
{
	std::string fname(1024, '\0');

	DWORD LenFileName = GetModuleFileName(NULL, (char *) fname.data(), fname.size());
	if (!(LenFileName != 0 && LenFileName < fname.size()))
		throw FilesysExc("current executable filename");
	fname.resize(LenFileName);

	return fname;
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
