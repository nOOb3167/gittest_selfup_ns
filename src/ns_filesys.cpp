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

namespace ns_filesys
{

std::string current_executable_filename()
{
	std::string fname(1024, '\0');
	DWORD LenFileName = 0;

	DWORD LenFileName = GetModuleFileName(NULL, (char *) fname.data(), fname.size());
	if (!(LenFileName != 0 && LenFileName < fname.size()))
		throw FilesysExc("current executable filename");
	fname.resize(LenFileName);

	return fname;
}

}
