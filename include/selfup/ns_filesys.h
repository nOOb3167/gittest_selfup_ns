#ifndef _NS_FILESYS_H_
#define _NS_FILESYS_H_

#include <cstring>
#include <stdexcept>
#include <string>

class FilesysExc : std::runtime_error
{
public:
	FilesysExc(const char *msg) :
		std::runtime_error(msg)
	{}
};

namespace ns_filesys
{

std::string current_executable_filename();

};

#endif /* _NS_FILESYS_H_ */
