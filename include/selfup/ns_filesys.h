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

std::string build_modified_filename(
	std::string base_filename,
	std::string expected_suffix,
	std::string expected_extension,
	std::string replacement_suffix,
	std::string replacement_extension);

std::string path_append_abs_rel(
	std::string absolute,
	std::string relative);

std::string file_read(
	std::string filename);
void file_write_frombuffer(
	std::string filename,
	const char *buf, size_t buf_len);

std::string current_executable_relative_filename(std::string relative);
std::string current_executable_filename();
std::string current_executable_directory();

void rename_file_file(
	std::string src_filename,
	std::string dst_filename);

void directory_create_unless_exist(std::string dirname);

}

#endif /* _NS_FILESYS_H_ */
