#ifndef _NS_FILESYS_H_
#define _NS_FILESYS_H_

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

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

std::string file_read(
	std::string filename);
void file_write_frombuffer(
	std::string filename,
	const char *buf, size_t buf_len);

std::string current_executable_relative_filename(std::string relative);
std::string current_executable_directory();

std::string current_executable_filename();

std::string path_directory(std::string path);
std::string path_append_abs_rel(
	std::string absolute,
	std::string relative);

void rename_file_file(
	std::string src_filename,
	std::string dst_filename);

void directory_create_unless_exist(std::string dirname);

void process_start(
	const std::string &filename,
	const std::vector<std::string> &args,
	long long *retcode_blocking_opt);

}

#endif /* _NS_FILESYS_H_ */
