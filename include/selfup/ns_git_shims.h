#ifndef _NS_GIT_SHIMS_H_
#define _NS_GIT_SHIMS_H_

#include <cassert>
#include <string>

#include <zlib.h>

#include <selfup/ns_filesys.h>

#define NS_GIT_OID_RAWSZ 20
#define NS_GIT_OID_HEXSZ (2 * NS_GIT_OID_RAWSZ)

namespace ns_git
{

struct ns_git_oid
{
	unsigned char id[NS_GIT_OID_RAWSZ];
};
typedef struct ns_git_oid ns_git_oid;

std::string inflatebuf(const std::string &buf)
{
	/* https://www.zlib.net/zpipe.c
	     official example
	*/

    std::string result;

	int ret = Z_OK;

	const size_t CHUNK = 16384;
	char out[CHUNK] = {};

	z_stream strm = {};

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;

    if (inflateInit(&strm) != Z_OK)
        throw std::runtime_error("inflate init");

	strm.avail_in = buf.size();
	strm.next_in = (Bytef *) buf.data();

	result.reserve(2 * CHUNK);  // arbitrary preallocation

	do {
		strm.avail_out = CHUNK;
		strm.next_out = (Bytef *) out;

		ret = inflate(&strm, Z_NO_FLUSH);
		if (ret != Z_OK && ret != Z_STREAM_END)
			throw std::runtime_error("inflate inflate");

		size_t have = CHUNK - strm.avail_out;
		result.append(out, have);
	} while (ret != Z_STREAM_END);

	if (inflateEnd(&strm) != Z_OK)
		throw std::runtime_error("inflate inflateend");

	return result;
}

char decode_hex_char(const char hex_char)
{
	/* '0' to '9' guaranteed contiguous */

	if (hex_char >= '0' && hex_char <= '9')
		return hex_char - '0';

	/* the letters are contiguous in ASCII but no standard */

	switch (hex_char) {
	case 'a':
	case 'A':
		return 10;
	case 'b':
	case 'B':
		return 11;
	case 'c':
	case 'C':
		return 12;
	case 'd':
	case 'D':
		return 13;
	case 'e':
	case 'E':
		return 14;
	case 'f':
	case 'F':
		return 15;
	default:
		throw std::runtime_error("decode hex char");
	}

	return 0;
}

std::string decode_hex(const std::string &hex, bool web_programmer_designed_swapped_hex_mental_illness)
{
	std::string bin(hex.size() / 2, '\0');

	/* one full byte is a hex pair of characters - better be divisible by two */

	if (hex.size() % 2 != 0)
		throw std::runtime_error("hex divisibility");

	/* decode */

	for (size_t i = 0; i < hex.size(); i += 2) {
		size_t first = decode_hex_char(hex[i]) & 0xF;
		size_t second = decode_hex_char(hex[i + 1]) & 0xF;
		if (web_programmer_designed_swapped_hex_mental_illness)
			bin[i / 2] = first << 4 | second << 0;
		else
			bin[i / 2] = first << 0 | second << 4;
	}

	return bin;
}

std::string encode_hex(const std::string &bin, bool web_programmer_designed_swapped_hex_mental_illness)
{
	std::string hex;
	const char chars[] = "0123456789ABCDEF";
	for (size_t i = 0; i < bin.size(); i++) {
		char first = chars[(bin[i] >> 0) & 0xF];
		char second = chars[(bin[i] >> 4) & 0xF];
		if (web_programmer_designed_swapped_hex_mental_illness) {
			hex.append(1, second);
			hex.append(1, first);
		}
		else {
			hex.append(1, first);
			hex.append(1, second);
		}
	}
}

ns_git_oid oid_from_hexstr(std::string str)
{
	ns_git_oid ret;
	std::string raw = decode_hex(str, true);
	if (raw.size() != NS_GIT_OID_HEXSZ)
		throw std::runtime_error("oid str size");
	memcpy(ret.id, raw.data(), raw.size());
	return ret;
}

std::string memes_objpath(
	std::string repopath,
	ns_git_oid oid)
{
	/* see function object_file_name in odb_loose.c (libgit2) */

	std::string objects("objects/");
	std::string objectspath = ns_filesys::path_append_abs_rel(repopath, objects);

	std::string sha1 = encode_hex(std::string((char *) oid.id, NS_GIT_OID_RAWSZ), true);
	std::string sha1path = sha1.substr(0, 2) + "/" + sha1.substr(2, std::string::npos);

	std::string fullpath = ns_filesys::path_append_abs_rel(objectspath, sha1path);

	return fullpath;
}

ns_git_oid latest_commit_tree_oid(
	std::string repopath,
	std::string refname)
{
	/* https://github.com/git/git/blob/f06d47e7e0d9db709ee204ed13a8a7486149f494/refs.c#L36-100 */
	/* also libgit2 refs.c git_reference__normalize_name */
	// FIXME:
	//if (!!(r = git_reference_normalize_name(RefNameNormalBuf, sizeof RefNameNormalBuf, RefNameBuf, GIT_REF_FORMAT_NORMAL)))
	//	GS_GOTO_CLEAN();

	std::string reffilepath = ns_filesys::path_append_abs_rel(repopath, refname);

	std::string reffilecontent = ns_filesys::file_read(reffilepath);

	ns_git_oid commit_head_oid = oid_from_hexstr(reffilecontent);

	std::string commit_head_path = memes_objpath(repopath, commit_head_oid);

	std::string content = ns_filesys::file_read(commit_head_path);

	//if (!!(r = git_memes_inflate(CommitContentBuf, LenCommitContent, &CommitInflated, &CommitType, &CommitOffset, &CommitSize)))
	//	GS_GOTO_CLEAN();

	//if (CommitType != GIT_OBJ_COMMIT)
	//	GS_ERR_CLEAN(1);

	//if (!!(r = git_memes_commit(CommitInflated.ptr + CommitOffset, CommitSize, &TreeHeadOid)))
	//	GS_GOTO_CLEAN();

	//if (oCommitHeadOid)
	//	git_oid_cpy(oCommitHeadOid, &CommitHeadOid);
	//if (oTreeHeadOid)
	//	git_oid_cpy(oTreeHeadOid, &TreeHeadOid);
}

}

#endif /* _NS_GIT_SHIMS_H_ */
