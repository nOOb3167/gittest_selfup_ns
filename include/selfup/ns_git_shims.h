#ifndef _NS_GIT_SHIMS_H_
#define _NS_GIT_SHIMS_H_

#include <cassert>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <utility>

#include <zlib.h>

#include <selfup/ns_filesys.h>
#include <selfup/ns_helpers.h>  // decode_hex, encode_hex

#define NS_GIT_OID_RAWSZ 20
#define NS_GIT_OID_HEXSZ (2 * NS_GIT_OID_RAWSZ)

namespace ns_git
{

/* keep enum value compatibility with libgit2 for interop */
typedef enum {
	NS_GIT_OBJ_BAD = -1,
	NS_GIT_OBJ_COMMIT = 1,
	NS_GIT_OBJ_TREE = 2,
	NS_GIT_OBJ_BLOB = 3,
} ns_git_otype;

typedef enum {
	NS_GIT_FILEMODE_TREE            = 0040000,
	NS_GIT_FILEMODE_BLOB            = 0100644,
	NS_GIT_FILEMODE_BLOB_EXECUTABLE = 0100755,
} ns_git_filemode_t;

static struct { ns_git_otype n; const char *s; } ns_git_objects_table[] = {
	{ NS_GIT_OBJ_COMMIT, "commit" },
	{ NS_GIT_OBJ_TREE, "tree" },
	{ NS_GIT_OBJ_BLOB, "blob" },
};

struct ns_git_oid
{
	unsigned char id[NS_GIT_OID_RAWSZ];
};
typedef struct ns_git_oid ns_git_oid;

struct nsgitobject_deflated_tag_t {};
struct nsgitobject_normal_tag_t {};

class NsGitObject
{
public:
	NsGitObject(ns_git_oid oid, ns_git_otype type, std::string inflated, size_t inflated_offset, size_t inflated_size, std::string deflated, nsgitobject_deflated_tag_t) :
		m_oid(oid),
		m_type(type),
		m_inflated(std::move(inflated)),
		m_inflated_offset(std::move(inflated_offset)),
		m_inflated_size(inflated_size),
		m_deflated(std::move(deflated))
	{}

	NsGitObject(ns_git_oid oid, ns_git_otype type, std::string inflated, size_t inflated_offset, size_t inflated_size, nsgitobject_normal_tag_t) :
		m_oid(oid),
		m_type(type),
		m_inflated(std::move(inflated)),
		m_inflated_offset(std::move(inflated_offset)),
		m_inflated_size(inflated_size),
		m_deflated(std::string())
	{}

public:
	ns_git_oid m_oid;
	ns_git_otype m_type;
	std::string m_inflated;
	size_t m_inflated_offset;
	size_t m_inflated_size;
	std::string m_deflated;
};

struct oid_comparator_t {
	bool operator()(const ns_git_oid &a, const ns_git_oid &b) const {
		for (size_t i = 0; i < NS_GIT_OID_RAWSZ; i++)
			if (a.id[i] != b.id[i])
				return a.id[i] - b.id[i] < 0;
		return false;
	}
};

typedef ::std::map<ns_git_oid, NsGitObject, oid_comparator_t> treemap_t;
typedef ::std::set<ns_git_oid, oid_comparator_t> treeset_t;

std::string inflatebuf(const std::string &buf);

bool oid_equals(const ns_git_oid &a, const ns_git_oid &b);
ns_git_oid oid_zero();
ns_git_oid oid_from_raw(const std::string &raw);
ns_git_oid oid_from_hexstr(const std::string &str);
ns_git_oid oid_from_ref_file(const std::string &reffilepath);

ns_git_otype object_string2type(std::string s);
std::string commit_create_buffer(
	ns_git_oid tree, ns_git_oid parent,
	const std::string &name, const std::string &email, const std::string &message);
std::string memes_objpath(
	const std::string &repopath,
	ns_git_oid oid);
unsigned long long memes_parse_mode(const std::string &buf);
int memes_tree(
	const std::string &inflated,
	size_t inflated_offset,
	size_t in_parse_offset,
	unsigned long long *out_mode,
	std::string *out_filename,
	ns_git_oid *out_sha1);
void memes_get_object_header(
	const std::string &data,
	ns_git_otype *out_type, size_t *out_data_offset, size_t *out_data_size);
ns_git_oid memes_commit_tree(
	const std::string &buf);

ns_git_oid latest_commit_tree_oid(
	const std::string &repopath,
	const std::string &refname);
ns_git_oid latest_selfupdate_blob_oid(
	const std::string &repopath,
	const std::string &refname,
	const std::string &blob_filename);

NsGitObject read_object_memory_ex(const std::string &deflated);
NsGitObject read_object(
	const std::string &repopath,
	ns_git_oid oid,
	bool also_fill_out_deflated);

void treelist_visit(const std::string &repopath, treemap_t *treemap, treeset_t *markset, NsGitObject tree);
treemap_t treelist_recursive(
	const std::string &repopath,
	ns_git_oid tree_oid);
}

#endif /* _NS_GIT_SHIMS_H_ */
