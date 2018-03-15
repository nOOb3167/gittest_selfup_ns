#include <selfup/ns_git_shims.h>

namespace ns_git
{

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
		if (ret != Z_OK && ret != Z_STREAM_END) {
			if (inflateEnd(&strm) != Z_OK)
				throw std::runtime_error("inflate inflateend");
			throw std::runtime_error("inflate inflate");
		}

		size_t have = CHUNK - strm.avail_out;
		result.append(out, have);
	} while (ret != Z_STREAM_END);

	if (inflateEnd(&strm) != Z_OK)
		throw std::runtime_error("inflate inflateend");

	return result;
}

bool oid_equals(const ns_git_oid &a, const ns_git_oid &b)
{
	return ! oid_comparator_t()(a, b) && ! oid_comparator_t()(b, a);
}

ns_git_oid oid_zero()
{
	ns_git_oid ret;
	memset(ret.id, '\0', NS_GIT_OID_RAWSZ);
	return ret;
}

ns_git_oid oid_from_raw(const std::string &raw)
{
	ns_git_oid ret;
	if (raw.size() != NS_GIT_OID_RAWSZ)
		throw std::runtime_error("oid raw size");
	memcpy(ret.id, raw.data(), raw.size());
	return ret;
}

ns_git_oid oid_from_hexstr(const std::string &str)
{
	return oid_from_raw(decode_hex(str, true));
}

ns_git_oid oid_from_ref_file(const std::string &reffilepath)
{
	std::string reffilecontent = ns_filesys::file_read(reffilepath);
	if (reffilecontent.size() != NS_GIT_OID_HEXSZ + 1 || reffilecontent[NS_GIT_OID_HEXSZ] != '\n')
		throw std::runtime_error("ref file format");
	reffilecontent.resize(reffilecontent.size() - 1);
	ns_git_oid commit_head_oid = oid_from_hexstr(reffilecontent);
	return commit_head_oid;
}

ns_git_otype object_string2type(std::string s)
{
	for (size_t i = 0; i < sizeof ns_git_objects_table / sizeof *ns_git_objects_table; i++)
		if (s == ns_git_objects_table[i].s)
			return ns_git_objects_table[i].n;
	return NS_GIT_OBJ_BAD;
}

std::string commit_create_buffer(
	ns_git_oid tree, ns_git_oid parent,
	const std::string &name, const std::string &email, const std::string &message)
{
	/* see functions commit_tree_extended in git */

	std::string buf;

	buf.reserve(8192);

	buf.append("tree "); buf.append(encode_hex(std::string((char *) tree.id, NS_GIT_OID_RAWSZ), true)); buf.append(1, '\n');
	buf.append("parent "); buf.append(encode_hex(std::string((char *) parent.id, NS_GIT_OID_RAWSZ), true)); buf.append(1, '\n');
	buf.append("author ")   ; buf.append(name); buf.append(" <"); buf.append(email); buf.append("> "); buf.append("0000000000 +0100");
	buf.append("committer "); buf.append(name); buf.append(" <"); buf.append(email); buf.append("> "); buf.append("0000000000 +0100");
	buf.append("\n");
	buf.append(message);

	return buf;
}

std::string memes_objpath(
	const std::string &repopath,
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

unsigned long long memes_parse_mode(const std::string &buf)
{
	/* see function parse_mode in tree.c */
	unsigned long long mode = 0;
	for (size_t i = 0; i < buf.size(); i++) {
		if (buf[i] < '0' || buf[i] > '7')
			throw std::runtime_error("mode format");
		mode = (mode << 3) + (buf[i] - '0');
	}
	return mode;
}

int memes_tree(
	const std::string &inflated,
	size_t inflated_offset,
	size_t in_parse_offset,
	unsigned long long *out_mode,
	std::string *out_filename,
	ns_git_oid *out_sha1)
{
	/* adjust by inflated_offset - this will be undone computing final inout_parse_offset */

	size_t offset = inflated_offset + in_parse_offset;

	/* handle end condition */

	if (offset >= inflated.size())
		return -1;

	/* parse mode string (octal digits followed by space) */

	size_t spc = inflated.find_first_of(' ', offset);

	if (spc == std::string::npos)
		throw std::runtime_error("tree spc");

	unsigned long long mode = memes_parse_mode(inflated.substr(offset, spc - offset));

	if (mode != NS_GIT_FILEMODE_TREE &&
		mode != NS_GIT_FILEMODE_BLOB &&
		mode != NS_GIT_FILEMODE_BLOB_EXECUTABLE)
	{
		throw std::runtime_error("tree mode");
	}

	size_t aftermode = spc + 1;

	/* parse filename (bytearray followed by '\0') */

	size_t nul = inflated.find_first_of('\0', aftermode);

	if (nul == std::string::npos)
		throw std::runtime_error("tree nul");

	std::string filename = inflated.substr(aftermode, nul - aftermode);

	size_t afterfilename = nul + 1;

	/* parse SHA1 */

	ns_git_oid sha1 = oid_from_raw(inflated.substr(afterfilename, NS_GIT_OID_RAWSZ));

	size_t aftersha1 = afterfilename + NS_GIT_OID_RAWSZ;
	size_t aftersha1_parse_offset = aftersha1 - inflated_offset;

	*out_mode = mode;
	*out_filename = std::move(filename);
	*out_sha1 = sha1;

	return aftersha1_parse_offset;
}

void memes_get_object_header(
	const std::string &data,
	ns_git_otype *out_type, size_t *out_data_offset, size_t *out_data_size)
{
	/* see function get_object_header in odb_loose.c */
	/* also this comment from git source LUL: (sha1_file.c::parse_sha1_header_extended)
	*   """We used to just use "sscanf()", but that's actually way
	*   too permissive for what we want to check. So do an anal
	*   object header parse by hand."""
	*/

	ns_git_otype type = NS_GIT_OBJ_BAD;
	unsigned long long num = 0;

	/* parse type string */

	size_t spc = data.find_first_of(' ', 0);

	if (spc == std::string::npos)
		throw std::runtime_error("hdr spc");

	/* see also git_object_typeisloose (as used by odb_loose.c) */
	if ((type = object_string2type(data.substr(0, spc))) == NS_GIT_OBJ_BAD)
		throw std::runtime_error("hdr type");

	spc++;

	/* parse size string */

	size_t afternum = std::string::npos;

	if ((afternum = data.find_first_not_of("0123456789", spc)) == std::string::npos)
		throw std::runtime_error("hdr num");

	std::string strnum = data.substr(spc, afternum - spc);

	for (size_t i = 0; i < strnum.size(); i++)
		num = num * 10 + (strnum[i] - '0');

	/* null header terminator */

	if (data.at(afternum) != '\0')
		throw std::runtime_error("hdr null");

	size_t afterhdr = afternum + 1;

	/* sanity checks */

	if (num > SIZE_MAX)
		throw std::runtime_error("hdr num");

	if (afterhdr + num > data.size())
		throw std::runtime_error("hdr data");

	if (out_type)
		*out_type = type;
	if (out_data_offset)
		*out_data_offset = afterhdr;
	if (out_data_size)
		*out_data_size = (size_t)num;
}

ns_git_oid memes_commit_tree(
	const std::string &buf)
{
	/* see function parse_commit_buffer in git */

	const int tree_entry_len = NS_GIT_OID_HEXSZ + 5;

	if (tree_entry_len + 1 >= buf.size() || !! buf.substr(0, 5).compare("tree ") || buf[tree_entry_len] != '\n')
		throw std::runtime_error("commit format");

	ns_git_oid oid = oid_from_hexstr(buf.substr(5, NS_GIT_OID_HEXSZ));

	return oid;
}

ns_git_oid latest_commit_tree_oid(
	const std::string &repopath,
	const std::string &refname)
{
	/* https://github.com/git/git/blob/f06d47e7e0d9db709ee204ed13a8a7486149f494/refs.c#L36-100 */
	/* also libgit2 refs.c git_reference__normalize_name */
	// FIXME:
	//if (!!(r = git_reference_normalize_name(RefNameNormalBuf, sizeof RefNameNormalBuf, RefNameBuf, GIT_REF_FORMAT_NORMAL)))
	//	GS_GOTO_CLEAN();

	std::string reffilepath = ns_filesys::path_append_abs_rel(repopath, refname);

	ns_git_oid commit_head_oid = oid_from_ref_file(reffilepath);

	std::string commit_head_path = memes_objpath(repopath, commit_head_oid);

	std::string content = ns_filesys::file_read(commit_head_path);

	std::string inflated = inflatebuf(content);

	ns_git_otype inflated_type = NS_GIT_OBJ_BAD;
	size_t inflated_offset = 0;
	size_t inflated_size = 0;
	memes_get_object_header(inflated, &inflated_type, &inflated_offset, &inflated_size);

	if (inflated_type != NS_GIT_OBJ_COMMIT)
		throw std::runtime_error("inflated type");

	ns_git_oid tree_head_oid = memes_commit_tree(inflated.substr(inflated_offset, inflated_size));

	return tree_head_oid;
}

ns_git_oid latest_selfupdate_blob_oid(
	const std::string &repopath,
	const std::string &refname,
	const std::string &blob_filename)
{
	ns_git_oid tree_oid = latest_commit_tree_oid(repopath, refname);
	NsGitObject tree_obj = read_object(repopath, tree_oid, false);

	size_t             off  = 0;
	unsigned long long mode = 0;
	std::string        filename;
	ns_git_oid         objoid = {};
	while ((off = memes_tree(tree_obj.m_inflated, tree_obj.m_inflated_offset, off, &mode, &filename, &objoid)) != -1)
		if (filename == blob_filename)
			return objoid;

	throw std::runtime_error("selfupdate tree missing entry blob_filename");
}

NsGitObject read_object_memory_ex(const std::string &deflated)
{
	/* returns a scuffed NsGitObject - zero oid */

	std::string inflated = inflatebuf(deflated);

	ns_git_otype inflated_type = NS_GIT_OBJ_BAD;
	size_t inflated_offset = 0;
	size_t inflated_size = 0;
	memes_get_object_header(inflated, &inflated_type, &inflated_offset, &inflated_size);

	ns_git_oid oid_zero = {};
	NsGitObject nsgitobj(oid_zero, inflated_type, std::move(inflated), inflated_offset, inflated_size, nsgitobject_normal_tag_t());
	return nsgitobj;
}

NsGitObject read_object(
	const std::string &repopath,
	ns_git_oid oid,
	bool also_fill_out_deflated)
{
	std::string objpath = memes_objpath(repopath, oid);

	std::string deflated = ns_filesys::file_read(objpath);

	std::string inflated = inflatebuf(deflated);

	ns_git_otype inflated_type = NS_GIT_OBJ_BAD;
	size_t inflated_offset = 0;
	size_t inflated_size = 0;
	memes_get_object_header(inflated, &inflated_type, &inflated_offset, &inflated_size);

	if (also_fill_out_deflated) {
		NsGitObject nsgitobj(oid, inflated_type, std::move(inflated), inflated_offset, inflated_size, std::move(deflated), nsgitobject_deflated_tag_t());
		return nsgitobj;
	}
	else {
		NsGitObject nsgitobj(oid, inflated_type, std::move(inflated), inflated_offset, inflated_size, nsgitobject_normal_tag_t());
		return nsgitobj;
	}
}

void treelist_visit(const std::string &repopath, treemap_t *treemap, treeset_t *markset, NsGitObject tree)
{
	/* = if n is not marked (i.e. has not been visited yet) then = */
	if (markset->find(tree.m_oid) == markset->end()) {
		/* = mark n = */
		markset->insert(tree.m_oid);
		/* = for each node m with an edge from n to m do = */
		size_t             off    = 0;
		unsigned long long mode   = 0;
		std::string        filename;
		ns_git_oid         objoid = {};
		while ((off = memes_tree(tree.m_inflated, tree.m_inflated_offset, off, &mode, &filename, &objoid)) != -1) {
			if (mode != NS_GIT_FILEMODE_TREE)
				continue;
			NsGitObject subtree = read_object(repopath, objoid, 1);
			/* = visit(m) = */
			treelist_visit(repopath, treemap, markset, std::move(subtree));
		}
		/* = add n to head of L = */
		if (! treemap->insert(std::make_pair(tree.m_oid, std::move(tree))).second)
			throw std::runtime_error("treemap exist");
	}
}

treemap_t treelist_recursive(
	const std::string &repopath,
	ns_git_oid tree_oid)
{
	treemap_t treemap;
	treeset_t markset;

	NsGitObject tree = read_object(repopath, tree_oid, true);

	if (tree.m_type != NS_GIT_OBJ_TREE)
		throw std::runtime_error("tree type");

	treelist_visit(repopath, &treemap, &markset, std::move(tree));

	return treemap;
}

}
