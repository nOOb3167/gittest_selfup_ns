#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include <git2.h>

#include <selfup/ns_ex.h>
#include <selfup/ns_filesys.h>
#include <selfup/ns_git_aux.h>
#include <selfup/ns_git_shims.h>
#include <selfup/ns_helpers.h>
#include <selfup/TCPSocket.h>

SelfupUpdater::SelfupUpdater(const char * node, const char * service, const std::string & repopath, const std::string & refname) :
	m_repopath(repopath),
	m_refname(refname),
	m_socket(node, service, tcpsocket_connect_tag_t())
{}

bool SelfupUpdater::updateOneshot(const char * node, const char * service, const std::string & repopath, const std::string & refname)
{
	selfup_git_repository_ensure(repopath, ".git");
	return SelfupUpdater(node, service, repopath, refname).doUpdate();
}

bool SelfupUpdater::doUpdate()
{
	unique_ptr_gitrepository repo(selfup_git_repository_open(m_repopath));

	/* request latest version git_oid */

	NetworkPacket packet_req_latest(SELFUP_CMD_REQUEST_LATEST_COMMIT_TREE, networkpacket_cmd_tag_t());
	packet_req_latest << (uint32_t)m_refname.size();
	packet_req_latest.outSizedStr(m_refname.data(), m_refname.size());
	m_socket.Send(& packet_req_latest);

	NetworkPacket res_latest_pkt = m_socket.Recv();
	res_latest_pkt.readEnsureCmd(SELFUP_CMD_RESPONSE_LATEST_COMMIT_TREE);
	git_oid res_latest_oid = {};
	git_oid_fromraw(&res_latest_oid, (const unsigned char *)res_latest_pkt.inSizedStr(GIT_OID_RAWSZ));

	/* determine local version git_oid */

	git_oid repo_head_tree_oid = selfup_git_reference_get_tree_or_default_zero(repo.get(), m_refname);

	/* matching versions suggest an update is unnecessary */

	if (git_oid_cmp(&repo_head_tree_oid, &res_latest_oid) == 0)
		return false;

	/* request list of trees comprising latest version */

	NetworkPacket req_treelist_pkt(SELFUP_CMD_REQUEST_TREELIST, networkpacket_cmd_tag_t());
	req_treelist_pkt.outSizedStr((char *)res_latest_oid.id, GIT_OID_RAWSZ);
	m_socket.Send(& req_treelist_pkt);

	NetworkPacket res_treelist_pkt = m_socket.Recv();
	res_treelist_pkt.readEnsureCmd(SELFUP_CMD_RESPONSE_TREELIST);
	uint32_t res_treelist_treenum = 0;
	std::vector<git_oid> res_treelist_treevec;
	res_treelist_pkt >> res_treelist_treenum;
	for (size_t i = 0; i < res_treelist_treenum; i++)
		res_treelist_treevec.push_back(selfup_git_oid_from(res_treelist_pkt.inSizedStr(GIT_OID_RAWSZ), GIT_OID_RAWSZ));

	/* determine which trees are missing */

	std::deque<git_oid> missing_tree_oids;
	for (size_t i = 0; i < res_treelist_treevec.size(); i++)
		if (! selfup_git_exists(repo.get(), &res_treelist_treevec[i]))
			missing_tree_oids.push_back(res_treelist_treevec[i]);

	/* request missing trees and write received into the repository */

	requestAndRecvAndWriteObjs(repo.get(), &missing_tree_oids);

	/* determine which blobs are missing - validating trees and their entries in the meantime */

	/* by now all required trees should of been either preexistent or missing but written into the repository.
	validating trees comprises of:
	- confirming existence of trees themselves
	- examining the trees' entries:
	- tree entries for existence
	- blob entries for existence, recording missing blobs */

	std::deque<git_oid> missing_blob_oids;

	for (size_t i = 0; i < res_treelist_treevec.size(); i++) {
		unique_ptr_gitodb odb(selfup_git_repository_odb(repo.get()));
		unique_ptr_gittree tree(selfup_git_tree_lookup(repo.get(), &res_treelist_treevec[i]));
		for (size_t j = 0; j < git_tree_entrycount(tree.get()); j++) {
			const git_tree_entry *entry = git_tree_entry_byindex(tree.get(), j);
			if (git_tree_entry_type(entry) == GIT_OBJ_TREE) {
				if (! git_odb_exists(odb.get(), git_tree_entry_id(entry)))
					throw std::runtime_error("entry tree inexistant");
			}
			else if (git_tree_entry_type(entry) == GIT_OBJ_BLOB) {
				if (! git_odb_exists(odb.get(), git_tree_entry_id(entry)))
					missing_blob_oids.push_back(*git_tree_entry_id(entry));
			}
			else {
				throw std::runtime_error("entry type");
			}
		}
	}

	/* request missing blobs and write received into the repository */

	requestAndRecvAndWriteObjs(repo.get(), &missing_blob_oids);

	/* by now all required blobs should of been either preexistent or missing but written into the repository */

	/* required trees were confirmed present above and required blobs are present within the repository.
	supposedly we have correctly received a full update. */

	unique_ptr_gitcommit new_commit = selfup_git_commit_write_from_tree(repo.get(), res_latest_oid);
	unique_ptr_gitreference new_ref(selfup_git_reference_create_and_force_set(repo.get(), m_refname, git_commit_id(new_commit.get())));

	return true;
}

/* @missing_obj_oids: will be popped as objects are received - empties completely on success */
void SelfupUpdater::requestAndRecvAndWriteObjs(git_repository * repo, std::deque<git_oid>* missing_obj_oids)
{
	size_t gui_missing_initial_size = missing_obj_oids->size();
	size_t gui_received_count = 0;

	size_t missing_obj_request_limit = missing_obj_oids->size();
	do {
		NetworkPacket req_objs(SELFUP_CMD_REQUEST_OBJS3, networkpacket_cmd_tag_t());
		req_objs << (uint32_t)missing_obj_request_limit;
		for (size_t i = 0; i < missing_obj_request_limit; i++)
			req_objs.outSizedStr((char *)(*missing_obj_oids)[i].id, GIT_OID_RAWSZ);
		m_socket.Send(& req_objs);

		std::vector<git_oid> received_obj_oids = recvAndWriteObjsUntilDone(repo, gui_missing_initial_size, &gui_received_count);

		for (size_t i = 0; i < received_obj_oids.size(); i++) {
			if (missing_obj_oids->empty() || git_oid_cmp(&received_obj_oids[i], &missing_obj_oids->front()) != 0)
				throw std::runtime_error("unsolicited obj received and written?");
			missing_obj_oids->pop_front();
		}

		missing_obj_request_limit = GS_MIN(missing_obj_oids->size(), received_obj_oids.size() * 2);
	} while (! missing_obj_oids->empty());
}

std::vector<git_oid> SelfupUpdater::recvAndWriteObjsUntilDone(git_repository * repo, size_t gui_missing_initial_size, size_t * gui_received_count)
{
	std::vector<git_oid> received_blob_oids;
	unique_ptr_gitodb odb(selfup_git_repository_odb(repo));
	while (true) {
		NetworkPacket res_blobs = m_socket.Recv();
		uint8_t res_blobs_cmd = res_blobs.readGetCmd();

		if (res_blobs_cmd == SELFUP_CMD_RESPONSE_OBJS3) {
			uint32_t size = 0;
			res_blobs >> size;

			ns_git::NsGitObject obj(ns_git::read_object_memory_ex(std::string(res_blobs.inSizedStr(size), size)));

			git_oid written_oid = {};
			if (!! git_odb_write(&written_oid, odb.get(), obj.m_inflated.data() + obj.m_inflated_offset, obj.m_inflated_size, (git_otype)obj.m_type))
				throw std::runtime_error("inflate write");
			received_blob_oids.push_back(written_oid);

			(*gui_received_count)++;
		}
		else if (res_blobs_cmd == SELFUP_CMD_RESPONSE_OBJS3_DONE) {
			break;
		}
		else {
			throw std::runtime_error("cmd objs3");
		}
	}
	return received_blob_oids;
}

bool SelfupFileOps::selfCheckIsOutdated(std::string repopath, std::string refname, std::string cur_exe_filename)
{
	return selfup_git_check_isoutdated(repopath, refname, cur_exe_filename, SELFUP_SELFUPDATE_BLOB_ENTRY_FILENAME);
}

void SelfupFileOps::selfOverwriteAndReExec(std::string repopath, std::string refname, std::string cur_exe_filename)
{
	std::string temp_filename = ns_filesys::build_modified_filename(
		cur_exe_filename, "", ".exe", "_helper", ".exe");
	std::string old_filename = ns_filesys::build_modified_filename(
		cur_exe_filename, "", ".exe", "_helper_old", ".exe");

	std::string update_buffer = selfup_git_checkout_memory(repopath, refname, SELFUP_SELFUPDATE_BLOB_ENTRY_FILENAME);

	ns_filesys::file_write_frombuffer(temp_filename, update_buffer.data(), update_buffer.size());

	dryrun(temp_filename);

	ns_filesys::rename_file_file(cur_exe_filename, old_filename);
	ns_filesys::rename_file_file(temp_filename, cur_exe_filename);

	reexec(cur_exe_filename);
}

void SelfupFileOps::checkout(const std::string & repopath, const std::string & refname, const std::string & checkoutpath)
{
	ns_filesys::directory_create_unless_exist(checkoutpath);
	selfup_git_checkout(repopath, refname, checkoutpath);
}

void SelfupFileOps::dryrun(std::string exe_filename)
{
	long long ret;
	ns_filesys::process_start(exe_filename, { SELFUP_ARG_VERSUB }, &ret);
	if (ret != SELFUP_ARG_VERSUB_SUCCESS_CODE)
		throw std::runtime_error("dryrun retcode");
}

void SelfupFileOps::reexec(std::string exe_filename)
{
	ns_filesys::process_start(exe_filename, { SELFUP_ARG_CHILD }, NULL);
}
