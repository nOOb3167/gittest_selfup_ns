#include <cassert>
#include <cstring>
#include <exception>
#include <memory>
#include <stdexcept>

#include <git2.h>

#include <selfup/ns_git_aux.h>

RefKill::RefKill(git_repository * repo, const std::string & refname) :
	m_repo(repo),
	m_refname(refname)
{}

RefKill::~RefKill()
{
	// CXX11 std::uncaught_exception() true but std::current_exception() null during stack unwinding (object destructor)
	//	 in a 'throw exc' with no matching handler, std::terminate / std::unexpected(n3242@15.4 / 9) interpose
	//	 into the stack unwinding mechanism(n3242@15.3 / 9).
	//	 further, std::unexpected causes handler be considered inactive(n3242@15.3 / 7).
	//	 with no active handler there is no such thing as 'currently handled exception' (n3242@15.3 / 8).
	//	 std::current_exception() refers to the 'currently handled exception' - of which there is none(n3242@18.8.5 / 7).
	//
	//	 std::uncaught_exception() at least is able to detect exceptionness(n3242@18.8.4 / 1).
	//
	// RefKill relies on stack unwinding therefore do not allow a throw with no matching handler
	//   guard main() with a try catch block suppressing the exceptions (log or set an error flag)
	//   see NS_TOPLEVEL_CATCH

	if (std::uncaught_exception()) {
		try {
			unique_ptr_gitcommit dummy_commit(selfup_git_commit_dummy_ensure(m_repo));
			unique_ptr_gitreference ref(selfup_git_reference_create_and_force_set(m_repo, m_refname.c_str(), git_commit_id(dummy_commit.get())));
		}
		catch (const std::exception &e) {
			/* suppress */
		}
	}
}

void deleteGitrepository(git_repository * p)
{
	if (p)
		git_repository_free(p);
}

void deleteGitblob(git_blob * p)
{
	if (p)
		git_blob_free(p);
}

void deleteGitcommit(git_commit * p)
{
	if (p)
		git_commit_free(p);
}

void deleteGittree(git_tree * p)
{
	if (p)
		git_tree_free(p);
}

void deleteGittreebuilder(git_treebuilder * p)
{
	if (p)
		git_treebuilder_free(p);
}

void deleteGitodb(git_odb * p)
{
	if (p)
		git_odb_free(p);
}

void deleteGitsignature(git_signature * p)
{
	if (p)
		git_signature_free(p);
}

void deleteGitreference(git_reference * p)
{
	if (p)
		git_reference_free(p);
}

git_oid selfup_git_oid_from(const char *s, size_t l)
{
	git_oid oid = {};
	if (l < GIT_OID_RAWSZ)
		throw std::runtime_error("oid from");
	memcpy(oid.id, s, GIT_OID_RAWSZ);
	return oid;
}

git_oid selfup_git_blob_from(git_repository * repo, const char *s, size_t l)
{
	git_oid blob_oid = {};
	if (!! git_blob_create_frombuffer(&blob_oid, repo, s, l))
		throw std::runtime_error("blob create frombuffer");
	return blob_oid;
}

unique_ptr_gitblob selfup_git_blob_lookup(git_repository * repository, const git_oid * oid)
{
	git_blob *p = NULL;
	if (!! git_blob_lookup(&p, repository, oid))
		throw std::runtime_error("blob lookup");
	return unique_ptr_gitblob(p, deleteGitblob);
}

unique_ptr_gitcommit selfup_git_commit_lookup(git_repository * repository, const git_oid * oid)
{
	// FIXME: not sure if GIT_ENOTFOUND return counts as official API for git_commit_lookup
	//        but may be useful as optional extra failure information ?
	git_commit *p = NULL;
	if (!! git_commit_lookup(&p, repository, oid))
		throw std::runtime_error("commit lookup");
	return unique_ptr_gitcommit(p, deleteGitcommit);
}

unique_ptr_gittree selfup_git_tree_lookup(git_repository * repository, const git_oid * oid)
{
	git_tree *p = NULL;
	if (!! git_tree_lookup(&p, repository, oid))
		throw std::runtime_error("tree lookup");
	return unique_ptr_gittree(p, deleteGittree);
}

unique_ptr_gittree selfup_git_commit_tree(git_commit * commit)
{
	git_tree *p = NULL;
	if (!! git_commit_tree(&p, commit))
		throw std::runtime_error("commit tree");
	return unique_ptr_gittree(p, deleteGittree);
}

unique_ptr_gitcommit selfup_git_commit_dummy_ensure(git_repository *repo)
{
	git_oid blob_oid = {};
	git_oid tree_oid = {};
	git_oid commit_oid = {};
	if (!! git_blob_create_frombuffer(&blob_oid, repo, "dummyblob", 9))
		throw std::runtime_error("blob create frombuffer");
	unique_ptr_gittreebuilder treebld(selfup_git_treebuilder_new(repo));
	if (!! git_treebuilder_insert(NULL, treebld.get(), "dummyfile", &blob_oid, GIT_FILEMODE_BLOB))
		throw std::runtime_error("treebuilder insert");
	if (!! git_treebuilder_write(&tree_oid, treebld.get()))
		throw std::runtime_error("treebuilder write");
	unique_ptr_gittree tree(selfup_git_tree_lookup(repo, &tree_oid));
	unique_ptr_gitsignature sig(selfup_git_signature_new_dummy());
	if (!! git_commit_create(&commit_oid, repo, NULL, sig.get(), sig.get(), "UTF-8", "Dummy", tree.get(), 0, NULL))
		throw std::runtime_error("commit create");
	unique_ptr_gitcommit commit(selfup_git_commit_lookup(repo, &commit_oid));
	return commit;
}

unique_ptr_gitcommit selfup_git_commit_write_from_tree(git_repository *repo, git_oid tree_oid)
{
	unique_ptr_gitodb odb(selfup_git_repository_odb(repo));
	unique_ptr_gittree tree(selfup_git_tree_lookup(repo, &tree_oid));
	unique_ptr_gitsignature sig(selfup_git_signature_new_dummy());

	git_buf buf = {};
	git_oid commit_oid_pre = {};
	git_oid commit_oid = {};

	if (!! git_commit_create_buffer(&buf, repo, sig.get(), sig.get(), "UTF-8", "Dummy", tree.get(), 0, NULL))
		throw std::runtime_error("git commit create buffer");

	if (!! git_odb_hash(&commit_oid_pre, buf.ptr, buf.size, GIT_OBJ_COMMIT))
		throw std::runtime_error("git odb hash");

	if (git_odb_exists(odb.get(), &commit_oid_pre))
		return selfup_git_commit_lookup(repo, &commit_oid_pre);

	if (!! git_odb_write(&commit_oid, odb.get(), buf.ptr, buf.size, GIT_OBJ_COMMIT))
		throw std::runtime_error("git odb write");

	assert(git_oid_cmp(&commit_oid_pre, &commit_oid) == 0);

	return selfup_git_commit_lookup(repo, &commit_oid);
}

unique_ptr_gitrepository selfup_git_repository_ensure(const std::string &repopath, const std::string &sanity_check_lump)
{
	if (repopath.substr(repopath.size() - sanity_check_lump.size()) != sanity_check_lump)
		throw std::runtime_error("ensure repository sanity check");

	git_repository *repo = NULL;
	git_repository_init_options init_options = GIT_REPOSITORY_INIT_OPTIONS_INIT;
	assert(init_options.version == 1 && GIT_REPOSITORY_INIT_OPTIONS_VERSION == 1);
	/* MKPATH for whole path creation (MKDIR only the last component) */
	/* BARE could be used (ex no dotgit dir) */
	init_options.flags = GIT_REPOSITORY_INIT_NO_REINIT | GIT_REPOSITORY_INIT_MKDIR;
	init_options.mode = GIT_REPOSITORY_INIT_SHARED_UMASK;
	init_options.workdir_path = NULL;
	init_options.description = NULL;
	init_options.template_path = NULL;
	init_options.initial_head = NULL;
	init_options.origin_url = NULL;

	int err = git_repository_init_ext(&repo, repopath.c_str(), &init_options);
	if (!!err && err == GIT_EEXISTS) {
		assert(!repo);
		return unique_ptr_gitrepository(selfup_git_repository_open(repopath.c_str()));
	}
	if (!!err)
		throw std::runtime_error("ensure repository init");

	return unique_ptr_gitrepository(repo, deleteGitrepository);
}

unique_ptr_gitrepository selfup_git_repository_open(std::string path)
{
	git_repository *p = NULL;
	if (!! git_repository_open(&p, path.c_str()))
		throw std::runtime_error("repository new");
	return unique_ptr_gitrepository(p, deleteGitrepository);
}

unique_ptr_gitodb selfup_git_repository_odb(git_repository * repository)
{
	git_odb *p = NULL;
	if (!! git_repository_odb(&p, repository))
		throw std::runtime_error("repository odb");
	return unique_ptr_gitodb(p, deleteGitodb);
}

bool selfup_git_exists(git_repository * repository, git_oid * oid)
{
	unique_ptr_gitodb odb(selfup_git_repository_odb(repository));
	return !! git_odb_exists(odb.get(), oid);
}

unique_ptr_gittreebuilder selfup_git_treebuilder_new(git_repository * repository)
{
	git_treebuilder *p = NULL;
	if (!! git_treebuilder_new(&p, repository, NULL))
		throw std::runtime_error("treebuilder new");
	return unique_ptr_gittreebuilder(p, deleteGittreebuilder);
}


unique_ptr_gitsignature selfup_git_signature_new_dummy()
{
	git_signature *sig = NULL;
	if (!! git_signature_new(&sig, "DummyName", "DummyEMail", 0, 0))
		throw std::runtime_error("signature");
	return unique_ptr_gitsignature(sig, deleteGitsignature);
}

unique_ptr_gitreference selfup_git_reference_create_and_force_set(git_repository * repo, const std::string & refname, const git_oid * commit_oid)
{
	git_reference *ref = NULL;
	if (!! git_reference_create(&ref, repo, refname.c_str(), commit_oid, true, "DummyLogMessage"))
		throw std::runtime_error("reference");
	return unique_ptr_gitreference(ref, deleteGitreference);
}

git_oid selfup_git_reference_name_to_id(git_repository *repo, const std::string &refname)
{
	git_oid oid = {};
	if (!! git_reference_name_to_id(&oid, repo, refname.c_str()))
		throw std::runtime_error("refname id");
	return oid;
}

git_oid selfup_git_reference_get_tree_or_default_zero(git_repository *repo, const std::string &refname)
{
	try {
		git_oid oid_head(selfup_git_reference_name_to_id(repo, refname));
		unique_ptr_gitcommit commit_head(selfup_git_commit_lookup(repo, &oid_head));
		unique_ptr_gittree   commit_tree(selfup_git_commit_tree(commit_head.get()));
		return *git_tree_id(commit_tree.get());
	}
	catch (const std::exception &e) {
		git_oid oid_zero = {};
		return oid_zero;
	}
}

std::string selfup_git_checkout_memory(const std::string &repopath, const std::string &refname, const std::string &tree_entry_blob_filename)
{
	unique_ptr_gitrepository repo(selfup_git_repository_open(repopath));

	{
		RefKill rki(repo.get(), refname);

		git_oid commit_head_oid(selfup_git_reference_name_to_id(repo.get(), refname));
		unique_ptr_gitcommit commit_head(selfup_git_commit_lookup(repo.get(), &commit_head_oid));
		unique_ptr_gittree   commit_tree(selfup_git_commit_tree(commit_head.get()));

		const git_tree_entry *entry = git_tree_entry_byname(commit_tree.get(), tree_entry_blob_filename.c_str());
		unique_ptr_gitblob blob(selfup_git_blob_lookup(repo.get(), git_tree_entry_id(entry)));
		std::string update_buffer((char *)git_blob_rawcontent(blob.get()), (size_t)git_blob_rawsize(blob.get()));
		return update_buffer;
	}
	throw std::runtime_error("checkout memory");
}

bool selfup_git_check_isoutdated(const std::string &repopath, const std::string &refname, const std::string &cur_exe_filename, const std::string &tree_entry_blob_filename)
{
	unique_ptr_gitrepository repo(selfup_git_repository_open(repopath));

	git_oid oid_cur_exe = {};
	if (!! git_odb_hashfile(&oid_cur_exe, cur_exe_filename.c_str(), GIT_OBJ_BLOB))
		throw std::runtime_error("hash");

	git_oid oid_commit_tree = selfup_git_reference_get_tree_or_default_zero(repo.get(), refname);
	unique_ptr_gittree commit_tree(selfup_git_tree_lookup(repo.get(), &oid_commit_tree));
	const git_tree_entry *entry = git_tree_entry_byname(commit_tree.get(), tree_entry_blob_filename.c_str());
	unique_ptr_gitblob blob(selfup_git_blob_lookup(repo.get(), git_tree_entry_id(entry)));

	return git_oid_cmp(&oid_cur_exe, git_blob_id(blob.get())) != 0;
}

void selfup_git_checkout(const std::string &repopath, const std::string &refname, const std::string &checkoutpath)
{
	unique_ptr_gitrepository repo(selfup_git_repository_open(repopath));

	{
		RefKill rki(repo.get(), refname);

		git_oid commit_head_oid(selfup_git_reference_name_to_id(repo.get(), refname));
		unique_ptr_gitcommit commit_head(selfup_git_commit_lookup(repo.get(), &commit_head_oid));
		unique_ptr_gittree   commit_tree(selfup_git_commit_tree(commit_head.get()));

		/* https://libgit2.github.com/docs/guides/101-samples/#objects_casting */
		// FIXME: reevaluate checkout_strategy flag GIT_CHECKOUT_REMOVE_UNTRACKED

		git_checkout_options opts = GIT_CHECKOUT_OPTIONS_INIT;
		opts.checkout_strategy = GIT_CHECKOUT_FORCE;
		opts.disable_filters = 1;
		opts.target_directory = checkoutpath.c_str();

		if (!! git_checkout_tree(repo.get(), (git_object *) commit_tree.get(), &opts))
			throw std::runtime_error("checkout tree");
	}
}
