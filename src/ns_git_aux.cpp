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
			unique_ptr_gitreference ref(selfup_git_reference_create_and_force_set(m_repo, m_refname.c_str(), *git_commit_id(dummy_commit.get())));
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

unique_ptr_gitreference selfup_git_reference_create_and_force_set(git_repository * repo, const std::string & refname, git_oid commit_oid)
{
	git_reference *ref = NULL;
	if (!! git_reference_create(&ref, repo, refname.c_str(), &commit_oid, true, "DummyLogMessage"))
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
