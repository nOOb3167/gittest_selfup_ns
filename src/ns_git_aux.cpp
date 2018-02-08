#include <selfup/ns_git_aux.h>

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

git_blob * selfup_git_blob_lookup(git_repository * repository, git_oid * oid)
{
	git_blob *p = NULL;
	if (!! git_blob_lookup(&p, repository, oid))
		throw std::runtime_error("blob lookup");
	return p;
}

git_commit * selfup_git_commit_lookup(git_repository * repository, git_oid * oid)
{
	// FIXME: not sure if GIT_ENOTFOUND return counts as official API for git_commit_lookup
	//        but may be useful as optional extra failure information ?
	git_commit *p = NULL;
	if (!! git_commit_lookup(&p, repository, oid))
		throw std::runtime_error("commit lookup");
	return p;
}

git_tree * selfup_git_tree_lookup(git_repository * repository, git_oid * oid)
{
	git_tree *p = NULL;
	if (!! git_tree_lookup(&p, repository, oid))
		throw std::runtime_error("tree lookup");
	return p;
}

git_tree * selfup_git_commit_tree(git_commit * commit)
{
	git_tree *p = NULL;
	if (!! git_commit_tree(&p, commit))
		throw std::runtime_error("commit tree");
	return p;
}

git_repository * selfup_git_repository_new()
{
	/* https://github.com/libgit2/libgit2/blob/master/include/git2/sys/repository.h */
	git_repository *p = NULL;
	if (!! git_repository_new(&p))
		throw std::runtime_error("repository new");
	return p;
}

git_repository * selfup_git_repository_open(std::string path)
{
	git_repository *p = NULL;
	if (!! git_repository_open(&p, path.c_str()))
		throw std::runtime_error("repository new");
	return p;
}

git_repository * selfup_git_memory_repository_new()
{
	int r = 0;

	unique_ptr_gitrepository repository_memory(selfup_git_repository_new(), deleteGitrepository);
	unique_ptr_gitodb repository_odb(selfup_git_repository_odb(repository_memory.get()), deleteGitodb);

	/* NOTE: backend is owned by odb, and odb is owned by repository.
	backend thus destroyed indirectly with the repository. */
	git_odb_backend *backend_memory = NULL;
	/* https://github.com/libgit2/libgit2/blob/master/include/git2/sys/mempack.h */
	if (!!(r = git_mempack_new(&backend_memory)))
		throw std::runtime_error("mempack");
	if (!!(r = git_odb_add_backend(repository_odb.get(), backend_memory, 999)))
		throw std::runtime_error("backend");

	return repository_memory.release();
}

git_odb * selfup_git_repository_odb(git_repository * repository)
{
	git_odb *p = NULL;
	if (!! git_repository_odb(&p, repository))
		throw std::runtime_error("repository odb");
	return p;
}

git_signature * selfup_git_signature_new_dummy()
{
	git_signature *sig = NULL;
	if (!! git_signature_new(&sig, "DummyName", "DummyEMail", 0, 0))
		throw std::runtime_error("signature");
	return sig;
}

git_reference * selfup_git_reference_create_and_force_set(git_repository * repo, const std::string & refname, git_oid commit_oid)
{
	git_reference *ref = NULL;
	if (!! git_reference_create(&ref, repo, refname.c_str(), &commit_oid, true, "DummyLogMessage"))
		throw std::runtime_error("reference");
	return ref;
}
