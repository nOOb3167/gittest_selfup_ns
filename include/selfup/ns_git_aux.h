#ifndef _NS_GIT_AUX_
#define _NS_GIT_AUX_

#include <memory>

#include <git2.h>

typedef ::std::unique_ptr<git_repository, void(*)(git_repository *)> unique_ptr_gitrepository;
typedef ::std::unique_ptr<git_blob, void(*)(git_blob *)> unique_ptr_gitblob;
typedef ::std::unique_ptr<git_commit, void(*)(git_commit *)> unique_ptr_gitcommit;
typedef ::std::unique_ptr<git_tree, void(*)(git_tree *)> unique_ptr_gittree;
typedef ::std::unique_ptr<git_treebuilder, void(*)(git_treebuilder *)> unique_ptr_gittreebuilder;
typedef ::std::unique_ptr<git_odb, void(*)(git_odb *)> unique_ptr_gitodb;
typedef ::std::unique_ptr<git_signature, void(*)(git_signature *)> unique_ptr_gitsignature;
typedef ::std::unique_ptr<git_reference, void(*)(git_reference *)> unique_ptr_gitreference;

class RefKill
{
public:
	RefKill(git_repository *repo, const std::string &refname);
	
	RefKill(const RefKill &a)            = default;
	RefKill& operator=(const RefKill &a) = default;
	RefKill(RefKill &&a)                 = default;
	RefKill& operator=(RefKill &&a)      = default;

	~RefKill();

private:
	git_repository *m_repo;
	std::string     m_refname;
};
typedef RefKill ref_kill_t;

void deleteGitrepository(git_repository *p);
void deleteGitblob(git_blob *p);
void deleteGitcommit(git_commit *p);
void deleteGittree(git_tree *p);
void deleteGitodb(git_odb *p);
void deleteGitsignature(git_signature *p);
void deleteGitreference(git_reference *p);

git_blob *   selfup_git_blob_lookup(git_repository *repository, git_oid *oid);
git_commit * selfup_git_commit_lookup(git_repository *repository, git_oid *oid);
git_tree *   selfup_git_tree_lookup(git_repository *repository, git_oid *oid);

git_tree *   selfup_git_commit_tree(git_commit *commit);
unique_ptr_gitcommit selfup_git_commit_dummy_ensure(git_repository *repo);

git_repository * selfup_git_repository_new();
git_repository * selfup_git_repository_open(std::string path);
git_repository * selfup_git_memory_repository_new();

git_odb * selfup_git_repository_odb(git_repository *repository);

bool selfup_git_exists(git_repository * repository, git_oid * oid);

git_treebuilder * selfup_git_treebuilder_new(git_repository * repository);

git_signature * selfup_git_signature_new_dummy();

git_reference * selfup_git_reference_create_and_force_set(git_repository *repo, const std::string &refname, git_oid commit_oid);
git_oid         selfup_git_reference_name_to_id(git_repository *repo, const std::string &refname);


#endif /* _NS_GIT_AUX_ */
