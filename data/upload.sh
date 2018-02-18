#!/usr/bin/bash

set -e

CURRENTDIR=$(dirname $(readlink -e "$0"))
[ -d "$CURRENTDIR" ] && cd "$CURRENTDIR" || exit 1;

CFG_EXEPATH=../bin/selfup_ns.exe
CFG_DIRBASE=
CFG_DIRNAME=
CFG_CMD_SSH="ssh -T -e none"
CFG_CMD_SCP=scp
CFG_CMD_SCP_RECURSIVE="scp -r"
CFG_CMD_BASH="bash -e -s"

CFG_REMOTE_HOST=
CFG_REMOTE_REPO=
CFG_REMOTE_REPO_WORKTREE_SELFUP=
CFG_REMOTE_WKTREE_DIRBASE=

[ -f "$CURRENTDIR/upload_config.inc" ] && . "$CURRENTDIR/upload_config.inc"

[ -n "$CFG_DIRBASE" ] && [ -n "$CFG_DIRNAME" ] || exit 1

[ -n "$CFG_REMOTE_HOST" ] && [ -n "$CFG_REMOTE_REPO" ] || exit 1
[ -n "$CFG_REMOTE_REPO_WORKTREE_SELFUP" ] && [ -n "$CFG_REMOTE_WKTREE_DIRBASE" ] || exit 1

MAINUP_DIR="$CFG_DIRBASE/$CFG_DIRNAME"
WKTREE_DIR="$CFG_REMOTE_WKTREE_DIRBASE/$CFG_DIRNAME"

##
# selfup
##

$CFG_CMD_SSH "$CFG_REMOTE_HOST" "$CFG_CMD_BASH" <<EOF
	cd "$CFG_REMOTE_REPO"
	git worktree add -f "$CFG_REMOTE_REPO_WORKTREE_SELFUP" selfup >/dev/null 2>&1 || true
	cd "$CFG_REMOTE_REPO_WORKTREE_SELFUP"
	git rev-parse --is-inside-work-tree >/dev/null 2>&1
	
	git checkout --detach HEAD >/dev/null 2>&1 || true
	git branch -D tmp_selfup >/dev/null 2>&1 || true
	git checkout --orphan tmp_selfup >/dev/null 2>&1 || true
	git rm -rf . >/dev/null 2>&1 || true
EOF

[ -f "$CFG_EXEPATH" ] || exit 1
$CFG_CMD_SCP "$CFG_EXEPATH" "$CFG_REMOTE_HOST:$CFG_REMOTE_REPO_WORKTREE_SELFUP"

$CFG_CMD_SSH "$CFG_REMOTE_HOST" "$CFG_CMD_BASH" <<EOF
	cd "$CFG_REMOTE_REPO_WORKTREE_SELFUP"
	git rev-parse --is-inside-work-tree >/dev/null 2>&1
	
	git add --all
	git commit -m"dummy"
	git update-ref refs/heads/selfup tmp_selfup
EOF

##
# mainup
##

$CFG_CMD_SSH "$CFG_REMOTE_HOST" "$CFG_CMD_BASH" <<EOF
	cd "$CFG_REMOTE_REPO"
	git worktree add -f "$WKTREE_DIR" master >/dev/null 2>&1 || true
	cd "$WKTREE_DIR"
	git rev-parse --is-inside-work-tree >/dev/null 2>&1
	
	git checkout --detach HEAD >/dev/null 2>&1 || true
	git branch -D tmp_mainup >/dev/null 2>&1 || true
	git checkout --orphan tmp_mainup >/dev/null 2>&1 || true
	git rm -rf . >/dev/null 2>&1 || true
EOF

$CFG_CMD_SCP_RECURSIVE "$MAINUP_DIR" "$CFG_REMOTE_HOST:$CFG_REMOTE_WKTREE_DIRBASE" >/dev/null 2>&1

$CFG_CMD_SSH "$CFG_REMOTE_HOST" "$CFG_CMD_BASH" <<EOF
	cd "$WKTREE_DIR"
	git rev-parse --is-inside-work-tree >/dev/null 2>&1
	
	git add --all
	git commit -m"dummy"
	git update-ref refs/heads/master tmp_mainup
EOF

echo done
