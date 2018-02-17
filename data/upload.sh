#!/usr/bin/bash

set -e

CURRENTDIR=$(dirname $(readlink -e "$0"))
[ -d "$CURRENTDIR" ] && cd "$CURRENTDIR" || exit 1;

#CFG_EXELUMP=../bin/selfup_ns.exe
CFG_EXEPATH=../../tmp2/selfup_ns_release/Release/selfup_ns.exe
CFG_CMD_SSH="ssh -T -e none"
CFG_CMD_SCP=scp
CFG_CMD_BASH="bash -e -s"

CFG_REMOTE_HOST=progame@10.55.1.6
CFG_REMOTE_REPO=/home/progame/gittest/gittest_selfup_ns/serv_repo
CFG_REMOTE_REPO_WORKTREE_SELFUP=/home/progame/gittest/gittest_selfup_ns/www
CFG_REMOTE_PATH=/home/progame/gittest/gittest_selfup_ns/tmptmp

[ -f "$CFG_EXEPATH" ] || exit 1;

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

$CFG_CMD_SCP "$CFG_EXEPATH" "$CFG_REMOTE_HOST:$CFG_REMOTE_REPO_WORKTREE_SELFUP"

$CFG_CMD_SSH "$CFG_REMOTE_HOST" "$CFG_CMD_BASH" <<EOF
	cd "$CFG_REMOTE_REPO_WORKTREE_SELFUP"
	git rev-parse --is-inside-work-tree >/dev/null 2>&1
	git add --all
	git commit -m"dummy"
	git update-ref selfup tmp_selfup
EOF

echo done
