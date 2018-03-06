#!/usr/bin/bash

set -e

CURRENTDIR=$(dirname $(readlink -e "$0"))
[ -d "$CURRENTDIR" ] && cd "$CURRENTDIR" || exit 1;

CFG_CMD_SSH="ssh -T -e none"
CFG_CMD_SCP_RECURSIVE="scp -r"
CFG_CMD_BASH="bash -e -s -x"

CFG_ARCHIVE_SELFUP=
CFG_ARCHIVE_MAINUP=

CFG_REMOTE_ARCHIVE_SELFUP=
CFG_REMOTE_ARCHIVE_MAINUP=

CFG_REMOTE_HOST=
CFG_REMOTE_REPO=

[ -f "$CURRENTDIR/upload_config.inc" ] && . "$CURRENTDIR/upload_config.inc"

[ -f "$CFG_ARCHIVE_SELFUP" ] && [ -f "$CFG_ARCHIVE_MAINUP" ] || exit 1
[ -n "$CFG_REMOTE_ARCHIVE_SELFUP" ] && [ -n "$CFG_REMOTE_ARCHIVE_MAINUP" ] || exit 1
[ -n "$CFG_REMOTE_HOST" ] && [ -n "$CFG_REMOTE_REPO" ] || exit 1

$CFG_CMD_SCP_RECURSIVE "$CFG_ARCHIVE_SELFUP" "$CFG_REMOTE_HOST:$CFG_REMOTE_ARCHIVE_SELFUP_WEB" >/dev/null 2>&1
$CFG_CMD_SCP_RECURSIVE "$CFG_ARCHIVE_SELFUP" "$CFG_REMOTE_HOST:$CFG_REMOTE_ARCHIVE_SELFUP" >/dev/null 2>&1
$CFG_CMD_SCP_RECURSIVE "$CFG_ARCHIVE_MAINUP" "$CFG_REMOTE_HOST:$CFG_REMOTE_ARCHIVE_MAINUP" >/dev/null 2>&1

$CFG_CMD_SSH "$CFG_REMOTE_HOST" "$CFG_CMD_BASH" <<EOF
	chmod 744 "$CFG_REMOTE_ARCHIVE_SELFUP_WEB"

	cd "$CFG_REMOTE_REPO"
	
	# selfup
	
	git checkout selfup >/dev/null 2>&1  # checkout something otherwise --orphan can choke
	
	git branch -D tmp_selfup || true
	git checkout --orphan tmp_selfup || true
	git rm -rf . >/dev/null 2>&1 || true
	
	unzip "$CFG_REMOTE_ARCHIVE_SELFUP" >/dev/null 2>&1
	
	git add --all
	git commit -m"dummy" >/dev/null 2>&1
	git update-ref refs/heads/selfup tmp_selfup
	
	# mainup

	git checkout selfup >/dev/null 2>&1  # checkout something otherwise --orphan can choke
	
	git branch -D tmp_mainup || true
	git checkout --orphan tmp_mainup || true
	git rm -rf . >/dev/null 2>&1 || true
	
	unzip "$CFG_REMOTE_ARCHIVE_MAINUP" >/dev/null 2>&1
	
	git add --all
	git commit -m "dummy" >/dev/null 2>&1
	git update-ref refs/heads/mainup tmp_mainup
EOF

echo done
