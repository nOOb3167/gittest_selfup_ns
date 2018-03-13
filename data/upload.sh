#!/usr/bin/bash

set -e

CURRENTDIR=$(dirname $(readlink -e "$0"))
[ -d "$CURRENTDIR" ] && cd "$CURRENTDIR" || exit 1;

CFG_CMD_SSH="ssh -T -e none"
CFG_CMD_SCP="scp"
CFG_CMD_BASH="bash -e -s -x"

CFG_ARCHIVE_SELFUP=
CFG_ARCHIVE_MAINUP=

CFG_REMOTE_ARCHIVE_SELFUP=
CFG_REMOTE_ARCHIVE_MAINUP=

CFG_REMOTE_HOST=
CFG_REMOTE_REPO=

[ -f "$CURRENTDIR/upload_config.inc" ] && . "$CURRENTDIR/upload_config.inc"

[ -f "$CFG_ARCHIVE_SELFUP" ] && [ -f "$CFG_ARCHIVE_MAINUP" ] && [ -f "$CFG_ARCHIVE_STAGE2" ] || exit 1
[ -n "$CFG_REMOTE_ARCHIVE_DIR" ] || exit 1
[ -n "$CFG_REMOTE_HOST" ] && [ -n "$CFG_REMOTE_REPO" ] || exit 1

REMOTE_ARCHIVE_SELFUP="$CFG_REMOTE_ARCHIVE_DIR/$(basename "$CFG_ARCHIVE_SELFUP")"
REMOTE_ARCHIVE_MAINUP="$CFG_REMOTE_ARCHIVE_DIR/$(basename "$CFG_ARCHIVE_MAINUP")"
REMOTE_ARCHIVE_STAGE2="$CFG_REMOTE_ARCHIVE_DIR/$(basename "$CFG_ARCHIVE_STAGE2")"

[ -n "$REMOTE_ARCHIVE_SELFUP" ] && [ -n "$REMOTE_ARCHIVE_MAINUP" ] && [ -n "$REMOTE_ARCHIVE_STAGE2" ] || exit 1

$CFG_CMD_SCP "$CFG_ARCHIVE_SELFUP" "$CFG_ARCHIVE_MAINUP" "$CFG_ARCHIVE_STAGE2" "$CFG_REMOTE_HOST:$CFG_REMOTE_ARCHIVE_DIR" >/dev/null 2>&1

$CFG_CMD_SSH "$CFG_REMOTE_HOST" "$CFG_CMD_BASH" <<EOF
	dummy_chkout ()
	{
		# checkout something otherwise --orphan can choke
		git branch z_dummy >/dev/null 2>&1 || true
		git checkout z_dummy >/dev/null 2>&1
	}
	
	prepare_branch ()
	{
		local NAME=\$1
		[ -n "\$NAME" ] || exit 1
		git branch -D "tmp_\$NAME" || true
		git checkout --orphan "tmp_\$NAME" || true
		git rm -rf . >/dev/null 2>&1 || true	
	}
	
	commit_branch ()
	{
		local NAME=\$1
		[ -n "\$NAME" ] || exit 1
		git add --all
		git commit -m"dummy" >/dev/null 2>&1
		git update-ref "refs/heads/\$NAME" "tmp_\$NAME"
	}

	chmod 744 "$REMOTE_ARCHIVE_SELFUP"
	cp "$REMOTE_ARCHIVE_SELFUP" "$CFG_REMOTE_ARCHIVE_SELFUP_WEB"

	cd "$CFG_REMOTE_REPO"
	
	dummy_chkout
	prepare_branch selfup
	unzip "$REMOTE_ARCHIVE_SELFUP" >/dev/null 2>&1
	commit_branch selfup
	
	dummy_chkout
	prepare_branch mainup
	unzip "$REMOTE_ARCHIVE_MAINUP" >/dev/null 2>&1
	commit_branch mainup
	
	dummy_chkout
	prepare_branch stage2
	unzip "$REMOTE_ARCHIVE_STAGE2" >/dev/null 2>&1
	commit_branch stage2
EOF

echo done
