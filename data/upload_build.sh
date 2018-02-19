#!/usr/bin/bash -x

set -e

CURRENTDIR=$(dirname $(readlink -e "$0"))
[ -d "$CURRENTDIR" ] && cd "$CURRENTDIR" || exit 1;

CFG_CMD_CMAKE=cmake

CFG_CMAKE_BUILD_CONFIG=Release

CFG_CMAKE_SOURCE_DIR=
CFG_CMAKE_BUILD_DIR=

[ -f "$CURRENTDIR/upload_config.inc" ] && . "$CURRENTDIR/upload_config.inc"

[ -d "$CFG_CMAKE_SOURCE_DIR" ] && [ -n "$CFG_CMAKE_BUILD_DIR" ] || exit 1

CMAKE_SOURCE_DIR_ABS=$(readlink -e "$CFG_CMAKE_SOURCE_DIR")
CMAKE_BUILD_DIR_ABS=$(readlink -e "$CFG_CMAKE_BUILD_DIR")

if which cygpath ; then
	CMAKE_SOURCE_DIR_ABS=$(cygpath -m "$CMAKE_SOURCE_DIR_ABS")
	CMAKE_BUILD_DIR_ABS=$(cygpath -m "$CMAKE_BUILD_DIR_ABS")
fi

"$CFG_CMD_CMAKE" --build "$CMAKE_BUILD_DIR_ABS" --config "$CFG_CMAKE_BUILD_CONFIG"

echo done
