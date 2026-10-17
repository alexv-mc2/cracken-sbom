#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test stand-in for unblob. It answers --version and "unpacks" any image into the
# synthetic fixtures/rootfs tree, laid out the way unblob names its results. The
# real unblob and binwalk are not provisioned by the test suite because they need
# several helper tools; see README "Firmware images" for the manual end-to-end run.
set -eu
if [ "${1:-}" = "--version" ]; then echo "fake-unblob 0.0.1"; exit 0; fi
if [ "${1:-}" = "--help" ]; then exit 0; fi
dir=
image=
while [ "$#" -gt 0 ]; do
  case "$1" in --extract-dir) dir=$2; shift ;; esac
  image=$1
  shift
done
[ -n "$dir" ] || exit 2
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# A tree named in "<image>.source-tree" replaces the default fixture, so a test
# can push any prepared tree (for example one with symlinks) through the CLI.
source="$here/../fixtures/rootfs"
if [ -f "$image.source-tree" ]; then source=$(cat "$image.source-tree"); fi
base="$dir/image.bin_extract"
mkdir -p "$base/0-512.unknown"
cp -RP "$source" "$base/512-4096.squashfs_extract"
