#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test stand-in for unblob. It answers --version and "unpacks" any image into the
# synthetic fixtures/rootfs tree, laid out the way unblob names its results. The
# real unblob and binwalk are not provisioned by the test suite because they need
# several helper tools; see README "Firmware images" for the manual end-to-end run.
set -eu
if [ "${1:-}" = "--version" ]; then echo "fake-unblob 0.0.1"; exit 0; fi
dir=
while [ "$#" -gt 0 ]; do
  case "$1" in --extract-dir) dir=$2; shift ;; esac
  shift
done
[ -n "$dir" ] || exit 2
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
base="$dir/image.bin_extract"
mkdir -p "$base/0-512.unknown"
cp -R "$here/../fixtures/rootfs" "$base/512-4096.squashfs_extract"
