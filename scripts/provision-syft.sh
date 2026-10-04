#!/bin/sh
# Installation only: download and authenticate Syft into an explicit path.
set -eu
if [ "$#" -ne 1 ]; then
    echo 'Usage: COSIGN=/trusted/cosign SYFT_CACHE=/temporary/cache provision-syft.sh /explicit/syft' >&2
    exit 2
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
destination=$1
cache=${SYFT_CACHE:-"${destination}.cache"}
exec python3 "$script_dir/provision-syft.py" --cosign "${COSIGN:-cosign}" --cache "$cache" --destination "$destination"
