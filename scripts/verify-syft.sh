#!/bin/sh
# Verify predownloaded upstream materials without installing an executable.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$script_dir/provision-syft.py" --offline --verify-only "$@"
