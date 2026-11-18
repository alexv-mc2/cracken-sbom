#!/bin/sh
# CI/test only: install the pinned sbomqs release (BSI TR-03183-2 v2.1 checks).
# Trust anchor: SHA-256 digests of the official v2.1.3 release archives as
# published by the GitHub release API. sbomqs is never shipped with the CLI.
set -eu
if [ "$#" -ne 1 ]; then
    echo 'Usage: provision-sbomqs.sh /explicit/sbomqs' >&2
    exit 2
fi
destination=$1
version=2.1.3
case $(uname -s)/$(uname -m) in
    Darwin/arm64) asset=Darwin_arm64; expected=1d923bdbb8ad4928db345523a38b03a25bf1ee89308ceef8c7b3acd4b614912b ;;
    Darwin/x86_64) asset=Darwin_x86_64; expected=d3c6efbc93ada92333208daa4d5664a7060b90c7de4401a37935abd2c489bb1e ;;
    Linux/aarch64|Linux/arm64) asset=Linux_arm64; expected=f8bdc31f52bff4560bbcf9073864a05903ba955da52af89593f88dab402fbe20 ;;
    Linux/x86_64) asset=Linux_x86_64; expected=c96f07a6a27314c1c268af141af04f1c1b49e61400d7058f6419ca4f7f3bdd6b ;;
    *) echo 'Unsupported platform' >&2; exit 1 ;;
esac
mkdir -p -- "$(dirname -- "$destination")"
work=$(mktemp -d "${destination}.XXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
    "https://github.com/interlynk-io/sbomqs/releases/download/v${version}/sbomqs_${version}_${asset}.tar.gz" \
    --output "$work/sbomqs.tar.gz"
python3 - "$work/sbomqs.tar.gz" "$expected" <<'PY'
import hashlib, sys
from pathlib import Path
actual = hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != sys.argv[2]:
    raise SystemExit('Pinned sbomqs SHA-256 mismatch')
print('sbomqs v2.1.3 archive SHA-256 verified:', actual)
PY
tar -xzf "$work/sbomqs.tar.gz" -C "$work" sbomqs
chmod 755 "$work/sbomqs"
"$work/sbomqs" version >/dev/null
mv -f -- "$work/sbomqs" "$destination"
echo "Provisioned sbomqs v${version}: $destination"
