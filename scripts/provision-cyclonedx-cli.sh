#!/bin/sh
# CI/test only: install the pinned CycloneDX CLI (independent schema validator).
# Trust anchor: SHA-256 digests of the official v0.33.1 release binaries as
# published by the GitHub release API. The CLI is never shipped with cracken-sbom.
set -eu
if [ "$#" -ne 1 ]; then
    echo 'Usage: provision-cyclonedx-cli.sh /explicit/cyclonedx' >&2
    exit 2
fi
destination=$1
version=0.33.1
case $(uname -s)/$(uname -m) in
    Darwin/arm64) asset=osx-arm64; expected=750c148780154833f6401f9067d08c5a4c31567b6ee3c26c062c3a95c62d741c ;;
    Darwin/x86_64) asset=osx-x64; expected=0ea92306fc7d7c30ed112a7463781a200585a3bf1cdaf77229181c5aabd1d4b6 ;;
    Linux/aarch64|Linux/arm64) asset=linux-arm64; expected=b2e9fdf9665ef49868a2ec012171c6e785dcd69745bc5869e53e4f4bfb096a5f ;;
    Linux/x86_64) asset=linux-x64; expected=bfc8b2538da86fe239bc53658bbb63c1c8c510a293c1e6891aa5bea5d3c58746 ;;
    *) echo 'Unsupported platform' >&2; exit 1 ;;
esac
mkdir -p -- "$(dirname -- "$destination")"
temporary=$(mktemp "${destination}.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
    "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v${version}/cyclonedx-${asset}" \
    --output "$temporary"
python3 - "$temporary" "$expected" <<'PY'
import hashlib, sys
from pathlib import Path
actual = hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != sys.argv[2]:
    raise SystemExit('Pinned cyclonedx-cli SHA-256 mismatch')
print('cyclonedx-cli v0.33.1 SHA-256 verified:', actual)
PY
chmod 755 "$temporary"
DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 "$temporary" --version
mv -f -- "$temporary" "$destination"
echo "Provisioned cyclonedx-cli v${version}: $destination"
