#!/bin/sh
# Bootstrap the pinned public verification tool over authenticated HTTPS.
# Trust anchor: pinned binary digest recorded from the official upstream release
# API and its checksum manifest. No signing, keys, credentials or global install.
set -eu
if [ "$#" -ne 1 ]; then
    echo 'Usage: provision-cosign.sh /explicit/cosign' >&2
    exit 2
fi
destination=$1
case $(uname -s)/$(uname -m) in
    Darwin/arm64) platform=darwin-arm64; expected=c01df01bac51714322f17d6416798d8a7b9e903657c6a2f8f09b9aee5ba29f57 ;;
    Darwin/x86_64) platform=darwin-amd64; expected=ad5db28c48faf66984c48733cad66504cea316f8e833bb13ef13060a6dc45b13 ;;
    Linux/aarch64|Linux/arm64) platform=linux-arm64; expected=3dee37fce75fcf51b00b985dbc64df15c30cf35d9ca9c5cdbf3e8e867a22e43f ;;
    Linux/x86_64) platform=linux-amd64; expected=d437b8f0d30f5dec169337607fcfa0238de1348503e175f1bb5b94330b1ee409 ;;
    *) echo 'Unsupported platform' >&2; exit 1 ;;
esac
mkdir -p -- "$(dirname -- "$destination")"
temporary=$(mktemp "${destination}.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
    "https://github.com/sigstore/cosign/releases/download/v2.6.2/cosign-${platform}" \
    --output "$temporary"
python3 - "$temporary" "$expected" <<'PY'
import hashlib, sys
from pathlib import Path
actual = hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != sys.argv[2]:
    raise SystemExit('Pinned cosign SHA-256 mismatch')
print('Cosign v2.6.2 SHA-256 verified:', actual)
PY
chmod 755 "$temporary"
"$temporary" version
mv -f -- "$temporary" "$destination"
echo "Provisioned cosign v2.6.2: $destination"
