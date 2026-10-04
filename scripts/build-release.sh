#!/usr/bin/env bash
# Build and inventory the exact release bytes; no signing or upload here.
set -euo pipefail
if [[ $# -ne 2 || ! $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo 'Usage: build-release.sh vX.Y.Z /new/output-directory' >&2
  exit 2
fi
version=${1#v}
output=$2
: "${SYFT:?Set SYFT to the independently verified Syft 1.54.0 executable}"
: "${SOURCE_DATE_EPOCH:?Set SOURCE_DATE_EPOCH to the source commit timestamp}"
mkdir "$output"
output=$(cd "$output" && pwd)
workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0
for platform in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  name="cracken-sbom_${version}_${platform%/*}_${platform#*/}"
  target="$workspace/$name"
  mkdir "$target"
  GOOS=${platform%/*} GOARCH=${platform#*/} go build \
    -trimpath -buildvcs=false -ldflags="-buildid= -X main.toolVersion=$version" \
    -o "$target/cracken-sbom" .
  # Build twice in different output directories and require byte equality.
  GOOS=${platform%/*} GOARCH=${platform#*/} go build \
    -trimpath -buildvcs=false -ldflags="-buildid= -X main.toolVersion=$version" \
    -o "$workspace/rebuilt" .
  cmp "$target/cracken-sbom" "$workspace/rebuilt"
  (
    cd "$target"
    SYFT_CHECK_FOR_APP_UPDATE=false "$SYFT" scan file:cracken-sbom \
      --source-name cracken-sbom --source-version "$version" \
      -o cyclonedx-json@1.5 > "$output/$name.cdx.json"
  )
  python3 scripts/package-release.py "$target/cracken-sbom" \
    "$output/$name.cdx.json" "$output/$name.tar.gz" "$SOURCE_DATE_EPOCH"
done
cp LICENSE NOTICE "$output/"
python3 - "$output" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
files = sorted(root.iterdir(), key=lambda p: p.name)
(root / 'SHA256SUMS').write_text(''.join(
    f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files
), encoding='ascii')
PY
