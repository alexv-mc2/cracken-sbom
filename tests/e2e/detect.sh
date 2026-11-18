#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# End-to-end: cracken-sbom detect with the real pinned Syft, offline.
# Run by tests/run-tests.sh (see tests/e2e/README.md for the environment).
set -euo pipefail
TOOL_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=${CRACKEN_SBOM_TEST_OUTPUT:?}
BIN=${CRACKEN_SBOM_BIN:?}
SYFT=${SYFT:?}
PYTHON=${PYTHON:-python3}
CASES="$OUT/detect"
mkdir "$CASES"

fail() { printf 'FAIL detect: %s\n' "$1" >&2; exit 1; }
# expect_text FILE TEXT...: every TEXT must appear in FILE.
expect_text() {
  local file=$1; shift
  for text in "$@"; do
    grep -qF -- "$text" "$file" || { cat "$file" >&2; fail "$(basename "$file") lacks: $text"; }
  done
}

# Builds an SBOM: detect PATH --output DIR, with the expected target type.
build_case() {
  local name=$1 target=$2 type=$3; shift 3
  "$BIN" detect "$target" --syft "$SYFT" --output "$CASES/$name" --target-id "fixture-detect-$name" "$@" \
    >"$CASES/$name.stdout" 2>"$CASES/$name.stderr" || { cat "$CASES/$name.stdout" "$CASES/$name.stderr" >&2; fail "$name exited non-zero"; }
  expect_text "$CASES/$name.stdout" "Command: cracken-sbom generate --target-type $type " "Generated sbom.cdx.json"
  [[ -f "$CASES/$name/sbom.cdx.json" ]] || fail "$name: no sbom.cdx.json"
  "$PYTHON" - "$CASES/$name/provenance.json" "$type" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
assert p['target']['type'] == sys.argv[2], p['target']
PY
  printf 'PASS detect %s -> %s\n' "$name" "$type"
}

build_case dir "$TOOL_DIR/fixtures/dir" dir
build_case rootfs "$TOOL_DIR/fixtures/rootfs" rootfs
build_case python "$TOOL_DIR/fixtures/python" python
build_case docker-archive "$OUT/archives/docker.tar" docker-archive
build_case oci-archive "$OUT/archives/oci.tar" oci-archive
build_case firmware-image "$OUT/archives/image.bin" firmware-image \
  --extractor "$TOOL_DIR/tests/fake-extractor.sh" --extractor-kind unblob

# No arguments, inside an npm project: the default subcommand, the engine
# found through PATH (no --syft), and the default output folder next to it.
mkdir "$CASES/no-args"
# fixtures/tr/npm has a full lockfile graph with integrity hashes.
cp -R "$TOOL_DIR/fixtures/tr/npm" "$CASES/no-args/web-app"
(cd "$CASES/no-args/web-app" && PATH="$(dirname "$SYFT"):$PATH" "$BIN" --target-id fixture-detect-no-args \
  >"$CASES/no-args.stdout" 2>"$CASES/no-args.stderr") || { cat "$CASES/no-args.stdout" "$CASES/no-args.stderr" >&2; fail "no-args exited non-zero"; }
expect_text "$CASES/no-args.stdout" "Found: an npm project with a lockfile" "--target-type npm" "--syft " "Generated sbom.cdx.json"
outputs=("$CASES"/no-args/web-app-sbom-*/sbom.cdx.json)
[[ ${#outputs[@]} -eq 1 && -f "${outputs[0]}" ]] || fail "no-args: default output folder missing"
"$PYTHON" - "${outputs[0]}" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc['compositions'][0]['aggregate'] == 'complete', 'npm lockfile graph must be complete'
PY
printf '%s\n' 'PASS detect no-args -> npm (engine from PATH, default output next to the project)'

# Guidance only: exit 0, explain, write nothing.
guide_case() {
  local name=$1 target=$2; shift 2
  "$BIN" detect "$target" --syft "$SYFT" >"$CASES/$name.stdout" 2>"$CASES/$name.stderr" \
    || { cat "$CASES/$name.stdout" "$CASES/$name.stderr" >&2; fail "$name must exit 0"; }
  expect_text "$CASES/$name.stdout" "No SBOM was written." "$@"
  if compgen -G "$(dirname "$target")/$(basename "$target")-sbom-*" >/dev/null; then fail "$name wrote output"; fi
  printf 'PASS detect %s explains and writes nothing\n' "$name"
}
cp -R "$TOOL_DIR/fixtures/detect" "$CASES/src"
guide_case yocto "$CASES/src/yocto-build" "Found: a Yocto build folder" "docs/YOCTO.md"
guide_case dockerfile "$CASES/src/dockerfile-only" "Found: a Dockerfile" "docker save -o"

# Nothing recognisable: exit 1 with the reason.
if "$BIN" detect "$CASES/src/nothing" --syft "$SYFT" >"$CASES/nothing.stdout" 2>"$CASES/nothing.stderr"; then
  fail "nothing must exit non-zero"
fi
expect_text "$CASES/nothing.stderr" "no SBOM was written: detect found nothing it can list"
printf '%s\n' 'PASS detect nothing -> exit 1 with the reason'

# First-run texts: help exits 0; unknown flags and bad paths are named.
for args in "--help" "detect --help" "generate --help" "help detect"; do
  # shellcheck disable=SC2086
  "$BIN" $args >"$CASES/help.stdout" 2>&1 || fail "$args must exit 0"
  if grep -q "invalid flags" "$CASES/help.stdout"; then fail "$args printed invalid flags"; fi
done
if "$BIN" generate --no-such-flag 2>"$CASES/flag.stderr"; then fail "unknown flag accepted"; fi
expect_text "$CASES/flag.stderr" "unknown flag --no-such-flag"
if "$BIN" detect "$CASES/does-not-exist" 2>"$CASES/path.stderr"; then fail "missing path accepted"; fi
expect_text "$CASES/path.stderr" "$CASES/does-not-exist" "does not exist"
printf '%s\n' 'PASS detect help exits 0; unknown flag and bad path are named'

# No engine anywhere: a clear install message, nothing written.
mkdir "$CASES/no-engine" "$CASES/no-engine/home"
cp "$BIN" "$CASES/no-engine/cracken-sbom"
if HOME="$CASES/no-engine/home" XDG_CACHE_HOME="$CASES/no-engine/home/cache" PATH=/usr/bin:/bin \
  "$CASES/no-engine/cracken-sbom" detect "$TOOL_DIR/fixtures/dir" --output "$CASES/no-engine/out" \
  >"$CASES/no-engine.stdout" 2>"$CASES/no-engine.stderr"; then
  fail "missing engine accepted"
fi
expect_text "$CASES/no-engine.stderr" "syft not found" "Install it like this" "releases/tag/v1.55.0"
[[ ! -e "$CASES/no-engine/out" ]] || fail "no-engine wrote output"
printf '%s\n' 'PASS detect without Syft says how to install it'
