#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Provision runtimes first; run this phase with OS network denial.
set -euo pipefail
TOOL_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
GO=${GO:-go}
SYFT=${SYFT:?Set SYFT to an authenticated Syft v1.54.0 executable}
PYTHON=${PYTHON:-python3}
if [[ -z "${CRACKEN_SBOM_TEST_OUTPUT:-}" ]]; then
  CRACKEN_SBOM_TEST_OUTPUT=$(mktemp -d "${TMPDIR:-/tmp}/cracken-sbom-tests.XXXXXX")
else
  mkdir -p "$CRACKEN_SBOM_TEST_OUTPUT"
fi
# Resolve caller-supplied relative paths before changing to TOOL_DIR. All
# validation and outputs below then use the same canonical locations.
SYFT=$("$PYTHON" -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' "$SYFT")
CRACKEN_SBOM_TEST_OUTPUT=$("$PYTHON" -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' "$CRACKEN_SBOM_TEST_OUTPUT")
if [[ -n "$(ls -A "$CRACKEN_SBOM_TEST_OUTPUT")" ]]; then
  printf '%s\n' 'CRACKEN_SBOM_TEST_OUTPUT must be empty; tests never overwrite prior evidence.' >&2
  exit 1
fi
export CRACKEN_SBOM_TEST_OUTPUT
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
cd "$TOOL_DIR"
"$GO" test ./...
"$GO" build -trimpath -o "$CRACKEN_SBOM_TEST_OUTPUT/cracken-sbom" .
"$PYTHON" "$TOOL_DIR/tests/make-archives.py" "$TOOL_DIR/fixtures/rootfs" "$CRACKEN_SBOM_TEST_OUTPUT/archives"
for target in rootfs npm python docker-archive oci-archive; do
  case "$target" in
    docker-archive) fixture="$CRACKEN_SBOM_TEST_OUTPUT/archives/docker.tar" ;;
    oci-archive) fixture="$CRACKEN_SBOM_TEST_OUTPUT/archives/oci.tar" ;;
    *) fixture="$TOOL_DIR/fixtures/$target" ;;
  esac
  "$CRACKEN_SBOM_TEST_OUTPUT/cracken-sbom" generate --target-type "$target" \
    --target "$fixture" --target-id "fixture-$target" --syft "$SYFT" \
    --output "$CRACKEN_SBOM_TEST_OUTPUT/$target"
done
"$PYTHON" "$TOOL_DIR/tests/license_choices_test.py" \
  "$CRACKEN_SBOM_TEST_OUTPUT/cracken-sbom" "$SYFT" "$TOOL_DIR/tests/schema"
"$PYTHON" "$TOOL_DIR/tests/upstream_qualifier_test.py" \
  "$CRACKEN_SBOM_TEST_OUTPUT/cracken-sbom" "$SYFT" "$TOOL_DIR/tests/schema"
# A CLI positive control proves the external synthetic host package is
# cataloged; the --base-path rootfs scan must then exclude it.
"$PYTHON" "$TOOL_DIR/tests/rootfs_absolute_symlink_test.py" \
  "$CRACKEN_SBOM_TEST_OUTPUT/cracken-sbom" "$SYFT" "$TOOL_DIR/fixtures" \
  "$CRACKEN_SBOM_TEST_OUTPUT/rootfs-symlink-tests"
# Acknowledgement cannot turn an empty inventory into a clean SBOM.
mkdir "$CRACKEN_SBOM_TEST_OUTPUT/empty-target"
if "$CRACKEN_SBOM_TEST_OUTPUT/cracken-sbom" generate --target-type rootfs \
  --target "$CRACKEN_SBOM_TEST_OUTPUT/empty-target" --target-id fixture-empty \
  --syft "$SYFT" --output "$CRACKEN_SBOM_TEST_OUTPUT/empty-output" --allow-incomplete \
  >"$CRACKEN_SBOM_TEST_OUTPUT/empty.stdout" 2>"$CRACKEN_SBOM_TEST_OUTPUT/empty.stderr"; then
  printf '%s\n' 'FAIL: empty fixture must be rejected' >&2
  exit 1
fi
"$PYTHON" - "$CRACKEN_SBOM_TEST_OUTPUT" <<'PY'
from pathlib import Path
import sys
output = Path(sys.argv[1])
assert 'empty_sbom' in (output/'empty.stderr').read_text(), 'empty reason must be explicit'
assert not (output/'empty-output').exists(), 'empty inventory must not publish outputs'
print('PASS actual Syft empty inventory fails before output publication')
PY
"$PYTHON" "$TOOL_DIR/tests/fixture_inventory_test.py"
"$PYTHON" "$TOOL_DIR/tests/validate-schema.py" "$CRACKEN_SBOM_TEST_OUTPUT"
printf 'PASS tool suite; local evidence: %s\n' "$CRACKEN_SBOM_TEST_OUTPUT"
