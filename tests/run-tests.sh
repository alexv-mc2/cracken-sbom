#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Provision runtimes first; run this phase with OS network denial.
set -euo pipefail
TOOL_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
GO=${GO:-go}
SYFT=${SYFT:?Set SYFT to an authenticated Syft v1.55.0 executable}
PYTHON=${PYTHON:-python3}
SBOMQS=${SBOMQS:?Set SBOMQS to sbomqs v2.1.3 (scripts/provision-sbomqs.sh)}
CYCLONEDX_CLI=${CYCLONEDX_CLI:?Set CYCLONEDX_CLI to cyclonedx-cli v0.33.1 (scripts/provision-cyclonedx-cli.sh)}
if [[ -z "${CRACKEN_SBOM_TEST_OUTPUT:-}" ]]; then
  CRACKEN_SBOM_TEST_OUTPUT=$(mktemp -d "${TMPDIR:-/tmp}/cracken-sbom-tests.XXXXXX")
else
  mkdir -p "$CRACKEN_SBOM_TEST_OUTPUT"
fi
# Resolve caller-supplied relative paths before changing to TOOL_DIR. All
# validation and outputs below then use the same canonical locations.
SYFT=$("$PYTHON" -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' "$SYFT")
SBOMQS=$("$PYTHON" -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' "$SBOMQS")
CYCLONEDX_CLI=$("$PYTHON" -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' "$CYCLONEDX_CLI")
CRACKEN_SBOM_TEST_OUTPUT=$("$PYTHON" -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' "$CRACKEN_SBOM_TEST_OUTPUT")
if [[ -n "$(ls -A "$CRACKEN_SBOM_TEST_OUTPUT")" ]]; then
  printf '%s\n' 'CRACKEN_SBOM_TEST_OUTPUT must be empty; tests never overwrite prior evidence.' >&2
  exit 1
fi
export CRACKEN_SBOM_TEST_OUTPUT SYFT PYTHON SBOMQS CYCLONEDX_CLI
export CRACKEN_SBOM_BIN="$CRACKEN_SBOM_TEST_OUTPUT/cracken-sbom"
# The .NET CLI needs no ICU data for validation.
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
cd "$TOOL_DIR"
"$GO" test ./...
"$GO" build -trimpath -o "$CRACKEN_SBOM_TEST_OUTPUT/cracken-sbom" .
"$PYTHON" "$TOOL_DIR/tests/make-archives.py" "$TOOL_DIR/fixtures/rootfs" "$CRACKEN_SBOM_TEST_OUTPUT/archives"
# Synthetic firmware image: opaque bytes unpacked by tests/fake-extractor.sh.
head -c 4096 /dev/zero > "$CRACKEN_SBOM_TEST_OUTPUT/archives/image.bin"
for target in rootfs npm python dir docker-archive oci-archive firmware-image; do
  extra=()
  case "$target" in
    docker-archive) fixture="$CRACKEN_SBOM_TEST_OUTPUT/archives/docker.tar" ;;
    oci-archive) fixture="$CRACKEN_SBOM_TEST_OUTPUT/archives/oci.tar" ;;
    firmware-image)
      fixture="$CRACKEN_SBOM_TEST_OUTPUT/archives/image.bin"
      extra=(--extractor "$TOOL_DIR/tests/fake-extractor.sh" --extractor-kind unblob) ;;
    *) fixture="$TOOL_DIR/fixtures/$target" ;;
  esac
  "$CRACKEN_SBOM_BIN" generate --target-type "$target" \
    --target "$fixture" --target-id "fixture-$target" --syft "$SYFT" \
    --output "$CRACKEN_SBOM_TEST_OUTPUT/$target" ${extra[@]+"${extra[@]}"}
done
# BSI TR-03183-2: a lockfile project with asserted product and SBOM-creator
# facts, once with concluded licences and once from a metadata file.
"$CRACKEN_SBOM_BIN" generate --target-type npm --target "$TOOL_DIR/fixtures/tr/npm" \
  --target-id fixture-tr-npm --syft "$SYFT" --output "$CRACKEN_SBOM_TEST_OUTPUT/tr-npm" \
  --product-name cracken-tr-fixture --product-version 2.0.0 --product-license Apache-2.0 \
  --manufacturer-name "Example Manufacturer GmbH" --manufacturer-email sbom@example.com \
  --conclude-licenses
"$CRACKEN_SBOM_BIN" generate --target-type npm --target "$TOOL_DIR/fixtures/tr/npm" \
  --target-id fixture-tr-metadata --syft "$SYFT" --output "$CRACKEN_SBOM_TEST_OUTPUT/tr-metadata" \
  --metadata "$TOOL_DIR/fixtures/tr/metadata.json"
"$PYTHON" - "$CRACKEN_SBOM_TEST_OUTPUT" <<'PY'
import json, sys
from pathlib import Path
output = Path(sys.argv[1])
doc = json.loads((output/'tr-npm'/'sbom.cdx.json').read_text())
by_name = {c['name']: c for c in doc['components']}
expected = {
    'left-pad': '5c8e4c3f354d0298c0ca1433a615fc06498ab0a5310f82ddc8adb88997901a29c137dc93413ddb165081cbf695c761eb35ca901ac768b7c821ae3cabbcc0a810',
    'is-odd': '090a6758fac3c263f5f923075d986d2ed26ff74ca2c957e5b86b17e62342564ae142d5374d01ec5163c6f7091d93d2e0779c8da4083d8d0128f7408169781630',
    'is-number': '5aed551de20b04af0a016254022499417f781a6384e39460ebfe77f1f2b08a5a14bb6d4a9dc1246063eaa1bda8499e66513ef7bcb1ab1d08cac3728c3f07c3ce',
}
for name, digest in expected.items():
    refs = [r for r in by_name[name].get('externalReferences', []) if r['type'] == 'distribution']
    assert refs and refs[0]['hashes'] == [{'alg': 'SHA-512', 'content': digest}], f'{name}: lockfile SHA-512 missing'
    assert refs[0]['url'] == f'https://registry.npmjs.org/{name}/-/{name}-{by_name[name]["version"]}.tgz', f'{name}: registry URL'
assert doc['compositions'][0]['aggregate'] == 'complete', 'lockfile graph must be complete'
assert doc['metadata']['manufacturer'] == {'name': 'Example Manufacturer GmbH', 'contact': [{'email': 'sbom@example.com'}]}
assert doc['metadata']['component']['licenses'] == [{'expression': 'Apache-2.0', 'acknowledgement': 'concluded'}]
assert all(l['license']['acknowledgement'] == 'concluded' for c in doc['components'] for l in c.get('licenses', []))
deps = {d['ref']: d['dependsOn'] for d in doc['dependencies']}
odd = by_name['is-odd']['bom-ref']
assert deps[odd] == [by_name['is-number']['bom-ref']], 'is-odd -> is-number edge lost'
meta = json.loads((output/'tr-metadata'/'sbom.cdx.json').read_text())
assert meta['metadata']['component']['name'] == 'cracken-tr-fixture-product'
assert meta['metadata']['manufacturer']['url'] == ['https://example.com/security']
assert all(l['license']['acknowledgement'] == 'declared' for c in meta['components'] for l in c.get('licenses', []))
for target in ['rootfs', 'dir', 'firmware-image']:
    other = json.loads((output/target/'sbom.cdx.json').read_text())
    assert other['compositions'][0]['aggregate'] != 'complete', f'{target}: must not claim a complete graph'
print('PASS TR-03183-2 lockfile SHA-512, product root, creator, acknowledgement and completeness')
PY
# Extension end-to-end tests (one file per target type or subcommand).
for e2e in "$TOOL_DIR"/tests/e2e/*.sh; do
  [[ -e "$e2e" ]] || continue
  bash "$e2e"
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
"$PYTHON" "$TOOL_DIR/tests/version_string_test.py" \
  "$CRACKEN_SBOM_TEST_OUTPUT/cracken-sbom" "$SYFT" "$TOOL_DIR/fixtures" \
  "$CRACKEN_SBOM_TEST_OUTPUT/version-string-tests"
"$PYTHON" "$TOOL_DIR/tests/validate-schema.py" "$CRACKEN_SBOM_TEST_OUTPUT"
"$PYTHON" "$TOOL_DIR/tests/tr_check.py" "$CRACKEN_SBOM_TEST_OUTPUT"
# Independent second validator over every generated SBOM and VEX file.
while IFS= read -r -d '' document; do
  "$CYCLONEDX_CLI" validate --input-file "$document" --input-format json \
    --input-version v1_6 --fail-on-errors >/dev/null
  printf 'PASS cyclonedx-cli v1_6 validate: %s\n' "${document#"$CRACKEN_SBOM_TEST_OUTPUT"/}"
done < <(find "$CRACKEN_SBOM_TEST_OUTPUT" \( -name sbom.cdx.json -o -name '*.vex.cdx.json' \) -print0 | sort -z)
"$PYTHON" "$TOOL_DIR/tests/sbomqs_check.py" "$SBOMQS" "$CRACKEN_SBOM_TEST_OUTPUT" \
  "$CRACKEN_SBOM_TEST_OUTPUT/sbomqs-reports"
printf 'PASS tool suite; local evidence: %s\n' "$CRACKEN_SBOM_TEST_OUTPUT"
