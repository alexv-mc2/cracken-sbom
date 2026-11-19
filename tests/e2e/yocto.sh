#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Yocto native SPDX (2.2 document set and 3.0.1 rootfs) -> CycloneDX 1.6 SBOM
# plus a separate CycloneDX VEX 1.6 file with the patched/assessed CVEs.
set -euo pipefail
TOOL_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
run() {
  "$CRACKEN_SBOM_BIN" generate --target-type yocto --target "$1" \
    --target-id "$2" --syft "$SYFT" --output "$CRACKEN_SBOM_TEST_OUTPUT/$2" "${@:3}" >/dev/null
}
run "$TOOL_DIR/fixtures/yocto/spdx2" yocto-spdx2
run "$TOOL_DIR/fixtures/yocto/spdx3" yocto-spdx3
cases=(yocto-spdx2 yocto-spdx3)
if command -v zstd >/dev/null 2>&1; then
  deploy="$CRACKEN_SBOM_TEST_OUTPUT/yocto-deploy-input"
  mkdir "$deploy"
  tar -C "$TOOL_DIR/fixtures/yocto/spdx2" -cf - . | zstd -q -o "$deploy/core-image-minimal-qemux86-64.spdx.tar.zst"
  run "$deploy" yocto-spdx2-tar-zst --zstd "$(command -v zstd)"
  cases+=(yocto-spdx2-tar-zst)
else
  echo 'NOTE zstd not installed: .spdx.tar.zst input not exercised here (unit tests cover the tar reader)'
fi
# Real Scarthgap output in a BitBake deploy layout: the dated archive and its
# IMAGE_LINK_NAME link count once, without --yocto-image (docs/YOCTO.md command).
if command -v zstd >/dev/null 2>&1; then
  images="$CRACKEN_SBOM_TEST_OUTPUT/yocto-real-build/tmp/deploy/images/stm32mp25-eval"
  mkdir -p "$images"
  cp "$TOOL_DIR/fixtures/yocto/real-scarthgap/core-image-minimal-stm32mp25-eval.spdx.tar.zst" \
    "$images/core-image-minimal-stm32mp25-eval.rootfs-20260618172332.spdx.tar.zst"
  ln -s core-image-minimal-stm32mp25-eval.rootfs-20260618172332.spdx.tar.zst \
    "$images/core-image-minimal-stm32mp25-eval.rootfs.spdx.tar.zst"
  run "$images" yocto-real-scarthgap --manufacturer-name "Example GmbH" \
    --manufacturer-email psirt@example.com --product-license LicenseRef-example-proprietary
  cases+=(yocto-real-scarthgap)
  # detect finds the image in the build folder and in the deploy folder.
  for where in build images; do
    target="$CRACKEN_SBOM_TEST_OUTPUT/yocto-real-build"
    [[ $where == images ]] && target="$images"
    "$CRACKEN_SBOM_BIN" detect "$target" --syft "$SYFT" --target-id real-detect-$where \
      --output "$CRACKEN_SBOM_TEST_OUTPUT/yocto-real-detect-$where" >"$CRACKEN_SBOM_TEST_OUTPUT/yocto-real-detect-$where.log"
    grep -q -- "--target-type yocto --target $images" "$CRACKEN_SBOM_TEST_OUTPUT/yocto-real-detect-$where.log"
    cases+=(yocto-real-detect-$where)
  done
fi
# The real Yocto 6.0.3 SPDX 3 sample is not checked in (see docs/YOCTO.md);
# point CRACKEN_SBOM_YOCTO_SPDX3_SAMPLE at a local copy to run it.
if [[ -n "${CRACKEN_SBOM_YOCTO_SPDX3_SAMPLE:-}" ]]; then
  images="$CRACKEN_SBOM_TEST_OUTPUT/yocto-real-build3/tmp/deploy/images/qemux86-64"
  mkdir -p "$images"
  cp "$CRACKEN_SBOM_YOCTO_SPDX3_SAMPLE" "$images/core-image-minimal-qemux86-64.rootfs-20260819091134.spdx.json"
  ln -s core-image-minimal-qemux86-64.rootfs-20260819091134.spdx.json "$images/core-image-minimal-qemux86-64.rootfs.spdx.json"
  run "$images" yocto-real-wrynose
  "$CRACKEN_SBOM_BIN" detect "$CRACKEN_SBOM_TEST_OUTPUT/yocto-real-build3" --syft "$SYFT" --target-id real-detect-wrynose \
    --output "$CRACKEN_SBOM_TEST_OUTPUT/yocto-real-detect-wrynose" >/dev/null
  cases+=(yocto-real-wrynose yocto-real-detect-wrynose)
fi
"$PYTHON" - "$CRACKEN_SBOM_TEST_OUTPUT" "${cases[@]}" <<'PY'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
expected = {
    'yocto-spdx2': {
        'components': {('busybox', '1.36.1-r0'), ('libz1', '1.3.1-r0'), ('busybox', '1.36.1'), ('zlib', '1.3.1')},
        'links': {'busybox': 'busybox', 'libz1': 'zlib'},
        'product': ('core-image-minimal-qemux86-64', '1.0'),
        'vex': {('CVE-2022-28391', 'resolved', 'busybox'), ('CVE-2022-30065', 'resolved', 'busybox'), ('CVE-2023-42364', 'resolved', 'busybox')},
    },
    'yocto-spdx3': {
        'components': {('busybox', '1.36.1'), ('libz1', '1.3.1'), ('libssl3', '3.2.3'), ('zlib', '1.3.1'), ('openssl', '3.2.3')},
        'links': {'busybox': 'busybox', 'libz1': 'zlib', 'libssl3': 'openssl'},
        'product': ('core-image-minimal-qemux86-64.rootfs', '1.0'),
        'vex': {('CVE-2023-42364', 'resolved', 'busybox'), ('CVE-2023-42363', 'not_affected', 'busybox'),
                ('CVE-2024-0727', 'exploitable', 'openssl'), ('CVE-2022-37434', 'resolved', 'zlib')},
    },
}
expected['yocto-spdx2-tar-zst'] = expected['yocto-spdx2']
# (components, recipe components, CPEs on recipes, VEX states): one component
# per recipe, packages without CPEs, one VEX entry per CVE and recipe.
counts = {'yocto-real-scarthgap': (62, 24, 26, {'resolved': 28}), 'yocto-real-wrynose': (65, 27, 28, {'not_affected': 22, 'resolved': 10})}
counts['yocto-real-detect-build'] = counts['yocto-real-detect-images'] = counts['yocto-real-scarthgap']
counts['yocto-real-detect-wrynose'] = counts['yocto-real-wrynose']

def recipe_model(case, sbom):
    """Packages link to a recipe component and carry no CPE; recipes carry them all."""
    by_ref = {c['bom-ref']: c for c in sbom['components']}
    links, recipes = {}, set()
    for c in sbom['components']:
        for p in c.get('properties', []):
            if p['name'] == 'cracken:yocto:recipe':
                assert p['value'] in by_ref, f'{case}: {c["name"]} links to unknown {p["value"]}'
                assert 'cpe' not in c and 'evidence' not in c, f'{case}: package {c["name"]} carries a CPE'
                links[c['name']] = by_ref[p['value']]['name']
                recipes.add(p['value'])
    cpes = 0
    for c in sbom['components']:
        ident = c.get('evidence', {}).get('identity', [])
        assert all(i['field'] == 'cpe' and i['concludedValue'].startswith('cpe:') for i in ident), f'{case}: identity evidence'
        if 'cpe' in c:
            assert c['bom-ref'] in recipes or not any(p['name'] == 'cracken:yocto:recipe' for p in c.get('properties', [])), f'{case}: CPE outside a recipe'
            cpes += 1 + len(ident)
    return by_ref, links, recipes, cpes

def vex_targets(case, sbom, vex):
    """Every affects[].ref is a BOM-Link into this SBOM, without versions."""
    serial = sbom['serialNumber']
    assert serial.startswith('urn:uuid:'), f'{case}: SBOM serial'
    prefix = 'urn:cdx:' + serial[len('urn:uuid:'):] + '/1#'
    assert {'name': 'cracken:vex:sbom:serial', 'value': serial} in vex['metadata']['properties'], f'{case}: VEX names the SBOM serial'
    for v in vex['vulnerabilities']:
        for a in v['affects']:
            assert a['ref'].startswith(prefix), f'{case}: {a["ref"]} is not a BOM-Link to this SBOM'
            assert 'versions' not in a, f'{case}: versions on a recipe statement'
            yield v, a['ref'][len(prefix):]

for case in sys.argv[2:]:
    if case in counts:
        sbom = json.loads((out/case/'sbom.cdx.json').read_text())
        vex = json.loads((out/case/'sbom.vex.cdx.json').read_text())
        assert 'vulnerabilities' not in sbom, f'{case}: vulnerability data inside the SBOM'
        by_ref, links, recipes, cpes = recipe_model(case, sbom)
        states, seen = {}, set()
        for v, ref in vex_targets(case, sbom, vex):
            assert ref in recipes, f'{case}: VEX names {ref}, not a recipe component'
            assert (v['id'], ref) not in seen, f'{case}: duplicate statement'
            seen.add((v['id'], ref))
            states[v['analysis']['state']] = states.get(v['analysis']['state'], 0) + 1
        got = (len(sbom['components']), len(recipes), cpes, states)
        assert got == counts[case], f'{case}: {got}'
        assert 'DocumentRef' not in (out/case/'sbom.cdx.json').read_text(), f'{case}: cross-document reference kept'
        print(f'PASS real Yocto {case}: {got[0]} components ({got[1]} recipes, {got[2]} CPEs, all on recipes), VEX {states} on recipes by BOM-Link')
        continue
    want = expected[case]
    sbom = json.loads((out/case/'sbom.cdx.json').read_text())
    assert 'vulnerabilities' not in sbom, f'{case}: vulnerability data inside the SBOM'
    comps = {(c['name'], c.get('version')) for c in sbom['components']}
    assert comps == want['components'], f'{case}: components {comps!r}'
    by_ref, links, recipes, cpes = recipe_model(case, sbom)
    assert links == want['links'], f'{case}: recipe links {links!r}'
    root = sbom['metadata']['component']
    assert (root['name'], root['version']) == want['product'], f'{case}: product {root!r}'
    vex = json.loads((out/case/'sbom.vex.cdx.json').read_text())
    assert vex['specVersion'] == '1.6' and not vex.get('components'), f'{case}: VEX shape'
    got = set()
    for v, ref in vex_targets(case, sbom, vex):
        comp = by_ref.get(ref)
        assert comp, f'{case}: VEX reference {ref} is not an SBOM bom-ref'
        got.add((v['id'], v['analysis']['state'], comp['name']))
    assert got == want['vex'], f'{case}: VEX {got!r}'
    prov = json.loads((out/case/'provenance.json').read_text())
    outputs = {o['name'] for o in prov.get('extra_outputs', [])}
    assert outputs == {'sbom.vex.cdx.json', 'cracken-upload.zip'}, f'{case}: provenance extra outputs {outputs!r}'
    text = (out/case/'sbom.cdx.json').read_text() + (out/case/'sbom.vex.cdx.json').read_text()
    for marker in ('fixtures/yocto', '/Users/', '/home/', 'spdx.org/spdxdocs', 'Applet disabled'):
        assert marker not in text, f'{case}: leaked {marker!r}'
    print(f'PASS Yocto {case}: CycloneDX 1.6 SBOM with recipe components and separate VEX ({len(got)} statements) by BOM-Link')
PY

# cracken-upload.zip is the native SPDX, byte for byte, under the original
# file names (checked on the real Scarthgap archive against its tar entries).
if command -v zstd >/dev/null 2>&1; then
  unpacked="$CRACKEN_SBOM_TEST_OUTPUT/yocto-real-unpacked"
  mkdir -p "$unpacked"
  zstd -q -d -c "$TOOL_DIR/fixtures/yocto/real-scarthgap/core-image-minimal-stm32mp25-eval.spdx.tar.zst" | tar -xf - -C "$unpacked"
  "$PYTHON" - "$CRACKEN_SBOM_TEST_OUTPUT/yocto-real-scarthgap/cracken-upload.zip" "$unpacked" <<'PY'
import hashlib, sys, zipfile
from pathlib import Path
upload, unpacked = Path(sys.argv[1]), Path(sys.argv[2])
source = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in unpacked.glob('*.spdx.json')}
with zipfile.ZipFile(upload) as z:
    names = z.namelist()
    got = {n: hashlib.sha256(z.read(n)).hexdigest() for n in names}
assert len(names) == 203 and names == sorted(names), f'{len(names)} entries'
assert got == source, 'cracken-upload.zip differs from the native SPDX documents'
assert upload.stat().st_size <= 16 * 1024 * 1024
print(f'PASS cracken-upload.zip: {len(names)} native SPDX documents, SHA-256 identical to the build archive')
PY
fi
# Above crAcken's ZIP limit: no upload file, a clear reason, and an error
# with --strict-upload. The SBOM and VEX are still written.
big="$CRACKEN_SBOM_TEST_OUTPUT/yocto-upload-over-limit-input"
mkdir -p "$big"
cp "$TOOL_DIR"/fixtures/yocto/spdx2/*.spdx.json "$big/"
"$PYTHON" - "$big/padding.spdx.json" <<'PY'
import json, sys
# A valid extra SPDX 2.2 document of 17 MiB (crAcken's unpacked limit is 16 MiB).
json.dump({'spdxVersion': 'SPDX-2.2', 'SPDXID': 'SPDXRef-DOCUMENT', 'name': 'padding', 'documentNamespace': 'https://example.invalid/padding', 'comment': 'x' * (17 * 1024 * 1024)}, open(sys.argv[1], 'w'))
PY
run "$big" yocto-upload-over-limit
[[ ! -e "$CRACKEN_SBOM_TEST_OUTPUT/yocto-upload-over-limit/cracken-upload.zip" ]]
grep -q 'cracken-upload.zip was not written: the SPDX documents are 17 MiB unpacked, above crAcken' "$CRACKEN_SBOM_TEST_OUTPUT/yocto-upload-over-limit/quality.json"
if "$CRACKEN_SBOM_BIN" generate --target-type yocto --target "$big" --target-id over-limit-strict --syft "$SYFT" \
  --output "$CRACKEN_SBOM_TEST_OUTPUT/yocto-upload-over-limit-strict" --strict-upload >/dev/null 2>"$CRACKEN_SBOM_TEST_OUTPUT/strict.err"; then
  echo 'FAIL --strict-upload must fail above the limit' >&2; exit 1
fi
grep -q 'cracken-upload.zip: the SPDX documents are 17 MiB unpacked' "$CRACKEN_SBOM_TEST_OUTPUT/strict.err"
[[ ! -e "$CRACKEN_SBOM_TEST_OUTPUT/yocto-upload-over-limit-strict" ]]
echo 'PASS cracken-upload.zip over crAcken limit: no file, clear reason; --strict-upload fails'
