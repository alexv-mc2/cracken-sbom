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
"$PYTHON" - "$CRACKEN_SBOM_TEST_OUTPUT" "${cases[@]}" <<'PY'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
expected = {
    'yocto-spdx2': {
        'components': {('busybox', '1.36.1-r0'), ('libz1', '1.3.1-r0')},
        'product': ('core-image-minimal-qemux86-64', '1.0'),
        'vex': {('CVE-2022-28391', 'resolved', 'busybox'), ('CVE-2022-30065', 'resolved', 'busybox'), ('CVE-2023-42364', 'resolved', 'busybox')},
    },
    'yocto-spdx3': {
        'components': {('busybox', '1.36.1'), ('libz1', '1.3.1'), ('libssl3', '3.2.3')},
        'product': ('core-image-minimal-qemux86-64.rootfs', '1.0'),
        'vex': {('CVE-2023-42364', 'resolved', 'busybox'), ('CVE-2023-42363', 'not_affected', 'busybox'),
                ('CVE-2024-0727', 'exploitable', 'libssl3'), ('CVE-2022-37434', 'resolved', 'libz1')},
    },
}
expected['yocto-spdx2-tar-zst'] = expected['yocto-spdx2']
for case in sys.argv[2:]:
    want = expected[case]
    sbom = json.loads((out/case/'sbom.cdx.json').read_text())
    assert 'vulnerabilities' not in sbom, f'{case}: vulnerability data inside the SBOM'
    comps = {(c['name'], c.get('version')) for c in sbom['components']}
    assert comps == want['components'], f'{case}: components {comps!r}'
    root = sbom['metadata']['component']
    assert (root['name'], root['version']) == want['product'], f'{case}: product {root!r}'
    by_ref = {c['bom-ref']: c for c in sbom['components']}
    vex = json.loads((out/case/'sbom.vex.cdx.json').read_text())
    assert vex['specVersion'] == '1.6' and not vex.get('components'), f'{case}: VEX shape'
    got = set()
    for v in vex['vulnerabilities']:
        for a in v['affects']:
            comp = by_ref.get(a['ref'])
            assert comp, f'{case}: VEX reference {a["ref"]} is not an SBOM bom-ref'
            assert a['versions'][0]['version'] == comp['version'], f'{case}: VEX version mismatch'
            got.add((v['id'], v['analysis']['state'], comp['name']))
    assert got == want['vex'], f'{case}: VEX {got!r}'
    prov = json.loads((out/case/'provenance.json').read_text())
    outputs = {o['name'] for o in prov.get('extra_outputs', [])}
    assert outputs == {'sbom.vex.cdx.json'}, f'{case}: provenance extra outputs {outputs!r}'
    text = (out/case/'sbom.cdx.json').read_text() + (out/case/'sbom.vex.cdx.json').read_text()
    for marker in ('fixtures/yocto', '/Users/', '/home/', 'spdx.org/spdxdocs', 'Applet disabled'):
        assert marker not in text, f'{case}: leaked {marker!r}'
    print(f'PASS Yocto {case}: CycloneDX 1.6 SBOM and separate VEX ({len(got)} statements) with SBOM bom-refs')
PY
