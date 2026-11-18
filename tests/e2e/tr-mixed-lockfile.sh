#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# A root npm lockfile next to a Python environment: only the packages the
# lockfile lists may be marked complete; the Python package and the product
# must not be (TR-03183-2 §5.2.2 completeness).
set -euo pipefail
TOOL_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
out="$CRACKEN_SBOM_TEST_OUTPUT/tr-mixed-lockfile"
"$CRACKEN_SBOM_BIN" generate --target-type npm --target "$TOOL_DIR/fixtures/tr/mixed" \
  --target-id fixture-tr-mixed --syft "$SYFT" --output "$out" >/dev/null
"$PYTHON" - "$out" <<'PY'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
doc = json.loads((out/'sbom.cdx.json').read_text())
names = {c['bom-ref']: c['name'] for c in doc['components']}
names['cracken-product'] = 'PRODUCT'
got = {c['aggregate']: sorted(names[r] for r in c['dependencies']) for c in doc['compositions']}
want = {'complete': ['cracken-tr-fixture', 'is-number', 'is-odd', 'left-pad'],
        'incomplete': ['PRODUCT', 'gamma-fixture']}
assert got == want, f'compositions {got!r}, want {want!r}'
quality = json.loads((out/'quality.json').read_text())
assert quality['tr_graph_completeness'] == 'incomplete', quality['tr_graph_completeness']
assert any('4 of 5 components' in g for g in quality['tr_gaps']), quality['tr_gaps']
print('PASS mixed npm lockfile + Python environment: complete only for lockfile packages')
PY
