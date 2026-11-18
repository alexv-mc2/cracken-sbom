#!/usr/bin/env python3
"""Validate generated documents using vendored schemas; never resolve a URL.

Every sbom.cdx.json and every *.vex.cdx.json below the output folder is
validated, so new target types and extra outputs are covered without edits.
"""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

REQUIRED_TARGETS = ['rootfs', 'npm', 'python', 'docker-archive', 'oci-archive', 'firmware-image', 'dir']

if importlib.metadata.version('jsonschema') != '4.23.0':
    raise RuntimeError('Tests require jsonschema==4.23.0; provision it before offline execution')
folder = Path(__file__).parent/'schema'
for line in (folder/'SHA256SUMS').read_text().splitlines():
    expected, name = line.split('  ', 1)
    actual = hashlib.sha256((folder/name).read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError(f'Vendored schema checksum mismatch: {name}')
resources = []
for name in ['bom-1.6.schema.json', 'spdx.schema.json', 'jsf-0.82.schema.json']:
    schema = json.loads((folder/name).read_text())
    resource = Resource.from_contents(schema, default_specification=DRAFT7)
    resources += [(schema['$id'], resource), ('http://cyclonedx.org/schema/'+name, resource)]
registry = Registry().with_resources(resources)
schema = json.loads((folder/'bom-1.6.schema.json').read_text())
validator = Draft7Validator(schema, registry=registry)
assert not validator.is_valid({'bomFormat':'CycloneDX', 'specVersion':'1.6', 'version':1,
                               'components':[{'type':'library'}]}), 'Validator must reject missing name'
output = Path(sys.argv[1])
for target in REQUIRED_TARGETS:
    if not (output/target/'sbom.cdx.json').is_file():
        raise RuntimeError(f'{target}: expected fixture SBOM is missing')
documents = sorted(set(output.rglob('sbom.cdx.json')) | set(output.rglob('*.vex.cdx.json')))
for path in documents:
    document = json.loads(path.read_text())
    label = str(path.relative_to(output))
    if document.get('specVersion') != '1.6':
        raise RuntimeError(f'{label}: specVersion must be 1.6')
    errors = sorted(validator.iter_errors(document), key=lambda e: str(list(e.path)))
    if errors:
        raise RuntimeError('\n'.join(f'{label}: {list(e.path)}: {e.message}' for e in errors))
    print(f'PASS official CycloneDX 1.6 schema: {label}')
