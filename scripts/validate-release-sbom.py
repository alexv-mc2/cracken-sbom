#!/usr/bin/env python3
"""Validate generated documents using vendored schemas; never resolve a URL."""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

if importlib.metadata.version('jsonschema') != '4.23.0':
    raise RuntimeError('Tests require jsonschema==4.23.0; provision it before offline execution')
folder = Path(__file__).resolve().parent.parent/'tests'/'schema'
for line in (folder/'SHA256SUMS').read_text().splitlines():
    expected, name = line.split('  ', 1)
    actual = hashlib.sha256((folder/name).read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError(f'Vendored schema checksum mismatch: {name}')
resources = []
for name in ['bom-1.5.schema.json', 'spdx.schema.json', 'jsf-0.82.schema.json']:
    schema = json.loads((folder/name).read_text())
    resource = Resource.from_contents(schema, default_specification=DRAFT7)
    resources += [(schema['$id'], resource), ('http://cyclonedx.org/schema/'+name, resource)]
registry = Registry().with_resources(resources)
schema = json.loads((folder/'bom-1.5.schema.json').read_text())
validator = Draft7Validator(schema, registry=registry)
assert not validator.is_valid({'bomFormat':'CycloneDX', 'specVersion':'1.5', 'version':1,
                               'components':[{'type':'library'}]}), 'Validator must reject missing name'
documents = sorted(Path(sys.argv[1]).glob('*.cdx.json'))
if len(documents) != 4:
    raise RuntimeError('Expected exactly four per-binary SBOM files')
for target in documents:
    document = json.loads(target.read_text())
    errors = sorted(validator.iter_errors(document), key=lambda e: str(list(e.path)))
    if errors:
        raise RuntimeError('\n'.join(f'{target.name}: {list(e.path)}: {e.message}' for e in errors))
    print(f'PASS official CycloneDX 1.5 schema: {target.name}')
