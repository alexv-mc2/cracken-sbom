#!/usr/bin/env python3
"""Check BSI TR-03183-2 v2.1.0 values that schema validators and sbomqs do not.

sbomqs checks that the bsi:component:* properties exist, not their values.
This script checks every sbom.cdx.json below the output folder against the
BSI CycloneDX property taxonomy v0.1.2 and the generator's own TR rules, and
every *.vex.cdx.json for being a separate VEX document.
Usage: tr_check.py OUTPUT_DIR
"""
import json
import re
import sys
from pathlib import Path

VALUES = {
    'bsi:component:executable': {'executable', 'non-executable'},
    'bsi:component:archive': {'archive', 'no archive'},
    'bsi:component:structured': {'structured', 'unstructured'},
}
EMAIL = re.compile(r'^[^@\s<>]+@[^@\s<>]+\.[A-Za-z0-9-]+$')
SHA512 = re.compile(r'^[0-9a-f]{128}$')


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def check_properties(label, component):
    props = component.get('properties', [])
    names = [p.get('name') for p in props]
    for name, allowed in VALUES.items():
        require(names.count(name) == 1, f'{label}: {name} must occur exactly once')
        value = next(p['value'] for p in props if p['name'] == name)
        require(value in allowed, f'{label}: {name} has invalid value {value!r}')
    require(names.count('bsi:component:filename') <= 1, f'{label}: bsi:component:filename occurs more than once')
    for p in props:
        if p['name'] == 'bsi:component:filename':
            require(p['value'] and '/' not in p['value'] and '\\' not in p['value'], f'{label}: filename must be a file name, not a path')
    for p in props:
        if p['name'].startswith('bsi:') and p['name'] not in VALUES and p['name'] not in ('bsi:component:filename', 'bsi:component:effectiveLicence'):
            raise Failure(f'{label}: unknown BSI property {p["name"]}')


def check_entity(label, entity):
    require(isinstance(entity, dict) and entity, f'{label}: empty organizational entity')
    for contact in entity.get('contact', []):
        require(EMAIL.match(contact.get('email', '')), f'{label}: invalid contact e-mail')
    for url in entity.get('url', []):
        require(url.startswith(('https://', 'http://')) and '@' not in url.split('/')[2], f'{label}: invalid or credential-bearing URL')


def check_hashes(label, component):
    for ref in component.get('externalReferences', []):
        if ref.get('type') == 'distribution':
            hashes = ref.get('hashes', [])
            require(hashes and all(h.get('alg') == 'SHA-512' and SHA512.match(h.get('content', '')) for h in hashes),
                    f'{label}: distribution hash must be SHA-512 hex')
            require('://' not in ref.get('url', '') or ref['url'].startswith('https://'), f'{label}: non-https distribution URL')


def check_sbom(path):
    doc = json.loads(path.read_text())
    label = str(path)
    require(doc.get('bomFormat') == 'CycloneDX' and doc.get('specVersion') == '1.6', f'{label}: must be CycloneDX 1.6')
    require('vulnerabilities' not in doc, f'{label}: an SBOM must not contain vulnerability information (TR §3.1)')
    require(str(doc.get('serialNumber', '')).startswith('urn:uuid:'), f'{label}: serialNumber (SBOM-URI) missing')
    meta = doc.get('metadata', {})
    require(meta.get('timestamp'), f'{label}: timestamp missing')
    props = {p['name']: p['value'] for p in meta.get('properties', [])}
    require(props.get('cracken:tr:profile') == 'BSI-TR-03183-2-v2.1.0', f'{label}: TR profile marker missing')
    ack = props.get('cracken:tr:licence-acknowledgement')
    require(ack in ('declared', 'concluded'), f'{label}: licence acknowledgement marker missing')
    graph_source = props.get('cracken:tr:graph-source')
    require(graph_source in ('lockfile', 'engine', 'none'), f'{label}: graph source marker missing')
    if 'manufacturer' in meta:
        check_entity(f'{label}: metadata.manufacturer', meta['manufacturer'])
    root = meta.get('component')
    require(isinstance(root, dict), f'{label}: metadata.component (product) missing')
    root_ref = root.get('bom-ref')
    require(root_ref and root.get('name') and root.get('version'), f'{label}: product needs bom-ref, name and version')
    check_properties(f'{label}: product', root)
    check_hashes(f'{label}: product', root)
    for lic in root.get('licenses', []):
        require(lic.get('acknowledgement') == 'concluded', f'{label}: product licence must be concluded')
    components = doc.get('components', [])
    refs = [c['bom-ref'] for c in components]
    require(len(set(refs)) == len(refs) and root_ref not in refs, f'{label}: duplicate component references')
    for c in components:
        clabel = f'{label}: {c.get("name")}'
        check_properties(clabel, c)
        check_hashes(clabel, c)
        if 'manufacturer' in c:
            check_entity(clabel, c['manufacturer'])
        for lic in c.get('licenses', []):
            holder = lic.get('license', lic)
            require(holder.get('acknowledgement') == ack, f'{clabel}: licence acknowledgement must be {ack}')
    deps = {d['ref']: d.get('dependsOn') for d in doc.get('dependencies', [])}
    require(deps.get(root_ref), f'{label}: the product must declare its direct dependencies')
    known = set(refs) | {root_ref}
    for ref in refs:
        require(ref in deps and isinstance(deps[ref], list), f'{label}: {ref} has no dependency entry')
    for ref, edges in deps.items():
        require(ref in known and all(e in known for e in edges), f'{label}: dependency graph names unknown references')
    reached, stack = set(), [root_ref]
    while stack:
        ref = stack.pop()
        if ref not in reached:
            reached.add(ref)
            stack.extend(deps.get(ref, []))
    require(reached == known, f'{label}: components unreachable from the product')
    compositions = doc.get('compositions', [])
    require(compositions, f'{label}: compositions missing')
    seen = []
    for composition in compositions:
        aggregate = composition.get('aggregate')
        require(aggregate in ('complete', 'incomplete', 'unknown'), f'{label}: invalid composition aggregate')
        members = composition.get('dependencies', [])
        require(members, f'{label}: empty composition')
        seen.extend(members)
        if aggregate == 'complete':
            require(graph_source == 'lockfile', f'{label}: "complete" only for a lockfile graph')
            by_ref = {c['bom-ref']: c for c in components}
            for ref in members:
                if ref == root_ref:
                    require(all(r in members for r in refs), f'{label}: product complete while components are not')
                    continue
                require(str(by_ref[ref].get('purl', '')).startswith('pkg:npm/'), f'{label}: complete component {ref} is not from the npm lockfile')
                require(all(e in members for e in deps.get(ref, [])), f'{label}: complete component {ref} depends on a component outside the complete set')
    require(sorted(seen) == sorted(known), f'{label}: every component and the product must be in exactly one composition')
    print(f'PASS TR-03183-2 value check: {label}')


def check_vex(path):
    doc = json.loads(path.read_text())
    label = str(path)
    require(doc.get('bomFormat') == 'CycloneDX' and doc.get('specVersion') == '1.6', f'{label}: VEX must be CycloneDX 1.6')
    require('vulnerabilities' in doc and not doc.get('components'), f'{label}: VEX must hold vulnerabilities and no inventory')
    print(f'PASS separate VEX document: {label}')


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: tr_check.py OUTPUT_DIR')
    output = Path(sys.argv[1])
    sboms = sorted(output.rglob('sbom.cdx.json'))
    require(sboms, 'no sbom.cdx.json found')
    for path in sboms:
        check_sbom(path)
    for path in sorted(output.rglob('*.vex.cdx.json')):
        check_vex(path)


if __name__ == '__main__':
    try:
        main()
    except (Failure, KeyError, json.JSONDecodeError) as error:
        print(f'FAIL TR-03183-2 value check: {error}', file=sys.stderr)
        raise SystemExit(1)
