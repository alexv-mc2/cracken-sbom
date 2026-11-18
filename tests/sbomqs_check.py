#!/usr/bin/env python3
"""Run sbomqs BSI TR-03183-2 v2.1 compliance on every generated SBOM.

Every SBOM must pass the SBOM-level checks the generator always controls:
no vulnerabilities, CycloneDX >= 1.6, timestamp, SBOM-URI, and a complete,
completeness-indicated dependency graph from the product. SBOMs generated
with a manufacturer contact must also pass the SBOM-creator check. The
reports and scores are written to REPORT_DIR for review.
Usage: sbomqs_check.py SBOMQS OUTPUT_DIR REPORT_DIR
"""
import json
import subprocess
import sys
from pathlib import Path

ALWAYS = ['vuln', 'specification version', 'timestamp', 'SBOM-URI', 'dependency graph completeness']


def main():
    if len(sys.argv) != 4:
        raise SystemExit('usage: sbomqs_check.py SBOMQS OUTPUT_DIR REPORT_DIR')
    sbomqs, output, reports = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    reports.mkdir(parents=True, exist_ok=False)
    sboms = sorted(output.rglob('sbom.cdx.json'))
    if not sboms:
        raise SystemExit('FAIL sbomqs: no SBOMs found')
    scores = {}
    for path in sboms:
        label = str(path.parent.relative_to(output)).replace('/', '__')
        process = subprocess.run([str(sbomqs), 'compliance', '--bsi-v21', '--json', str(path)],
                                 capture_output=True, text=True, timeout=120, check=False)
        if process.returncode != 0:
            raise SystemExit(f'FAIL sbomqs on {label}: exit {process.returncode}')
        (reports / f'{label}.json').write_text(process.stdout)
        report = json.loads(process.stdout)
        if report.get('revision') != 'TR-03183-2 (2.1.0)':
            raise SystemExit(f'FAIL sbomqs on {label}: unexpected profile {report.get("revision")!r}')
        sbom_level = {r['section_data_field']: r for r in report['sections'] if r.get('element_id') == 'SBOM'}
        required = list(ALWAYS)
        document = json.loads(path.read_text())
        if document.get('metadata', {}).get('manufacturer', {}).get('contact') or document.get('metadata', {}).get('manufacturer', {}).get('url'):
            required.append('creator of SBOM')
        for field in required:
            record = sbom_level.get(field)
            if record is None or record.get('score') != 10:
                raise SystemExit(f'FAIL sbomqs BSI v2.1 on {label}: {field}: {record and record.get("element_result")!r}')
        summary = report['summary']
        scores[label] = {k: round(summary[k], 2) for k in ('total_score', 'required_elements_score', 'additional_elements_score', 'optional_elements_score')}
        print(f'PASS sbomqs BSI TR-03183-2 v2.1 SBOM-level checks: {label} total={scores[label]["total_score"]} required={scores[label]["required_elements_score"]}')
    (reports / 'scores.json').write_text(json.dumps(scores, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
