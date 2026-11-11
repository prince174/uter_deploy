"""Narrow, auditable VEX gate for the exact verified SQLite candidate.

The ordinary security_gate remains strict.  Call only in the trusted CI job
that measured the exact image and captured raw Trivy vulnerability+secret data.
"""
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import sqlite_candidate_assessment as assessment


def assess_evidence(report, image_id, measurement):
    result = assessment.assess(report, image_id, measurement)
    purls = set()
    for group in report['Results']:
        for item in group.get('Vulnerabilities', []):
            if item.get('VulnerabilityID') in assessment.CVES and item.get('PkgName') == 'libsqlite3-0':
                purl = item.get('PkgIdentifier', {}).get('PURL')
                if purl != 'pkg:deb/debian/libsqlite3-0@3.54.1-2?arch=amd64&distro=debian-13.7':
                    raise ValueError('SQLITE_VEX_PACKAGE_UNVERIFIED')
                purls.add(purl)
    if len(purls) != 1:
        raise ValueError('SQLITE_VEX_PACKAGE_UNVERIFIED')
    purl = purls.pop()
    result['policy'] = 'exact-image-and-loaded-sqlite-vex'
    result['vex_gate_passed'] = True
    return purl, result


def build_vex(report, image_id, measurement, reference):
    purl, result = assess_evidence(report, image_id, measurement)
    match = re.fullmatch(r'ghcr\.io/prince174/(uter-(?:agent|guardrail))@sha256:([0-9a-f]{64})', reference)
    if not match:
        raise ValueError('SQLITE_VEX_IMAGE_REFERENCE_UNVERIFIED')
    package, digest = match.groups()
    product = 'pkg:oci/' + package + '@sha256:' + digest + '?repository_url=ghcr.io%2Fprince174%2F' + package
    vex = {'@context': 'https://openvex.dev/ns/v0.2.0',
           '@id': 'https://github.com/prince174/uter_deploy/security/sqlite-3.54.1-2/' + image_id.split(':')[1],
           'author': 'Uter deployment security assessment', 'timestamp': '2026-11-11T00:00:00Z', 'version': 1,
           'statements': [{'vulnerability': {'name': cve},
                           'products': [{'@id': product, 'subcomponents': [{'@id': purl}]}],
                           'status': 'not_affected', 'justification': 'vulnerable_code_not_present',
                           'impact_statement': 'Debian sid marks SQLite 3.54.1-2 fixed; exact loaded library SHA-256 was verified.'}
                          for cve in sorted(assessment.CVES)]}
    # release_gate_passed remains false: the unfiltered strict Trivy gate did not pass.
    return vex, result


if __name__ == '__main__':
    raw = json.loads(Path(sys.argv[1]).read_text())
    image = Path(sys.argv[2]).read_text().strip()
    measurement = json.loads(Path(sys.argv[3]).read_text())
    _, result = assess_evidence(raw, image, measurement)
    Path(sys.argv[4]).write_text(json.dumps(result, indent=2) + '\n')
