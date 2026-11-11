"""Evidence-only adjudication for three Debian SQLite scanner findings.

This does not publish, modify a Trivy report, or replace the release gate.
The caller must obtain the image identity and runtime measurement from a
trusted, isolated executor; JSON alone cannot prove their origin.
"""
import json
from pathlib import Path
import re
import sys

CVES = frozenset({'CVE-2026-119373', 'CVE-2026-119374', 'CVE-2026-119379'})
LIBRARY_SHA256 = '225ceb839db2c1dd484cfcaa5ef9fbdd429eb1d5f1e0c39fbd50150bca5fc7bc'


def assess(report, image_id, measurement):
    if (not isinstance(report, dict) or not isinstance(image_id, str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id)
            or report.get('Metadata', {}).get('ImageID') != image_id
            or report.get('Metadata', {}).get('OS', {}).get('Family') != 'debian'
            or not isinstance(measurement, dict)
            or measurement != {'sqlite_version': '3.54.1', 'library_sha256': LIBRARY_SHA256, 'fts5': 'pass'}):
        raise ValueError('SQLITE_ASSESSMENT_EVIDENCE_UNVERIFIED')
    results = report.get('Results')
    if not isinstance(results, list) or not any(r.get('Class') == 'os-pkgs' for r in results):
        raise ValueError('SQLITE_ASSESSMENT_REPORT_INCOMPLETE')
    findings = []
    for result in results:
        if not isinstance(result, dict) or result.get('Secrets'):
            raise ValueError('SQLITE_ASSESSMENT_UNEXPECTED_FINDING')
        for item in result.get('Vulnerabilities', []):
            if item.get('Severity') not in ('HIGH', 'CRITICAL'):
                continue
            if (result.get('Class') != 'os-pkgs' or result.get('Type') != 'debian'
                    or item.get('Severity') != 'HIGH' or item.get('PkgName') != 'libsqlite3-0'
                    or item.get('InstalledVersion') != '3.54.1-2'
                    or item.get('VulnerabilityID') not in CVES):
                raise ValueError('SQLITE_ASSESSMENT_UNEXPECTED_FINDING')
            findings.append(item['VulnerabilityID'])
    if len(findings) != len(CVES) or frozenset(findings) != CVES:
        raise ValueError('SQLITE_ASSESSMENT_FINDINGS_MISMATCH')
    return {'image_id': image_id, 'raw_high': len(findings), 'raw_critical': 0,
            'sqlite_version': measurement['sqlite_version'], 'library_sha256': LIBRARY_SHA256,
            'adjudicated_fixed': sorted(CVES), 'release_gate_passed': False,
            'source': 'https://security-tracker.debian.org/tracker/source-package/sqlite3'}


if __name__ == '__main__':
    result = assess(json.loads(Path(sys.argv[1]).read_text()), Path(sys.argv[2]).read_text().strip(),
                    json.loads(Path(sys.argv[3]).read_text()))
    Path(sys.argv[4]).write_text(json.dumps(result, indent=2) + '\n')
