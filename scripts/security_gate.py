"""Summarize full Trivy JSON; fail closed on Critical/High or secrets, no exclusions."""
import collections
import json
from pathlib import Path
import sys


def summary(data):
    counts = collections.Counter()
    secrets = 0
    for result in data.get('Results', []):
        for item in result.get('Vulnerabilities', []):
            counts[item['Severity']] += 1
        secrets += len(result.get('Secrets', []))
    if data.get('Metadata', {}).get('OS', {}).get('Family') not in ('debian', 'alpine') or not any(
        result.get('Class') == 'os-pkgs' for result in data.get('Results', [])
    ):
        raise ValueError('Incomplete Trivy report')
    return {'vulnerabilities': dict(sorted(counts.items())), 'secrets': secrets,
            'critical_high': counts['CRITICAL'] + counts['HIGH']}


if __name__ == '__main__':
    report = summary(json.loads(Path(sys.argv[1]).read_text()))
    Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    if report['critical_high'] or report['secrets']:
        raise SystemExit('Security gate failed: Critical/High or secrets remain')
