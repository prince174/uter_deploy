"""Copy only non-secret candidate CI evidence for a public workflow artifact."""
import json
from pathlib import Path
import shutil
import sys


def export(work):
    work = Path(work)
    source = work / 'security'
    dest = work / 'public-evidence'
    dest.mkdir(mode=0o700, exist_ok=False)
    for service in ('agent', 'guardrail'):
        report = source / (service + '.json')
        if report.exists():
            value = json.loads(report.read_text(encoding='utf-8'))
            results = value.get('Results')
            if not isinstance(results, list) or any(not isinstance(x, dict) for x in results):
                raise ValueError('EVIDENCE_REPORT_UNVERIFIED')
            if not any(item.get('Secrets') for item in results):
                shutil.copyfile(report, dest / report.name)
            else:
                (dest / (service + '-raw-report-withheld.txt')).write_text(
                    'Raw scan report withheld: secret findings require private review.\n', encoding='utf-8')
        for suffix in ('-image-id.txt', '-sqlite.json', '-assessment.json', '-vex.json', '-vex-summary.json'):
            item = source / (service + suffix)
            if item.is_file():
                shutil.copyfile(item, dest / item.name)
    publication = source / 'publication.json'
    if publication.is_file():
        shutil.copyfile(publication, dest / publication.name)
    for name in ('acceptance.json', 'restart.txt'):
        item = work / 'integration-evidence' / name
        if item.is_file():
            shutil.copyfile(item, dest / name)


if __name__ == '__main__':
    export(sys.argv[1])
