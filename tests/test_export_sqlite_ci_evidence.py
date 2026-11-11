import json
from pathlib import Path
import tempfile
import unittest

from scripts.export_sqlite_ci_evidence import export


class ExportEvidenceTests(unittest.TestCase):
    def test_raw_report_only_exported_without_secret_findings(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            security = work / 'security'
            security.mkdir()
            (security / 'agent.json').write_text(json.dumps({'Results': [{'Vulnerabilities': [{'VulnerabilityID': 'CVE-1'}]}]}))
            (security / 'guardrail.json').write_text(json.dumps({'Results': [{'Secrets': [{'Match': 'secret-canary'}]}]}))
            export(work)
            output = work / 'public-evidence'
            self.assertTrue((output / 'agent.json').exists())
            self.assertFalse((output / 'guardrail.json').exists())
            self.assertTrue((output / 'guardrail-raw-report-withheld.txt').exists())
            self.assertNotIn('secret-canary', ''.join(p.read_text() for p in output.iterdir()))

    def test_invalid_report_is_not_exported(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            (work / 'security').mkdir()
            (work / 'security' / 'agent.json').write_text('{}')
            with self.assertRaises(ValueError):
                export(work)
            self.assertFalse((work / 'public-evidence' / 'agent.json').exists())


if __name__ == '__main__':
    unittest.main()
