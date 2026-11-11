import copy
import unittest

from scripts import sqlite_candidate_assessment as assessment


class SQLiteCandidateAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.image_id = 'sha256:' + 'a' * 64
        self.measurement = {'sqlite_version': '3.54.1', 'library_sha256': assessment.LIBRARY_SHA256, 'fts5': 'pass'}
        self.report = {'Metadata': {'ImageID': self.image_id, 'OS': {'Family': 'debian'}},
                       'Results': [{'Class': 'os-pkgs', 'Type': 'debian', 'Vulnerabilities': [
                           {'VulnerabilityID': name, 'PkgName': 'libsqlite3-0',
                            'InstalledVersion': '3.54.1-2', 'Severity': 'HIGH'}
                           for name in sorted(assessment.CVES)]}]}

    def test_records_raw_findings_without_claiming_gate_pass(self):
        result = assessment.assess(self.report, self.image_id, self.measurement)
        self.assertEqual(result['raw_high'], 3)
        self.assertEqual(set(result['adjudicated_fixed']), assessment.CVES)
        self.assertFalse(result['release_gate_passed'])

    def test_rejects_wrong_image_or_loaded_library(self):
        for image, measurement in [(('sha256:' + 'b' * 64), self.measurement),
                                   (self.image_id, dict(self.measurement, library_sha256='0' * 64)),
                                   (self.image_id, dict(self.measurement, sqlite_version='3.46.1'))]:
            with self.subTest(image=image, measurement=measurement), self.assertRaises(ValueError):
                assessment.assess(self.report, image, measurement)

    def test_rejects_unexpected_or_missing_high_and_critical(self):
        for mutation in ('extra_high', 'critical', 'missing', 'duplicate', 'wrong_version', 'secret'):
            report = copy.deepcopy(self.report)
            items = report['Results'][0]['Vulnerabilities']
            if mutation == 'extra_high': items.append(dict(items[0], VulnerabilityID='CVE-2099-1234'))
            if mutation == 'critical': items[0]['Severity'] = 'CRITICAL'
            if mutation == 'missing': items.pop()
            if mutation == 'duplicate': items[0] = dict(items[1])
            if mutation == 'wrong_version': items[0]['InstalledVersion'] = '3.46.1-7+deb13u2'
            if mutation == 'secret': report['Results'][0]['Secrets'] = [{'RuleID': 'secret'}]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                assessment.assess(report, self.image_id, self.measurement)


if __name__ == '__main__':
    unittest.main()
