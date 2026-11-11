import copy
import unittest
from scripts import sqlite_candidate_assessment as base, sqlite_vex_gate as gate


class SQLiteVexGateTests(unittest.TestCase):
    def setUp(self):
        self.image = 'sha256:' + 'a' * 64
        self.ref = 'ghcr.io/prince174/uter-agent@sha256:' + 'c' * 64
        self.measure = {'sqlite_version': '3.54.1', 'library_sha256': base.LIBRARY_SHA256, 'fts5': 'pass'}
        self.report = {'Metadata': {'ImageID': self.image, 'OS': {'Family': 'debian'}},
                       'Results': [{'Class': 'os-pkgs', 'Type': 'debian', 'Vulnerabilities': [
                           {'VulnerabilityID': cve, 'PkgName': 'libsqlite3-0', 'Severity': 'HIGH',
                            'InstalledVersion': '3.54.1-2', 'PkgIdentifier': {'PURL':
                            'pkg:deb/debian/libsqlite3-0@3.54.1-2?arch=amd64&distro=debian-13.7'}}
                           for cve in sorted(base.CVES)]}]}

    def test_only_exact_findings_get_a_transparent_vex(self):
        vex, result = gate.build_vex(self.report, self.image, self.measure, self.ref)
        self.assertEqual({s['vulnerability']['name'] for s in vex['statements']}, base.CVES)
        for item in vex['statements']:
            self.assertIn('sha256:' + 'c' * 64, item['products'][0]['@id'])
            self.assertEqual(len(item['products'][0]['subcomponents']), 1)
        self.assertEqual(result['raw_high'], 3)
        self.assertFalse(result['release_gate_passed'])
        self.assertTrue(result['vex_gate_passed'])

    def test_other_high_critical_secrets_and_wrong_purl_refused(self):
        for kind in ('high', 'critical', 'secret', 'purl', 'duplicate'):
            report = copy.deepcopy(self.report)
            items = report['Results'][0]['Vulnerabilities']
            if kind == 'high': items.append(dict(items[0], VulnerabilityID='CVE-2099-1234'))
            if kind == 'critical': items[0]['Severity'] = 'CRITICAL'
            if kind == 'secret': report['Results'][0]['Secrets'] = [{'RuleID': 'secret'}]
            if kind == 'purl': items[0]['PkgIdentifier']['PURL'] = 'pkg:deb/debian/other@3.54.1-2'
            if kind == 'duplicate': items.append(dict(items[0]))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                gate.build_vex(report, self.image, self.measure, self.ref)

    def test_wrong_identity_version_and_library_hash_refused(self):
        for image, measure in [('sha256:' + 'b' * 64, self.measure),
                               (self.image, dict(self.measure, sqlite_version='3.46.1')),
                               (self.image, dict(self.measure, library_sha256='b' * 64))]:
            with self.subTest(image=image, measure=measure), self.assertRaises(ValueError):
                gate.build_vex(self.report, image, measure, self.ref)

    def test_unpinned_or_unrelated_registry_reference_rejected(self):
        for ref in ('ghcr.io/prince174/uter-agent:latest', 'ghcr.io/other/uter-agent@sha256:' + 'c' * 64):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                gate.build_vex(self.report, self.image, self.measure, ref)


if __name__ == '__main__':
    unittest.main()
