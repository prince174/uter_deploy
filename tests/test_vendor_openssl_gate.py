import json
from pathlib import Path
import tempfile
import unittest

from scripts import vendor_openssl_gate as gate


class VendorOpenSSLTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.measurement = self.root/'measurement.json'
        self.control = self.root/'control.txt'
        self.data = {'package':'libssl3', 'package_version':gate.VERSION,
                     'package_sha256':gate.PACKAGE_SHA256, 'version':'OpenSSL 3.0.22 2026',
                     'distribution':'debian-12-bookworm',
                     'libraries':{'libssl.so.3':'a'*64, 'libcrypto.so.3':'b'*64}}
        self.measurement.write_text(json.dumps(self.data))
        self.control.write_text('Package: libssl3\nVersion: '+gate.VERSION+'\nSource: openssl\n')

    def test_requires_matching_provenance_before_creating_scan_roots(self):
        gate.prepare(self.measurement, self.control, self.root/'scans')
        self.assertIn(gate.VERSION, (self.root/'scans/actual/var/lib/dpkg/status').read_text())
        self.assertIn('3.0.0-1', (self.root/'scans/negative/var/lib/dpkg/status').read_text())
        self.data['package_sha256'] = '0'*64
        self.measurement.write_text(json.dumps(self.data))
        with self.assertRaises(ValueError):
            gate.prepare(self.measurement, self.control, self.root/'other')
        self.assertFalse((self.root/'other').exists())

    def report(self, version, vulnerabilities):
        return {'Metadata': {'OS': {'Family':'debian', 'Name':'12.0'}},
                'Results':[{'Class':'os-pkgs','Packages':[{'Name':'libssl3','Version':version}],
                            'Vulnerabilities':vulnerabilities}]}

    def test_rejects_bad_current_report_and_missing_positive_control(self):
        actual = self.root/'actual.json'; negative = self.root/'negative.json'
        actual.write_text(json.dumps(self.report(gate.VERSION, [])))
        negative.write_text(json.dumps(self.report('3.0.0-1', [{'Severity':'HIGH'}])))
        self.assertEqual(gate.verify(actual, negative)['status'], 'pass')
        negative.write_text(json.dumps(self.report('3.0.0-1', [])))
        with self.assertRaises(ValueError): gate.verify(actual, negative)
        negative.write_text(json.dumps(self.report('3.0.0-1', [{'Severity':'HIGH'}])))
        actual.write_text(json.dumps(self.report(gate.VERSION, [{'Severity':'CRITICAL'}])))
        with self.assertRaises(ValueError): gate.verify(actual, negative)

    def test_accepts_trivy_split_debian_version_and_release(self):
        data = self.report('3.0.22', [])
        package = data['Results'][0]['Packages'][0]
        package.update({'Release':'1~deb12u2', 'SrcName':'openssl'})
        self.assertEqual(gate.validate_report(data, gate.VERSION), [])


if __name__ == '__main__':
    unittest.main()
