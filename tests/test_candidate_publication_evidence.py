import json
from pathlib import Path
import tempfile
import unittest

from scripts import add_vendor_openssl_sbom, candidate_publication_evidence as publication, security_gate, sqlite_vex_gate, vendor_openssl_gate
from tests.test_sqlite_vex_gate import SQLiteVexGateTests
from tests.test_vendor_openssl_gate import VendorOpenSSLTests


class CandidatePublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.evidence = self.root/'evidence'; self.evidence.mkdir()
        sample = SQLiteVexGateTests(); sample.setUp(); self.sample = sample
        self.openssl = {'package':'libssl3', 'package_version':vendor_openssl_gate.VERSION,
                        'package_sha256':vendor_openssl_gate.PACKAGE_SHA256,
                        'distribution':'debian-12-bookworm', 'version':'OpenSSL 3.0.22 2026',
                        'libraries':{'libssl.so.3':'a'*64,'libcrypto.so.3':'b'*64}}
        vendor = VendorOpenSSLTests()
        actual = vendor.report(vendor_openssl_gate.VERSION, [])
        negative = vendor.report('3.0.0-1', [{'Severity':'HIGH'}])
        files = {'trivy-vuln-report.json':sample.report, 'security-summary.json':security_gate.summary(sample.report),
                 'sqlite-measurement.json':sample.measure,
                 'sqlite-vex-summary.json':sqlite_vex_gate.assess_evidence(sample.report,sample.image,sample.measure)[1],
                 'openssl-measurement.json':self.openssl, 'vendor-openssl-report.json':actual,
                 'vendor-openssl-control-report.json':negative,
                 'vendor-openssl-summary.json':{'package':'libssl3','version':vendor_openssl_gate.VERSION,
                                               'high_critical':0,'negative_control_high_critical':1,'status':'pass'},
                 'openssl-tls-check.json':{'valid_tls':'pass','hostname_rejection':'pass',
                                           'untrusted_ca_rejection':'pass','openssl':self.openssl['version']}}
        for name, value in files.items(): (self.evidence/name).write_text(json.dumps(value))
        raw_sbom={'bomFormat':'CycloneDX','components':[]}
        (self.evidence/'sbom.cdx.json').write_text(json.dumps(raw_sbom))
        merged=add_vendor_openssl_sbom.combine(raw_sbom,self.openssl,files['vendor-openssl-summary.json'])
        (self.evidence/'sbom-with-vendor.cdx.json').write_text(json.dumps(merged))
        (self.evidence/'openssl-control.txt').write_text('Package: libssl3\nVersion: '+vendor_openssl_gate.VERSION+'\nSource: openssl\n')
        self.runtime = {'sqlite':sample.measure, 'openssl':{'version':self.openssl['version'],'libraries':self.openssl['libraries']}}

    def test_requires_exact_runtime_and_security_evidence(self):
        result = publication.verify(self.root,'agent',self.sample.image,self.runtime)
        self.assertEqual(result['security']['critical_high'],3)
        self.assertTrue(result['sqlite_vex']['vex_gate_passed'])
        with self.assertRaises(ValueError): publication.verify(self.root,'agent','sha256:'+'b'*64,self.runtime)
        altered = dict(self.runtime, sqlite=dict(self.sample.measure, library_sha256='c'*64))
        with self.assertRaises(ValueError): publication.verify(self.root,'agent',self.sample.image,altered)
        (self.evidence/'vendor-openssl-control-report.json').write_text('{}')
        with self.assertRaises(ValueError): publication.verify(self.root,'agent',self.sample.image,self.runtime)

    def test_rejects_unexpected_high(self):
        report = self.sample.report
        report['Results'][0]['Vulnerabilities'].append({'Severity':'HIGH','PkgName':'openssl','VulnerabilityID':'CVE-2099-1234'})
        (self.evidence/'trivy-vuln-report.json').write_text(json.dumps(report))
        with self.assertRaises(ValueError): publication.verify(self.root,'agent',self.sample.image,self.runtime)


if __name__ == '__main__':
    unittest.main()
