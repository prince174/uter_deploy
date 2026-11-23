import unittest

from scripts import add_vendor_openssl_sbom as sbom, vendor_openssl_gate as gate


class VendorSBOMTests(unittest.TestCase):
    def setUp(self):
        self.doc = {'bomFormat':'CycloneDX','components':[{'name':'python'}]}
        self.measure = {'package_sha256':gate.PACKAGE_SHA256,'package_version':gate.VERSION,
                        'libraries':{'libssl.so.3':'a'*64,'libcrypto.so.3':'b'*64}}
        self.summary = {'status':'pass','version':gate.VERSION,'high_critical':0}

    def test_adds_vendor_identity_and_loaded_hashes(self):
        component = sbom.combine(self.doc,self.measure,self.summary)['components'][-1]
        self.assertIn('distro=debian-12', component['purl'])
        self.assertEqual(component['hashes'][0]['content'],gate.PACKAGE_SHA256)
        self.assertIn('a'*64, [item['value'] for item in component['properties']])

    def test_rejects_existing_ssl_or_failed_vendor_scan(self):
        self.doc['components'].append({'name':'libssl3t64'})
        with self.assertRaises(ValueError): sbom.combine(self.doc,self.measure,self.summary)
        self.doc['components'].pop()
        with self.assertRaises(ValueError): sbom.combine(self.doc,self.measure,dict(self.summary,status='fail'))


if __name__ == '__main__':
    unittest.main()
