import io
import json
from pathlib import Path
import tempfile
import unittest
from scripts import backup_store as store


class BackupSetTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name)
        self.home=self.root/'home';self.home.mkdir();self.key=b'k'*32
        self.site={'backend':'compose','name':'uter-test','namespace':'uter-test','context':'default'}

    def writer(self, name='backup',site=None):
        return store.BackupWriter(self.root/name,self.key,self.home,site or self.site,'1.0.0')

    def complete(self,w):
        for component in store.REQUIRED[w.manifest['backend']]:w.put(component,io.BytesIO((component+'-data').encode()))
        return w.finish()

    def test_verified_bound_set(self):
        w=self.writer();m=self.complete(w)
        self.assertEqual(store.verify_set(w.path,self.key,home=self.home,site=self.site,version='1.0.0'),m)
        with self.assertRaisesRegex(ValueError,'different installation'):store.verify_set(w.path,self.key,home=self.root/'other',site=self.site)
        with self.assertRaisesRegex(ValueError,'version mismatch'):store.verify_set(w.path,self.key,version='1.0.1')
        self.assertNotIn(b'redis-data',(w.path/'redis.enc').read_bytes())

    def test_incomplete_or_tampered_set_cannot_pass(self):
        w=self.writer();w.put('redis',io.BytesIO(b'REDIS'))
        with self.assertRaisesRegex(ValueError,'Incomplete'):w.finish()
        self.assertFalse((w.path/'manifest.json').exists())
        w.put('runtime',io.BytesIO(b'runtime'));w.put('audit',io.BytesIO(b'audit'));w.finish()
        data=json.loads((w.path/'manifest.json').read_text());data['manifest']['version']='9.0.0'
        (w.path/'manifest.json').write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'authentication'):store.verify_set(w.path,self.key)

    def test_forbids_wrong_scope_overwrites_and_nested_destination(self):
        with self.assertRaisesRegex(ValueError,'outside'):store.BackupWriter(self.home/'backup',self.key,self.home,self.site,'1.0.0')
        w=self.writer();w.put('redis',io.BytesIO(b'content'))
        with self.assertRaisesRegex(ValueError,'duplicate'):w.put('redis',io.BytesIO(b'overwrite'))
        with self.assertRaisesRegex(ValueError,'Unexpected'):w.put('kubernetes',io.BytesIO(b'wrong'))
        with self.assertRaisesRegex(ValueError,'already exists'):self.writer()

    def test_helm_requires_cluster_resources(self):
        site={**self.site,'backend':'helm'};w=self.writer(site=site)
        for label in ('redis','runtime','audit'):w.put(label,io.BytesIO(b'data'))
        with self.assertRaisesRegex(ValueError,'Incomplete'):w.finish()
        w.put('kubernetes',io.BytesIO(b'resources'));self.assertEqual(w.finish()['backend'],'helm')
