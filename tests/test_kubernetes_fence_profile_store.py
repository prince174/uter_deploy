import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import kubernetes_fence_profile_store as store
from tests.test_kubernetes_fence_pin import KubernetesPinTests


@unittest.skipUnless(os.name=='posix','private profile requires POSIX')
class ProfileStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):KubernetesPinTests.setUpClass()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.path=self.root/'profile.json';self.key=b'k'*32
        fixture=KubernetesPinTests();fixture.setUp()
        self.record={'schema':1,'site':'uter-test','api':fixture.profile,
            'writer_uids':{'guardrail':'7a1ae129-82a8-490f-86e3-84dfd735d334',
                           'agent':'7a1ae129-82a8-490f-86e3-84dfd735d335'},
            'release_version':'0.1.6','inventory_sha256':'a'*64,'publisher_sha256':'b'*64}

    def test_create_once_authenticates_exact_profile(self):
        digest=store.create(self.path,self.key,self.record)
        value,actual=store.read(self.path,self.key)
        self.assertEqual(value,self.record);self.assertEqual(digest,actual)
        self.assertEqual(digest,hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(self.path.stat().st_mode&0o777,0o600)
        with self.assertRaises(store.ProfileError):store.create(self.path,self.key,self.record)
        self.assertEqual(store.read(self.path,self.key)[0],self.record)

    def test_wrong_key_modification_symlink_and_duplicate_keys_rejected(self):
        store.create(self.path,self.key,self.record)
        with self.assertRaises(store.ProfileError):store.read(self.path,b'z'*32)
        original=self.path.read_bytes();value=json.loads(original);value['record']['site']='other'
        self.path.write_text(json.dumps(value));self.path.chmod(0o600)
        with self.assertRaises(store.ProfileError):store.read(self.path,self.key)
        duplicate=original.replace(b'{"mac":',b'{"mac":"duplicate","mac":',1)
        self.path.write_bytes(duplicate);self.path.chmod(0o600)
        with self.assertRaises(store.ProfileError):store.read(self.path,self.key)
        self.path.unlink();self.path.symlink_to(self.root/'missing')
        with self.assertRaises(store.ProfileError):store.read(self.path,self.key)

    def test_invalid_pins_or_reused_uid_are_never_persisted(self):
        for mutation in ('missing','duplicate','invaliduid','schema'):
            value=copy.deepcopy(self.record)
            if mutation=='missing':value['api'].pop('ca_sha256')
            if mutation=='duplicate':value['writer_uids']['agent']=value['api']['redis_pvc_uid']
            if mutation=='invaliduid':value['writer_uids']['agent']='invalid'
            if mutation=='schema':value['schema']=True
            with self.subTest(mutation=mutation),self.assertRaises(store.ProfileError):store.create(self.path,self.key,value)
            self.assertFalse(self.path.exists())

    def test_uncertain_fsync_leaves_profile_for_inspection(self):
        with patch.object(store.os,'fsync',side_effect=OSError('disk failure')):
            with self.assertRaises(store.ProfileError):store.create(self.path,self.key,self.record)
        self.assertTrue(self.path.exists())
        with self.assertRaises(store.ProfileError):store.create(self.path,self.key,self.record)

    def test_schema_two_requires_independent_audit_pvc_uid(self):
        record=copy.deepcopy(self.record);record['schema']=2;record['kubectl_sha256']='f'*64
        for uid in (None,'bad',record['api']['redis_pvc_uid'],record['writer_uids']['agent']):
            record['audit_pvc_uid']=uid
            with self.subTest(uid=uid),self.assertRaises(store.ProfileError):store.create(self.path,self.key,record)
            self.assertFalse(self.path.exists())
        record['audit_pvc_uid']='7a1ae129-82a8-490f-86e3-84dfd735d336'
        record['kubectl_sha256']='bad'
        with self.assertRaises(store.ProfileError):store.create(self.path,self.key,record)
        record['kubectl_sha256']='f'*64
        store.create(self.path,self.key,record)
        self.assertEqual(store.read(self.path,self.key)[0],record)
