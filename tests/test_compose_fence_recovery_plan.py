import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from scripts import compose_fence_recovery_plan as plan
from scripts import redis_fence_journal as journal


@unittest.skipUnless(os.name=='posix','requires POSIX fd and fsync')
class ComposeFenceRecoveryPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name);self.key=b'k'*32
        self.record={'schema':1,'operation':'1'*32,'site':'test','container_id':'a'*64,'started_at':'2026-10-30T00:00:00.123456789Z',
                     'restart_count':0,'image_ref':'ghcr.io/owner/redis@sha256:'+'b'*64,'image_config_id':'sha256:'+'c'*64,
                     'restart_policy':'unless-stopped','volume_name':'test_redis-data','volume_driver':'local',
                     'network_id':'d'*64,'network_name':'test_backend','network_driver':'bridge','network_scope':'local',
                     'network_internal':True,'network_subnet':'172.30.0.0/16','network_gateway':'172.30.0.1',
                     'endpoint_id':'e'*64,'endpoint_ipv4':'172.30.0.5','endpoint_static_ipv4':None,
                     'endpoint_aliases':['redis','test-redis-1'],'endpoint_mac':'02:42:ac:1e:00:05',
                     'ipv6_enabled':False,'network_options':{},'endpoint_driver_options':{}}

    def create(self):return plan.create(self.path,self.record,self.key)
    def read(self,digest,key=None,site='test',resource=None,operation=None):
        return plan.read(self.path,key if key is not None else self.key,digest,operation=operation or '1'*32,site=site,resource=resource or 'a'*64)

    def test_new_operation_is_random_128_bit_hex(self):
        with mock.patch.object(plan.secrets,'token_hex',return_value='a'*32) as random:
            self.assertEqual(plan.new_operation(),'a'*32)
            random.assert_called_once_with(16)

    def test_plan_roundtrip_is_bound_to_journal_site_and_resource(self):
        digest=self.create()
        actual=journal.create(self.path,backend='compose',site='test',resource='a'*64,plan_sha256=digest,operation=self.record['operation'])
        self.assertEqual(self.read(actual['plan_sha256'],site=actual['site'],resource=actual['resource'],operation=actual['operation']),self.record)
        self.assertEqual((self.path/plan.NAME).stat().st_mode & 0o777,0o600)
        with self.assertRaisesRegex(plan.ComposePlanError,'IDENTITY_MISMATCH'):self.read(digest,operation='2'*32)
        with self.assertRaisesRegex(plan.ComposePlanError,'IDENTITY_MISMATCH'):self.read(digest,site='other')
        with self.assertRaisesRegex(plan.ComposePlanError,'IDENTITY_MISMATCH'):self.read(digest,resource='f'*64)

    def test_tamper_even_with_recomputed_unkeyed_hash_fails_mac(self):
        self.create();path=self.path/plan.NAME;envelope=json.loads(path.read_text())
        envelope['plan']['endpoint_ipv4']='172.30.0.6'
        raw=json.dumps(envelope,sort_keys=True,separators=(',',':')).encode()+b'\n'
        path.write_bytes(raw)
        with self.assertRaisesRegex(plan.ComposePlanError,'AUTH_FAILED'):self.read(hashlib.sha256(raw).hexdigest())

    def test_wrong_key_and_changed_hash_are_rejected(self):
        digest=self.create()
        with self.assertRaisesRegex(plan.ComposePlanError,'AUTH_FAILED'):self.read(digest,key=b'x'*32)
        with self.assertRaisesRegex(plan.ComposePlanError,'HASH_MISMATCH'):self.read('0'*64)
        with self.assertRaisesRegex(plan.ComposePlanError,'KEY_INVALID'):self.read(digest,key=b'x')

    def test_never_overwrites_existing_plan(self):
        digest=self.create();original=(self.path/plan.NAME).read_bytes()
        with self.assertRaisesRegex(plan.ComposePlanError,'WRITE_FAILED'):self.create()
        self.assertEqual((self.path/plan.NAME).read_bytes(),original)
        self.assertEqual(self.read(digest),self.record)
        self.assertEqual(sorted(p.name for p in self.path.iterdir()),[plan.NAME])

    def test_rejects_incomplete_or_unsupported_topology(self):
        variants=[{'operation':'x'*32},{'operation':None},{'ipv6_enabled':True},{'network_internal':False},{'network_driver':'overlay'},
                  {'network_options':{'custom':'x'}},{'endpoint_driver_options':{'x':'y'}},
                  {'restart_policy':'always'},{'volume_driver':'nfs'},{'container_id':'z'*64},
                  {'endpoint_ipv4':'172.31.0.1'},{'endpoint_ipv4':False},
                  {'endpoint_static_ipv4':'172.30.0.8'},{'endpoint_aliases':['other']},
                  {'endpoint_aliases':['redis','redis']},{'endpoint_aliases':['redis',{}]},
                  {'started_at':'2026-99-99T00:00:00Z'},{'network_subnet':'172.30.1.0/16'},
                  {'endpoint_mac':'synthetic'}]
        for patch in variants:
            with self.subTest(patch=patch),self.assertRaisesRegex(plan.ComposePlanError,'^COMPOSE_PLAN_INVALID$'):
                plan.create(self.path,dict(self.record,**patch),self.key)
        self.assertFalse((self.path/plan.NAME).exists())
        missing=copy.deepcopy(self.record);missing.pop('site')
        with self.assertRaises(plan.ComposePlanError):plan.create(self.path,missing,self.key)
        extra=dict(self.record,password='secret-do-not-print')
        with self.assertRaisesRegex(plan.ComposePlanError,'^COMPOSE_PLAN_INVALID$'):plan.create(self.path,extra,self.key)

    def test_rejects_symlinks_hardlinks_and_unsafe_permissions(self):
        digest=self.create();path=self.path/plan.NAME;link=self.path/'second'
        os.link(path,link)
        with self.assertRaisesRegex(plan.ComposePlanError,'FILE_UNSAFE'):self.read(digest)
        link.unlink();path.chmod(0o644)
        with self.assertRaisesRegex(plan.ComposePlanError,'FILE_UNSAFE'):self.read(digest)
        path.unlink();path.symlink_to(link)
        with self.assertRaisesRegex(plan.ComposePlanError,'UNREADABLE'):self.read(digest)
        path.unlink();self.path.chmod(0o755)
        with self.assertRaisesRegex(plan.ComposePlanError,'DIRECTORY_UNSAFE'):self.create()

    def test_failed_fsync_fails_closed_and_removes_temp(self):
        with mock.patch.object(plan.os,'fsync',side_effect=OSError('secret path')):
            with self.assertRaisesRegex(plan.ComposePlanError,'^COMPOSE_PLAN_WRITE_FAILED$'):self.create()
        self.assertEqual(list(self.path.iterdir()),[])

    def test_key_never_stored_in_plan(self):
        self.create();self.assertNotIn(self.key,(self.path/plan.NAME).read_bytes())


if __name__=='__main__':unittest.main()
