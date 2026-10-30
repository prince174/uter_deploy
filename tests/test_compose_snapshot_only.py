import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import backup_store, compose_snapshot_only as subject, redis_fence_journal as journal
from scripts import snapshot_only_receipts as receipts


@unittest.skipUnless(os.name=='posix','durable journal requires POSIX')
class SnapshotOnlyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.home=self.root/'home';self.home.mkdir(mode=0o700)
        self.dest=self.root/'backup';self.key=b'K'*32
        self.site={'backend':'compose','name':'uter-test','namespace':'uter-test','context':'default'}
        self.record=journal.create(self.home,backend='compose',site='uter-test',resource='a'*64,plan_sha256='b'*64)
        for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','capturing'),('capturing','captured')):
            self.record=journal.advance(self.home,operation=self.record['operation'],expected=old,next_phase=new)
        writer=backup_store.BackupWriter(self.dest,self.key,self.home,self.site,'0.1.6')
        import io
        for component in ('runtime','redis','audit'):writer.put(component,io.BytesIO(b'fixture-'+component.encode()))
        self.manifest=writer.finish()
        self.binding={'plan':{},'current':{'version':'0.1.6'},'site':self.site,'bundle':'c'*64,
                      'checkpoint':'d'*64,'executor':'e'*64,'destination':subject._hash(str(self.dest.resolve()).encode())}
        descriptor={'schema':1,'operation':self.record['operation'],'backend':'compose','site':'uter-test',
                    'resource':'a'*64,'release_version':'0.1.6','bundle_sha256':'c'*64,
                    'fence_checkpoint_sha256':'d'*64,'identity_sha256':'b'*64,'backup_id':self.manifest['id'],
                    'backup_location_sha256':self.binding['destination'],'executor_sha256':'e'*64}
        digest=receipts.write_descriptor(self.home,self.key,descriptor)
        receipt={'schema':1,'operation':self.record['operation'],'descriptor_sha256':digest,'backup_id':self.manifest['id'],
                 'manifest_sha256':subject._hash((self.dest/'manifest.json').read_bytes())}
        receipts.write_receipt(self.home,self.key,receipt)
        self.adapter=Mock();self.adapter.home=self.home;self.adapter.backup_key=self.key
        self.adapter._attach_snapshot_recovery.return_value=True;self.adapter.verify_fenced.return_value=True
        self.adapter._recover_snapshot_only.return_value=True

    def recover(self):
        with patch.object(subject,'_bound',return_value=self.binding),patch.object(subject,'_assert_adapter'):
            return subject.recover(self.adapter,'executor','key',self.dest)

    def test_caller_supplied_adapter_is_not_accepted(self):
        with self.assertRaisesRegex(subject.SnapshotOnlyError,'RECOVERY_INCOMPLETE'):
            subject.recover(self.adapter,'executor','key',self.dest)
        self.adapter._attach_snapshot_recovery.assert_not_called()

    def test_releases_only_original_redis_after_verified_complete_backup(self):
        receipts.write_decision(self.home,self.key,'release')
        self.assertEqual(self.recover(),self.manifest['id'])
        self.assertEqual(journal.read(self.home)['phase'],'redis_released')
        self.adapter._attach_snapshot_recovery.assert_called_once()
        self.adapter.verify_fenced.assert_called_once()
        self.adapter._recover_snapshot_only.assert_called_once()
        self.adapter.resume_writers.assert_not_called()

    def test_mutation_decision_and_tampered_backup_never_remove_fence(self):
        receipts.write_decision(self.home,self.key,'mutation')
        with self.assertRaisesRegex(subject.SnapshotOnlyError,'RECOVERY_INCOMPLETE'):self.recover()
        self.adapter._attach_snapshot_recovery.assert_not_called()
        (self.home/receipts.DECISION).unlink()
        receipts.write_decision(self.home,self.key,'release')
        with (self.dest/'redis.enc').open('ab') as out:out.write(b'corruption')
        with self.assertRaisesRegex(subject.SnapshotOnlyError,'RECOVERY_INCOMPLETE'):self.recover()
        self.assertEqual(journal.read(self.home)['phase'],'captured')
        self.adapter._attach_snapshot_recovery.assert_not_called()

    def test_failed_redis_release_retains_durable_releasing_phase(self):
        receipts.write_decision(self.home,self.key,'release')
        self.adapter._recover_snapshot_only.side_effect=RuntimeError('unknown result')
        with self.assertRaisesRegex(subject.SnapshotOnlyError,'RECOVERY_INCOMPLETE'):self.recover()
        self.assertEqual(journal.read(self.home)['phase'],'snapshot_releasing')
        self.adapter.resume_writers.assert_not_called()
        self.adapter._recover_snapshot_only.side_effect=None
        self.assertEqual(self.recover(),self.manifest['id'])
        self.assertEqual(journal.read(self.home)['phase'],'redis_released')

    def test_wrong_executor_or_bundle_binding_never_touches_redis(self):
        receipts.write_decision(self.home,self.key,'release')
        for field in ('bundle','checkpoint','executor','destination'):
            with self.subTest(field=field):
                original=self.binding[field];self.binding[field]='f'*64
                with self.assertRaisesRegex(subject.SnapshotOnlyError,'RECOVERY_INCOMPLETE'):self.recover()
                self.binding[field]=original
                self.adapter._attach_snapshot_recovery.assert_not_called()

    def test_executor_inventory_detects_changed_running_source(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from scripts import bundle, compose_nsfirewall_signed_ci as ci
        import json
        key=Ed25519PrivateKey.generate()
        private=self.root/'private.pem'
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        manifest={'schema':1,'config_schema':1,'tooling_schema':1,'status':'released','version':'0.1.6',
                  'source_commit':'a'*40,'data_epoch':1,'upgrade_from':[],
                  'images':{name:'registry.example/'+name+'@sha256:'+'b'*64 for name in ('guardrail','agent','redis')}}
        manifest_path=self.root/'manifest.json';manifest_path.write_text(json.dumps(manifest))
        product=self.root/'product';bundle.build(manifest_path,product,private)
        executor,pub=ci._ci_signed_executor(product,self.root)
        self.assertEqual(len(subject._executor(executor,pub)),64)
        signed=executor/'scripts'/'compose_snapshot_only.py'
        signed.write_bytes(signed.read_bytes()+b'\n# alteration\n')
        with self.assertRaisesRegex(subject.SnapshotOnlyError,'EXECUTOR_UNVERIFIED'):subject._executor(executor,pub)
