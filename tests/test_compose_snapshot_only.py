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

    def test_snapshot_only_recovery_rejects_dangling_update_intent(self):
        receipts.write_decision(self.home,self.key,'release')
        for name in (journal.UPDATE_INTENT,journal.UPDATE_START,journal.UPDATE_RESULT,journal.CLEANUP_INTENT):
            marker=self.home/name;marker.symlink_to(self.home/'missing')
            with self.assertRaisesRegex(subject.SnapshotOnlyError,'RECOVERY_INCOMPLETE'):self.recover()
            self.adapter._attach_snapshot_recovery.assert_not_called()
            self.assertEqual(journal.read(self.home)['phase'],'captured');marker.unlink()

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

    def test_mutation_release_rejects_missing_wrong_or_tampered_decision(self):
        from scripts import compose_fenced_update
        self.adapter.bundle=self.root/'old';self.adapter.publisher_key='publisher'
        with patch.object(compose_fenced_update,'_verify_binding'),patch.object(subject,'_bound',return_value=self.binding), \
             patch.object(subject,'_assert_adapter'):
            with self.assertRaisesRegex(subject.SnapshotOnlyError,'RECOVERY_INCOMPLETE'):
                subject.release_for_mutation(self.adapter,'executor','key',self.dest,'target')
            receipts.write_decision(self.home,self.key,'release')
            with self.assertRaisesRegex(subject.SnapshotOnlyError,'RECOVERY_INCOMPLETE'):
                subject.release_for_mutation(self.adapter,'executor','key',self.dest,'target')
            (self.home/receipts.DECISION).unlink();receipts.write_decision(self.home,self.key,'mutation')
            path=self.home/receipts.DECISION
            path.write_bytes(path.read_bytes().replace(b'mutation',b'release'))
            with self.assertRaisesRegex(subject.SnapshotOnlyError,'RECOVERY_INCOMPLETE'):
                subject.release_for_mutation(self.adapter,'executor','key',self.dest,'target')
        self.adapter._attach_snapshot_recovery.assert_not_called()
        self.assertEqual(journal.read(self.home)['phase'],'captured')

    def test_mutation_release_requires_authenticated_update_binding_and_never_resumes_writers(self):
        from scripts import compose_fenced_update
        self.adapter.bundle=self.root/'old';self.adapter.publisher_key='publisher'
        receipts.write_decision(self.home,self.key,'mutation')
        with patch.object(compose_fenced_update,'_verify_binding',side_effect=ValueError('unbound')):
            with self.assertRaises(ValueError):
                subject.release_for_mutation(self.adapter,'executor','key',self.dest,'target')
        self.adapter._attach_snapshot_recovery.assert_not_called()
        with patch.object(compose_fenced_update,'_verify_binding'),patch.object(subject,'_bound',return_value=self.binding), \
             patch.object(subject,'_assert_adapter'):
            self.assertEqual(subject.release_for_mutation(self.adapter,'executor','key',self.dest,'target'),self.manifest['id'])
        self.adapter._recover_snapshot_only.assert_called_once();self.adapter.resume_writers.assert_not_called()
        self.assertEqual(journal.read(self.home)['phase'],'redis_released')

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


class CaptureStageDiagnosticTests(unittest.TestCase):
    def test_capture_errors_expose_only_fixed_stage_without_runtime_data(self):
        from types import SimpleNamespace
        record={'phase':'isolated','operation':'a'*32,'site':'fixture','resource':'b'*64,'plan_sha256':'c'*64}
        binding={'site':{'name':'fixture'},'current':{'version':'1.0.0'},'bundle':'d'*64,
                 'checkpoint':'e'*64,'executor':'f'*64,'destination':'1'*64,
                 'plan':{'site':'fixture','container_id':'b'*64}}
        adapter=SimpleNamespace(home='/fixture',backup_key=b'k'*32,verify_fenced=Mock(return_value=True),
                                _run=Mock(return_value='guard'))
        writer=SimpleNamespace(manifest={'id':'2'*32})
        for failing,expected in (('runtime','RUNTIME'),('redis','REDIS_CAPTURE'),('audit','AUDIT_CAPTURE'),
                                 ('runtime_validate','RUNTIME_VALIDATE'),('audit_validate','AUDIT_VALIDATE'),
                                 ('rdb','RDB_VALIDATE')):
            def crash(*args,**kwargs):
                target=args[1] if len(args)>1 else None
                if target==failing:raise ValueError('secret-canary')
            def archive(*args,**kwargs):
                if failing=='runtime':raise ValueError('secret-canary')
            def rdb(*args,**kwargs):
                if failing=='rdb':raise ValueError('secret-canary')
            def validate(writer,name):
                if failing==name+'_validate':raise ValueError('secret-canary')
            with self.subTest(stage=failing),patch.object(subject,'_assert_adapter'), \
                 patch.object(subject.journal,'read',return_value=record),patch.object(subject.journal,'advance'), \
                 patch.object(subject,'_bound',return_value=binding), \
                 patch.object(subject,'_file',return_value=b'{"backend":"compose"}'), \
                 patch.object(subject.backup_store,'BackupWriter',return_value=writer), \
                 patch.object(subject.receipts,'write_descriptor',return_value='3'*64), \
                 patch.object(subject.backup_snapshot,'archive_runtime',side_effect=archive), \
                 patch.object(subject.backup_snapshot,'process_component',side_effect=crash), \
                 patch.object(subject.backup_snapshot,'verify_encrypted_tar',side_effect=validate), \
                 patch.object(subject.backup_snapshot,'verify_redis_snapshot',side_effect=rdb):
                with self.assertRaises(subject.SnapshotOnlyError) as error:
                    subject.capture_for_mutation(adapter,record,'executor','publisher','destination')
                self.assertEqual(str(error.exception),'SNAPSHOT_CAPTURE_'+expected+'_UNCERTAIN')
                self.assertNotIn('secret',str(error.exception))

    def test_opt_in_requires_signed_capability_before_backup_or_journal_mutation(self):
        from types import SimpleNamespace
        record={'phase':'isolated'}
        adapter=SimpleNamespace(home='/fixture',bundle='/bundle',publisher_key='/key',backup_key=b'k'*32)
        binding={'current':{'version':'1.0.0'}}
        with patch.object(subject,'_assert_adapter'), patch.object(subject.journal,'read',return_value=record), \
             patch.object(subject.journal,'advance') as advance, patch.object(subject,'_bound',return_value=binding), \
             patch.object(subject,'_file',return_value=b'{"backend":"compose","maintenance_enabled":true}'), \
             patch.object(subject.maintenance_protocol,'verify_capability',side_effect=ValueError('no capability')), \
             patch.object(subject.backup_store,'BackupWriter') as writer:
            with self.assertRaisesRegex(subject.SnapshotOnlyError,'SNAPSHOT_CAPTURE_BINDING_UNCERTAIN'):
                subject.capture(adapter,record,'executor','publisher','destination')
            writer.assert_not_called(); advance.assert_not_called()

    def test_changed_opt_in_marker_cannot_produce_a_receipt(self):
        from types import SimpleNamespace
        record={'phase':'isolated','operation':'a'*32,'site':'fixture','resource':'b'*64,'plan_sha256':'c'*64}
        binding={'site':{'name':'fixture'},'current':{'version':'1.0.0'},'bundle':'d'*64,
                 'checkpoint':'e'*64,'executor':'f'*64,'destination':'1'*64}
        adapter=SimpleNamespace(home='/fixture',backup_key=b'k'*32,verify_fenced=Mock(return_value=True))
        writer=SimpleNamespace(manifest={'id':'2'*32})
        with patch.object(subject,'_assert_adapter'), patch.object(subject.journal,'read',return_value=record), \
             patch.object(subject.journal,'advance'), patch.object(subject,'_bound',return_value=binding), \
             patch.object(subject,'_file',side_effect=[b'{"backend":"compose"}',
                                                        b'{"backend":"compose","maintenance_enabled":true}']), \
             patch.object(subject.backup_store,'BackupWriter',return_value=writer), \
             patch.object(subject.receipts,'write_descriptor',return_value='3'*64), \
             patch.object(subject.receipts,'write_receipt') as receipt, \
             patch.object(subject.backup_snapshot,'archive_runtime'):
            with self.assertRaisesRegex(subject.SnapshotOnlyError,'SNAPSHOT_CAPTURE_RUNTIME_UNCERTAIN'):
                subject.capture(adapter,record,'executor','publisher','destination')
            receipt.assert_not_called()
