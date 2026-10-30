import os
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from scripts import (compose_fence_finalize as finalize, compose_fence_origin as origin,
                     compose_fence_recovery_plan as plans, compose_fence_resume as resume,
                     compose_fence_start as start, compose_nsfirewall_checkpoint as checkpoint,
                     redis_fence_journal as journal, snapshot_only_receipts as receipts)


@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'),'requires POSIX files')
class ComposeFenceFinalizeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name);self.key=b'k'*32
        self.record=journal.create(self.home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
        for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','pre_capture_aborting'),
                        ('pre_capture_aborting','redis_released'),('redis_released','writers_resuming'),
                        ('writers_resuming','writers_resumed')):
            self.record=journal.advance(self.home,operation=self.record['operation'],expected=old,next_phase=new)
        self.released={'schema':1,'operation':self.record['operation'],'site':'test','resource':'a'*64,
                       'plan_sha256':'b'*64,'origin':'pre_capture','receipt_sha256':'0'*64}
        self.names=[plans.NAME,checkpoint.NAME,start.NAME,origin.NAME,resume.NAME]
        for name in self.names:
            path=self.home/name;path.write_text('fixture',encoding='utf-8');path.chmod(0o600)
        self.adapter=Mock();self.adapter.home=self.home;self.adapter.backup_key=self.key
        self.adapter._lock=Mock()

    def test_cleanup_removes_journal_last_without_workload_mutation(self):
        removed=[];real_unlink=os.unlink
        def unlink(path,*args,**kwargs):
            if str(path) in self.names+[journal.NAME]:removed.append(str(path))
            return real_unlink(path,*args,**kwargs)
        backup=self.home/'backup-survives';backup.write_text('saved')
        with patch.object(finalize.origin,'read',return_value=self.released), \
             patch.object(finalize,'_validate_live',return_value=self.released), \
             patch.object(finalize.os,'unlink',side_effect=unlink):
            finalize.finalize(self.adapter,self.record,'executor-key',None)
        self.assertEqual(removed[-1],journal.NAME)
        self.assertFalse((self.home/journal.NAME).exists())
        self.assertFalse((self.home/journal.FINALIZE_ANCHOR).exists())
        self.assertTrue(backup.exists());self.adapter._run.assert_not_called()

    def test_interrupted_cleanup_keeps_finalizing_marker_and_never_starts_or_restores(self):
        real_unlink=os.unlink;calls=[]
        def fail_second(path,*args,**kwargs):
            if str(path) in self.names+[journal.NAME]:
                calls.append(str(path))
                if len(calls)==2:raise OSError('injected')
            return real_unlink(path,*args,**kwargs)
        with patch.object(finalize.origin,'read',return_value=self.released), \
             patch.object(finalize,'_validate_live',return_value=self.released), \
             patch.object(finalize.os,'unlink',side_effect=fail_second):
            with self.assertRaisesRegex(finalize.FinalizeError,'^FENCE_FINALIZE_INCOMPLETE$'):
                finalize.finalize(self.adapter,self.record,'executor-key',None)
        self.assertEqual(journal.read(self.home)['phase'],'finalizing')
        self.adapter._run.assert_not_called()

    def test_fsync_failure_after_journal_unlink_rearms_blocking_marker(self):
        real_fsync=os.fsync
        def fail_after_unlink(fd):
            if not os.path.lexists(self.home/journal.NAME) and os.path.lexists(self.home/journal.FINALIZE_ANCHOR):
                raise OSError('injected')
            return real_fsync(fd)
        with patch.object(finalize.origin,'read',return_value=self.released), \
             patch.object(finalize,'_validate_live',return_value=self.released),patch.object(finalize.os,'fsync',side_effect=fail_after_unlink):
            with self.assertRaisesRegex(finalize.FinalizeError,'^FENCE_FINALIZE_INCOMPLETE$'):
                finalize.finalize(self.adapter,self.record,'executor-key',None)
        self.assertTrue(os.path.lexists(self.home/journal.NAME))
        self.assertTrue(os.path.lexists(self.home/journal.FINALIZE_ANCHOR))
        self.assertTrue(journal.blocks_mutation(self.home));self.adapter._run.assert_not_called()

    def test_relink_failure_still_leaves_anchor_blocking_mutations(self):
        real_fsync=os.fsync;real_link=os.link
        def fail_after_unlink(fd):
            if not os.path.lexists(self.home/journal.NAME) and os.path.lexists(self.home/journal.FINALIZE_ANCHOR):
                raise OSError('injected fsync failure')
            return real_fsync(fd)
        def fail_relink(src,dst,*args,**kwargs):
            if src==journal.FINALIZE_ANCHOR and dst==journal.NAME:raise OSError('injected relink failure')
            return real_link(src,dst,*args,**kwargs)
        with patch.object(finalize.origin,'read',return_value=self.released), \
             patch.object(finalize,'_validate_live',return_value=self.released), \
             patch.object(finalize.os,'fsync',side_effect=fail_after_unlink),patch.object(finalize.os,'link',side_effect=fail_relink):
            with self.assertRaisesRegex(finalize.FinalizeError,'^FENCE_FINALIZE_INCOMPLETE$'):
                finalize.finalize(self.adapter,self.record,'executor-key',None)
        self.assertFalse(os.path.lexists(self.home/journal.NAME))
        self.assertTrue(os.path.lexists(self.home/journal.FINALIZE_ANCHOR))
        self.assertTrue(journal.blocks_mutation(self.home));self.adapter._run.assert_not_called()

    def test_anchor_unlink_failure_blocks_even_after_journal_deletion_was_synced(self):
        real_unlink=os.unlink
        def fail_anchor(path,*args,**kwargs):
            if path==journal.FINALIZE_ANCHOR:raise OSError('injected anchor unlink failure')
            return real_unlink(path,*args,**kwargs)
        with patch.object(finalize.origin,'read',return_value=self.released), \
             patch.object(finalize,'_validate_live',return_value=self.released), \
             patch.object(finalize.os,'unlink',side_effect=fail_anchor):
            with self.assertRaisesRegex(finalize.FinalizeError,'^FENCE_FINALIZE_INCOMPLETE$'):
                finalize.finalize(self.adapter,self.record,'executor-key',None)
        self.assertFalse(os.path.lexists(self.home/journal.NAME))
        self.assertTrue(os.path.lexists(self.home/journal.FINALIZE_ANCHOR))
        self.assertTrue(journal.blocks_mutation(self.home));self.adapter._run.assert_not_called()

    def test_fsync_failure_after_anchor_unlink_is_not_claimed_as_blocked(self):
        real_fsync=os.fsync;seen_anchor=[False]
        def fail_after_anchor_removed(fd):
            if os.path.lexists(self.home/journal.FINALIZE_ANCHOR):seen_anchor[0]=True
            if seen_anchor[0] and not os.path.lexists(self.home/journal.NAME) and not os.path.lexists(self.home/journal.FINALIZE_ANCHOR):
                raise OSError('injected post-anchor fsync failure')
            return real_fsync(fd)
        with patch.object(finalize.origin,'read',return_value=self.released), \
             patch.object(finalize,'_validate_live',return_value=self.released), \
             patch.object(finalize.os,'fsync',side_effect=fail_after_anchor_removed):
            with self.assertRaisesRegex(finalize.FinalizeError,'^FENCE_FINALIZE_INCOMPLETE$'):
                finalize.finalize(self.adapter,self.record,'executor-key',None)
        self.assertFalse(os.path.lexists(self.home/journal.NAME))
        self.assertFalse(os.path.lexists(self.home/journal.FINALIZE_ANCHOR))
        self.assertFalse(journal.blocks_mutation(self.home));self.adapter._run.assert_not_called()

    def test_replaced_evidence_rejected_before_cleanup(self):
        def replace(*args):
            path=self.home/start.NAME;path.unlink();path.write_text('replacement');path.chmod(0o600)
            return self.released
        with patch.object(finalize.origin,'read',return_value=self.released), \
             patch.object(finalize,'_validate_live',side_effect=replace):
            with self.assertRaisesRegex(finalize.FinalizeError,'^FENCE_FINALIZE_INCOMPLETE$'):
                finalize.finalize(self.adapter,self.record,'executor-key',None)
        self.assertEqual(journal.read(self.home)['phase'],'writers_resumed')
        self.assertTrue((self.home/plans.NAME).exists());self.adapter._run.assert_not_called()

    def test_missing_origin_or_snapshot_receipt_never_clears_journal(self):
        (self.home/origin.NAME).unlink()
        with self.assertRaisesRegex(finalize.FinalizeError,'^FENCE_FINALIZE_INCOMPLETE$'):
            finalize.finalize(self.adapter,self.record,'executor-key',None)
        self.assertEqual(journal.read(self.home)['phase'],'writers_resumed')
        path=self.home/origin.NAME;path.write_text('fixture');path.chmod(0o600)
        snapshot=dict(self.released,origin='snapshot',receipt_sha256='1'*64)
        with patch.object(finalize.origin,'read',return_value=snapshot):
            with self.assertRaisesRegex(finalize.FinalizeError,'^FENCE_FINALIZE_INCOMPLETE$'):
                finalize.finalize(self.adapter,self.record,'executor-key',self.home/'missing-backup')
        self.assertEqual(journal.read(self.home)['phase'],'writers_resumed')

    def test_prior_unrelated_operation_blocks_before_runtime_inspection(self):
        (self.home/'backup-operation.json').write_text('unknown')
        with patch.object(finalize.diagnostic,'inspect_installation') as inspection:
            with self.assertRaises(ValueError):
                finalize._validate_live(self.adapter,self.record,'executor-key',None)
        inspection.assert_not_called();self.assertEqual(journal.read(self.home)['phase'],'writers_resumed')

    def test_live_validation_rejects_foreign_resume_binding_or_pending_deployment(self):
        import uterctl
        signed={'version':'1.0.0'}
        self.adapter.bundle=self.home/'bundle';self.adapter.bundle.mkdir()
        (self.adapter.bundle/'checksums.json').write_bytes(b'{}')
        installed=self.home/'releases'/'1.0.0';installed.mkdir(parents=True)
        (installed/'checksums.json').write_bytes(b'{}')
        uterctl.write(self.home/'state.json',{'current':signed,'pending':None,'adopted_installer':True})
        original={'guardrail':{'id':'e'*64},'agent':{'id':'f'*64}}
        product_hash=hashlib.sha256(b'{}').hexdigest();executor_hash='8'*64
        base={'schema':1,'operation':self.record['operation'],'plan_sha256':self.record['plan_sha256'],
              'start_intent_sha256':hashlib.sha256(start._canonical(original)).hexdigest(),
              'bundle_sha256':product_hash,'executor_sha256':executor_hash,'backup_receipt_sha256':'0'*64}
        self.adapter._plan.return_value={'site':'test'};self.adapter.publisher_key='product-key'
        with patch.object(finalize.diagnostic,'inspect_installation'),patch.object(uterctl,'verify',return_value=signed), \
             patch.object(finalize.checkpoint,'read',return_value={'firewall_sha256':'7'*64}), \
             patch.object(finalize,'_attach_running_redis'),patch.object(finalize.start,'read_intent',return_value=original), \
             patch.object(finalize.resume,'read_intent',return_value=base) as read_resume, \
             patch.object(finalize.origin,'read',return_value=self.released), \
             patch.object(finalize.resume,'_current_writer_ids'),patch.object(finalize.resume,'_healthy'), \
             patch.object(finalize.snapshot,'_executor',return_value=executor_hash), \
             patch.object(finalize.snapshot,'_file',return_value=b'{}'),patch.object(uterctl,'site_config',return_value={'backend':'compose'}), \
             patch.object(finalize.resume,'_backup_evidence',return_value='0'*64):
            self.assertEqual(finalize._validate_live(self.adapter,self.record,'executor-key',None),self.released)
            for field in ('start_intent_sha256','bundle_sha256','executor_sha256','backup_receipt_sha256'):
                with self.subTest(field=field):
                    read_resume.return_value=dict(base,**{field:'0'*64 if base[field]!='0'*64 else '1'*64})
                    with self.assertRaises(ValueError):finalize._validate_live(self.adapter,self.record,'executor-key',None)
            read_resume.return_value=base
            uterctl.write(self.home/'state.json',{'current':signed,'pending':{'version':'2'},'adopted_installer':True})
            with self.assertRaises(ValueError):finalize._validate_live(self.adapter,self.record,'executor-key',None)
