import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import uterctl
from scripts import compose_fence_finalize, compose_fence_resume, compose_nsfirewall_adapter, compose_snapshot_only, redis_fence_journal as journal
from tests import test_controller as fixtures


@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'),'requires POSIX private files')
class FenceBackupCLITests(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.ControllerTests(methodName='test_signed_bundle');self.fx.setUp()
        self.addCleanup(self.fx.doCleanups);self.fx.home.chmod(0o700)
        self.key=self.fx.prepare_adopted();self.bundle=self.fx.home/'releases'/'1.0.0'
        self.parent=self.fx.root/'backups';self.parent.mkdir(mode=0o700)
        self.destination=self.parent/'set'
        self.record=journal.create(self.fx.home,backend='compose',site='uter-test',resource='a'*64,plan_sha256='b'*64)
        for old,new in (('prepared','isolating'),('isolating','isolated')):
            self.record=journal.advance(self.fx.home,operation=self.record['operation'],expected=old,next_phase=new)
        guard=patch.object(uterctl,'_load_signed_fence_executor');guard.start();self.addCleanup(guard.stop)

    def invoke(self,dest=None):
        return uterctl.main(['fence-backup-redis','--home',str(self.fx.home),'--bundle',str(self.bundle),
            '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),'--backup-key',str(self.key),
            '--backup-dir',str(self.destination if dest is None else dest)])

    def test_each_fence_command_rejects_dangling_guard_before_mutation(self):
        commands=('fence-recover-redis','fence-backup-redis','fence-start-redis',
                  'fence-recover-snapshot-redis','fence-resume-writers','fence-finalize')
        with patch.object(compose_nsfirewall_adapter.Adapter,'__init__',side_effect=AssertionError('adapter created')):
            for name in (journal.FINALIZE_ANCHOR,journal.UPDATE_INTENT,journal.UPDATE_START,journal.UPDATE_RESULT):
                marker=self.fx.home/name;marker.symlink_to(self.fx.home/'missing')
                for command in commands:
                    with self.subTest(command=command,name=name),self.assertRaisesRegex(ValueError,'^REDIS_FENCE_REQUIRES_INSPECTION$'):
                        uterctl.main([command,'--home',str(self.fx.home),'--bundle',str(self.bundle),
                            '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),'--backup-key',str(self.key),
                            '--backup-dir',str(self.destination)])
                self.assertTrue(marker.is_symlink());marker.unlink()
        self.assertEqual(journal.read(self.fx.home)['phase'],'isolated')

    def test_anchor_is_rechecked_under_lock_before_recovery_record(self):
        for name in (journal.FINALIZE_ANCHOR,journal.UPDATE_INTENT,journal.UPDATE_START,journal.UPDATE_RESULT):
            marker=self.fx.home/name;marker.symlink_to(self.fx.home/'missing')
            with patch.object(uterctl,'verify') as verify:
                with self.assertRaisesRegex(ValueError,'^REDIS_FENCE_REQUIRES_INSPECTION$'):
                    uterctl.recover_compose_redis_before_snapshot(self.fx.home,self.bundle,self.fx.pub,self.key)
            verify.assert_not_called();self.assertFalse((self.fx.home/'operation.lock').exists());marker.unlink()

    def test_real_backend_selected_and_captured_state_retained_under_lock(self):
        def capture(adapter,record,executor,key,destination):
            self.assertEqual((self.fx.home/'operation.lock').read_text(),str(os.getpid()))
            self.assertEqual(record,self.record);self.assertEqual(destination,self.destination)
            journal.advance(self.fx.home,operation=record['operation'],expected='isolated',next_phase='capturing')
            journal.advance(self.fx.home,operation=record['operation'],expected='capturing',next_phase='captured')
            return 'b'*32
        output=io.StringIO()
        with patch.object(compose_nsfirewall_adapter.Adapter,'attach_before_capture_recovery',return_value=True) as attach, \
             patch.object(compose_nsfirewall_adapter.Adapter,'verify_fenced',return_value=True) as fenced, \
             patch.object(compose_nsfirewall_adapter.Adapter,'close') as close, \
             patch.object(compose_snapshot_only,'capture',side_effect=capture) as capture_call, \
             patch.object(uterctl,'deploy') as deploy,contextlib.redirect_stdout(output):
            self.invoke()
        attach.assert_called_once();fenced.assert_called_once();close.assert_called_once();capture_call.assert_called_once()
        deploy.assert_not_called();self.assertEqual(journal.read(self.fx.home)['phase'],'captured')
        self.assertFalse((self.fx.home/'operation.lock').exists())
        self.assertIn('writers remain stopped',output.getvalue())

    def test_snapshot_failure_keeps_journal_and_never_resumes(self):
        def fail(adapter,record,executor,key,destination):
            journal.advance(self.fx.home,operation=record['operation'],expected='isolated',next_phase='capturing')
            raise RuntimeError('snapshot failed')
        with patch.object(compose_nsfirewall_adapter.Adapter,'attach_before_capture_recovery',return_value=True), \
             patch.object(compose_nsfirewall_adapter.Adapter,'verify_fenced',return_value=True), \
             patch.object(compose_nsfirewall_adapter.Adapter,'close') as close, \
             patch.object(compose_snapshot_only,'capture',side_effect=fail),patch.object(uterctl,'deploy') as deploy:
            with self.assertRaisesRegex(RuntimeError,'snapshot failed'):self.invoke()
        close.assert_called_once();deploy.assert_not_called()
        self.assertEqual(journal.read(self.fx.home)['phase'],'capturing')

    def test_bad_or_existing_destination_never_opens_adapter(self):
        unsafe=self.fx.root/'unsafe';unsafe.mkdir(mode=0o755);unsafe.chmod(0o755)
        existing=self.parent/'existing';existing.write_text('keep')
        for dest in (Path('relative'),self.fx.home/'backup',unsafe/'set',existing,self.parent/'..'/'escape'):
            with self.subTest(dest=dest),patch.object(compose_nsfirewall_adapter,'Adapter') as adapter:
                with self.assertRaisesRegex(ValueError,'^FENCE_BACKUP_DESTINATION_INVALID$'):self.invoke(dest)
                adapter.assert_not_called()
        self.assertEqual(existing.read_text(),'keep')
        self.assertEqual(journal.read(self.fx.home)['phase'],'isolated')

    def test_unverified_live_fence_does_not_call_snapshot(self):
        with patch.object(compose_nsfirewall_adapter.Adapter,'attach_before_capture_recovery',return_value=True), \
             patch.object(compose_nsfirewall_adapter.Adapter,'verify_fenced',return_value=False), \
             patch.object(compose_nsfirewall_adapter.Adapter,'close'),patch.object(compose_snapshot_only,'capture') as capture:
            with self.assertRaisesRegex(ValueError,'^FENCE_BACKUP_ISOLATION_UNVERIFIED$'):self.invoke()
        capture.assert_not_called();self.assertEqual(journal.read(self.fx.home)['phase'],'isolated')

    def test_recover_snapshot_uses_signed_scoped_backend_and_retains_marker(self):
        for old,new in (('isolated','capturing'),('capturing','captured')):
            journal.advance(self.fx.home,operation=self.record['operation'],expected=old,next_phase=new)
        self.destination.mkdir(mode=0o700)
        def recover(adapter,executor,key,destination):
            self.assertEqual((self.fx.home/'operation.lock').read_text(),str(os.getpid()))
            self.assertEqual(destination,self.destination)
            journal.advance(self.fx.home,operation=self.record['operation'],expected='captured',next_phase='snapshot_releasing')
            journal.advance(self.fx.home,operation=self.record['operation'],expected='snapshot_releasing',next_phase='redis_released')
            return 'b'*32
        out=io.StringIO()
        with patch.object(compose_snapshot_only,'recover',side_effect=recover) as recover_call, \
             patch.object(compose_nsfirewall_adapter.Adapter,'close') as close, \
             patch.object(uterctl,'deploy') as deploy,contextlib.redirect_stdout(out):
            uterctl.main(['fence-recover-snapshot-redis','--home',str(self.fx.home),'--bundle',str(self.bundle),
                          '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),'--backup-key',str(self.key),
                          '--backup-dir',str(self.destination)])
        recover_call.assert_called_once();close.assert_called_once();deploy.assert_not_called()
        self.assertEqual(journal.read(self.fx.home)['phase'],'redis_released')
        self.assertFalse((self.fx.home/'operation.lock').exists())
        self.assertIn('writers remain stopped',out.getvalue())

    def test_snapshot_recovery_failure_preserves_journal_and_never_restarts(self):
        for old,new in (('isolated','capturing'),('capturing','captured')):
            journal.advance(self.fx.home,operation=self.record['operation'],expected=old,next_phase=new)
        self.destination.mkdir(mode=0o700)
        def fail(adapter,executor,key,destination):
            journal.advance(self.fx.home,operation=self.record['operation'],expected='captured',next_phase='snapshot_releasing')
            raise RuntimeError('unknown result')
        with patch.object(compose_snapshot_only,'recover',side_effect=fail), \
             patch.object(compose_nsfirewall_adapter.Adapter,'close') as close,patch.object(uterctl,'deploy') as deploy:
            with self.assertRaisesRegex(RuntimeError,'unknown result'):
                uterctl.main(['fence-recover-snapshot-redis','--home',str(self.fx.home),'--bundle',str(self.bundle),
                              '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),'--backup-key',str(self.key),
                              '--backup-dir',str(self.destination)])
        close.assert_called_once();deploy.assert_not_called()
        self.assertEqual(journal.read(self.fx.home)['phase'],'snapshot_releasing')

    def test_snapshot_recovery_rejects_nonprivate_or_unfinished_backup(self):
        self.destination.mkdir(mode=0o700)
        with patch.object(compose_snapshot_only,'recover') as recover:
            with self.assertRaisesRegex(ValueError,'^FENCE_RECOVERY_STATE_UNSUPPORTED$'):
                uterctl.main(['fence-recover-snapshot-redis','--home',str(self.fx.home),'--bundle',str(self.bundle),
                              '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),'--backup-key',str(self.key),
                              '--backup-dir',str(self.destination)])
            recover.assert_not_called()
        self.destination.chmod(0o755)
        with patch.object(compose_snapshot_only,'recover') as recover:
            with self.assertRaisesRegex(ValueError,'^FENCE_BACKUP_DESTINATION_INVALID$'):
                uterctl.main(['fence-recover-snapshot-redis','--home',str(self.fx.home),'--bundle',str(self.bundle),
                              '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),'--backup-key',str(self.key),
                              '--backup-dir',str(self.destination)])
            recover.assert_not_called()

    def test_resume_writers_cli_keeps_marker_and_uses_locked_scoped_backend(self):
        for old,new in (('isolated','pre_capture_aborting'),('pre_capture_aborting','redis_released')):
            journal.advance(self.fx.home,operation=self.record['operation'],expected=old,next_phase=new)
        def run(adapter,record,executor,destination):
            self.assertEqual((self.fx.home/'operation.lock').read_text(),str(os.getpid()))
            self.assertIsNone(destination)
            journal.advance(self.fx.home,operation=record['operation'],expected='redis_released',next_phase='writers_resuming')
            journal.advance(self.fx.home,operation=record['operation'],expected='writers_resuming',next_phase='writers_resumed')
        output=io.StringIO()
        with patch.object(compose_fence_resume,'resume',side_effect=run) as run_call, \
             patch.object(compose_nsfirewall_adapter.Adapter,'close') as close, \
             patch.object(uterctl,'deploy') as deploy,contextlib.redirect_stdout(output):
            uterctl.main(['fence-resume-writers','--home',str(self.fx.home),'--bundle',str(self.bundle),
                          '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),'--backup-key',str(self.key)])
        run_call.assert_called_once();close.assert_called_once();deploy.assert_not_called()
        self.assertEqual(journal.read(self.fx.home)['phase'],'writers_resumed')
        self.assertIn('Traffic may have started',output.getvalue())
        self.assertFalse((self.fx.home/'operation.lock').exists())

    def test_resume_writers_cli_refuses_retry_after_uncertain_start(self):
        for old,new in (('isolated','pre_capture_aborting'),('pre_capture_aborting','redis_released'),
                        ('redis_released','writers_resuming')):
            journal.advance(self.fx.home,operation=self.record['operation'],expected=old,next_phase=new)
        with patch.object(compose_fence_resume,'resume') as run_call:
            with self.assertRaisesRegex(ValueError,'^FENCE_RECOVERY_STATE_UNSUPPORTED$'):
                uterctl.main(['fence-resume-writers','--home',str(self.fx.home),'--bundle',str(self.bundle),
                              '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),'--backup-key',str(self.key)])
        run_call.assert_not_called();self.assertEqual(journal.read(self.fx.home)['phase'],'writers_resuming')

    def test_finalize_cli_holds_lock_and_never_deletes_backup(self):
        for old,new in (('isolated','pre_capture_aborting'),('pre_capture_aborting','redis_released'),
                        ('redis_released','writers_resuming'),('writers_resuming','writers_resumed')):
            journal.advance(self.fx.home,operation=self.record['operation'],expected=old,next_phase=new)
        def finish(adapter,record,executor,destination):
            self.assertEqual((self.fx.home/'operation.lock').read_text(),str(os.getpid()))
            self.assertIsNone(destination)
            (self.fx.home/journal.NAME).unlink()
        output=io.StringIO()
        with patch.object(compose_fence_finalize,'finalize',side_effect=finish) as finalized, \
             patch.object(compose_nsfirewall_adapter.Adapter,'close') as close, \
             patch.object(uterctl,'deploy') as deploy,contextlib.redirect_stdout(output):
            uterctl.main(['fence-finalize','--home',str(self.fx.home),'--bundle',str(self.bundle),
                          '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),'--backup-key',str(self.key)])
        finalized.assert_called_once();close.assert_called_once();deploy.assert_not_called()
        self.assertFalse((self.fx.home/journal.NAME).exists());self.assertFalse((self.fx.home/'operation.lock').exists())
        self.assertIn('backup was not restored or deleted',output.getvalue())

    def test_finalize_cli_never_retries_partial_cleanup(self):
        for old,new in (('isolated','pre_capture_aborting'),('pre_capture_aborting','redis_released'),
                        ('redis_released','writers_resuming'),('writers_resuming','writers_resumed'),
                        ('writers_resumed','finalizing')):
            journal.advance(self.fx.home,operation=self.record['operation'],expected=old,next_phase=new)
        with patch.object(compose_fence_finalize,'finalize') as finalized:
            with self.assertRaisesRegex(ValueError,'^FENCE_RECOVERY_STATE_UNSUPPORTED$'):
                uterctl.main(['fence-finalize','--home',str(self.fx.home),'--bundle',str(self.bundle),
                              '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),'--backup-key',str(self.key)])
        finalized.assert_not_called();self.assertEqual(journal.read(self.fx.home)['phase'],'finalizing')
