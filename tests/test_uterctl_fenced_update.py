import contextlib
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import uterctl
from scripts import compose_fenced_update as update
from scripts import redis_fence_journal as journal
from tests import test_controller as fixtures


@unittest.skipUnless(os.name=='posix','POSIX installation lock')
class FencedUpdateCLITests(unittest.TestCase):
    def setUp(self):
        from scripts import experimental_operation_lock
        namespace=patch.object(experimental_operation_lock,'_host_pid_namespace',return_value=True)
        namespace.start();self.addCleanup(namespace.stop)
        self.fx=fixtures.ControllerTests(methodName='test_signed_bundle');self.fx.setUp();self.addCleanup(self.fx.doCleanups)
        self.fx.home.chmod(0o700);self.key=self.fx.prepare_adopted();self.source=self.fx.home/'releases'/'1.0.0'
        self.target=self.fx.bundle(fixtures.manifest('1.1.0',['1.0.0']),'target')
        self.parent=self.fx.root/'backup-parent';self.parent.mkdir(mode=0o700);self.destination=self.parent/'set'
        self.old=fixtures.manifest();self.new=fixtures.manifest('1.1.0',['1.0.0'])

    def test_cli_authenticates_executor_before_dispatch(self):
        with patch.object(uterctl,'_load_signed_fence_executor',side_effect=ValueError('executor refused')), \
             patch.object(uterctl,'apply_compose_fenced_update') as apply:
            with self.assertRaisesRegex(ValueError,'executor refused'):
                uterctl.main(['apply','--fenced-update','--home',str(self.fx.home),'--bundle',str(self.target),
                              '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),
                              '--backup-key',str(self.key),'--backup-dir',str(self.destination)])
        apply.assert_not_called()

    def test_pipeline_order_under_lock_and_no_ordinary_deploy(self):
        events=[]
        def record(name,result=None):
            def run(*args,**kwargs):
                self.assertEqual((self.fx.home/'operation.lock').read_text(),str(os.getpid()))
                events.append(name);return result
            return run
        with patch.object(update,'preflight',side_effect=record('preflight',(self.old,self.new))), \
             patch.object(update,'stage_target',side_effect=record('stage',self.target)), \
             patch.object(update,'pull_writers',side_effect=record('pull')), \
             patch.object(update,'capture_for_update',side_effect=record('capture')), \
             patch.object(update,'release_for_update',side_effect=record('release')), \
             patch.object(update,'start_target',side_effect=record('start')), \
             patch.object(update,'finalize_target',side_effect=record('finalize',self.new)), \
             patch.object(uterctl,'deploy') as ordinary,contextlib.redirect_stdout(io.StringIO()):
            uterctl.apply_compose_fenced_update(self.fx.home,self.target,self.fx.pub,self.fx.pub,self.key,self.destination)
        self.assertEqual(events,['preflight','stage','preflight','pull','capture','release','start','finalize'])
        ordinary.assert_not_called();self.assertFalse((self.fx.home/'operation.lock').exists())

    def test_capture_failure_does_not_release_or_start(self):
        with patch.object(update,'preflight',return_value=(self.old,self.new)), \
             patch.object(update,'stage_target',return_value=self.target), \
             patch.object(update,'capture_for_update',side_effect=ValueError('refused')), \
             patch.object(update,'release_for_update') as release,patch.object(update,'start_target') as start:
            with self.assertRaisesRegex(ValueError,'refused'):
                uterctl.apply_compose_fenced_update(self.fx.home,self.target,self.fx.pub,self.fx.pub,self.key,self.destination,offline=True)
        release.assert_not_called();start.assert_not_called()

    def test_finish_refuses_unknown_target_start_without_mutating(self):
        self.destination.mkdir(mode=0o700)
        record=journal.create(self.fx.home,backend='compose',site='uter-test',resource='a'*64,plan_sha256='b'*64)
        for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','capturing'),('capturing','captured'),
                        ('captured','snapshot_releasing'),('snapshot_releasing','redis_released'),('redis_released','target_starting')):
            record=journal.advance(self.fx.home,operation=record['operation'],expected=old,next_phase=new)
        with patch.object(update,'finalize_target') as finalize,patch.object(uterctl,'verify') as verify:
            with self.assertRaisesRegex(ValueError,'^FENCED_UPDATE_RECOVERY_REQUIRES_INSPECTION$'):
                uterctl.finish_compose_fenced_update(self.fx.home,self.target,self.fx.pub,self.fx.pub,self.key,self.destination)
        verify.assert_not_called();finalize.assert_not_called()
        self.assertEqual(journal.read(self.fx.home)['phase'],'target_starting')

    def test_finish_requires_signed_executor_before_any_recovery(self):
        with patch.object(uterctl,'_load_signed_fence_executor',side_effect=ValueError('executor refused')), \
             patch.object(uterctl,'finish_compose_fenced_update') as finish:
            with self.assertRaisesRegex(ValueError,'executor refused'):
                uterctl.main(['fence-finish-update','--home',str(self.fx.home),'--bundle',str(self.target),
                              '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),
                              '--backup-key',str(self.key),'--backup-dir',str(self.destination)])
        finish.assert_not_called()

    def test_fenced_commands_reject_relative_trust_paths_before_executor_load(self):
        for command in ('apply','fence-finish-update'):
            for option in ('--home','--bundle','--key','--executor-key'):
                values={'--home':str(self.fx.home),'--bundle':str(self.target),
                        '--key':str(self.fx.pub),'--executor-key':str(self.fx.pub)}
                values[option]='relative-path'
                argv=[command]+(['--fenced-update'] if command=='apply' else [])
                for name,value in values.items():argv.extend((name,value))
                with self.subTest(command=command,option=option),patch.object(uterctl,'_load_signed_fence_executor') as load:
                    with self.assertRaisesRegex(ValueError,'^FENCED_UPDATE_PATH_NOT_ABSOLUTE$'):
                        uterctl.main(argv)
                    load.assert_not_called()

    def test_finish_routes_sealed_cleanup_even_if_journal_already_unlinked(self):
        self.destination.mkdir(mode=0o700)
        (self.fx.home/journal.CLEANUP_INTENT).write_text('fixture')
        with patch.object(update,'finish_sealed_cleanup',return_value=self.new) as finish, \
             patch.object(journal,'read',side_effect=AssertionError('journal is absent')), \
             contextlib.redirect_stdout(io.StringIO()):
            uterctl.finish_compose_fenced_update(self.fx.home,self.target,self.fx.pub,self.fx.pub,self.key,self.destination)
        finish.assert_called_once();self.assertFalse((self.fx.home/'operation.lock').exists())

    def test_finish_never_prints_success_when_lease_release_fails(self):
        self.destination.mkdir(mode=0o700);(self.fx.home/journal.CLEANUP_INTENT).write_text('fixture')
        @contextlib.contextmanager
        def broken_lease(*args,**kwargs):
            yield
            raise ValueError('lease release uncertain')
        output=io.StringIO()
        with patch.object(uterctl,'fenced_locked',side_effect=broken_lease), \
             patch.object(update,'finish_sealed_cleanup',return_value=self.new),contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(ValueError,'lease release uncertain'):
                uterctl.finish_compose_fenced_update(self.fx.home,self.target,self.fx.pub,self.fx.pub,self.key,self.destination)
        self.assertNotIn('finalized',output.getvalue())

    def test_finish_reclaims_real_dead_managed_owner_only_after_double_proof(self):
        self.destination.mkdir(mode=0o700);(self.fx.home/journal.CLEANUP_INTENT).write_text('fixture')
        code=('import sys,time;from scripts import managed_operation_lock as m;'
              'm.primitive._host_pid_namespace=lambda:True;'
              'ctx=m.locked(sys.argv[1]);ctx.__enter__();print("READY",flush=True);time.sleep(300)')
        child=subprocess.Popen([sys.executable,'-c',code,str(self.fx.home)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        self.addCleanup(lambda:child.poll() is None and child.kill())
        self.addCleanup(child.stdout.close)
        self.assertEqual(child.stdout.readline().strip(),'READY')
        os.kill(child.pid,signal.SIGKILL);child.wait(timeout=10)
        with patch.object(update,'verify_reclaimable_finish') as proof, \
             patch.object(update,'finish_sealed_cleanup',return_value=self.new) as finish, \
             contextlib.redirect_stdout(io.StringIO()):
            uterctl.finish_compose_fenced_update(self.fx.home,self.target,self.fx.pub,self.fx.pub,self.key,self.destination)
        self.assertEqual(proof.call_count,2);finish.assert_called_once()
        self.assertFalse((self.fx.home/'operation.lock').exists())


if __name__=='__main__':unittest.main()
