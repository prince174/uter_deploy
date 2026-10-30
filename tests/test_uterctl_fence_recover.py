import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
import uterctl
from scripts import bundle as builder, compose_nsfirewall_adapter, compose_nsfirewall_protocol, redis_fence_journal as journal
from tests import test_controller as fixtures


def _host_proc_visible():
    try:os.stat('/proc/self/ns/pid');os.stat('/proc/1/ns/pid');return True
    except OSError:return False


@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'), 'requires POSIX private files')
class FenceRecoveryCLITests(unittest.TestCase):
    def setUp(self):
        from scripts import experimental_operation_lock
        namespace=patch.object(experimental_operation_lock,'_host_pid_namespace',return_value=True)
        namespace.start();self.addCleanup(namespace.stop)
        self.fx=fixtures.ControllerTests(methodName='test_signed_bundle')
        self.fx.setUp();self.addCleanup(self.fx.doCleanups)
        self.fx.home.chmod(0o700)
        self.key=self.fx.prepare_adopted()
        self.bundle=self.fx.home/'releases'/'1.0.0'
        self.record=journal.create(self.fx.home,backend='compose',site='uter-test',
                                   resource='a'*64,plan_sha256='b'*64)
        for old,new in (('prepared','isolating'),('isolating','isolated')):
            self.record=journal.advance(self.fx.home,operation=self.record['operation'],expected=old,next_phase=new)
        guard=patch.object(uterctl,'_load_signed_fence_executor')
        guard.start();self.addCleanup(guard.stop)

    def invoke(self):
        return uterctl.main(['fence-recover-redis','--home',str(self.fx.home),
                             '--bundle',str(self.bundle),'--key',str(self.fx.pub),'--backup-key',str(self.key),
                             '--executor-key',str(self.fx.pub)])

    def test_valid_recovery_selects_actual_protocol_under_lock_and_retains_marker(self):
        captured=[]
        def simulate(home,operation,adapter):
            self.assertEqual((home/'operation.lock').read_text(),str(os.getpid()))
            self.assertEqual(operation,self.record['operation'])
            captured.append(adapter)
            journal.advance(home,operation=operation,expected='isolated',next_phase='pre_capture_aborting')
            journal.advance(home,operation=operation,expected='pre_capture_aborting',next_phase='redis_released')
        output=io.StringIO()
        with patch.object(compose_nsfirewall_protocol,'recover_before_capture',side_effect=simulate), \
             patch.object(compose_nsfirewall_adapter.Adapter,'close') as close, \
             patch.object(uterctl,'deploy') as deploy,contextlib.redirect_stdout(output):
            self.invoke()
        self.assertEqual(len(captured),1);close.assert_called_once();deploy.assert_not_called()
        self.assertEqual(journal.read(self.fx.home)['phase'],'redis_released')
        self.assertTrue((self.fx.home/'redis-fence-operation.json').exists())
        self.assertFalse((self.fx.home/'operation.lock').exists())
        self.assertIn('writers remain stopped',output.getvalue())
        self.assertNotIn('kkkk',output.getvalue())

    def test_captured_state_and_stale_lock_never_recover(self):
        journal.advance(self.fx.home,operation=self.record['operation'],expected='isolated',next_phase='capturing')
        with patch.object(compose_nsfirewall_protocol,'recover_before_capture') as recover:
            with self.assertRaisesRegex(ValueError,'^FENCE_RECOVERY_STATE_UNSUPPORTED$'):self.invoke()
            recover.assert_not_called()
        self.assertEqual(journal.read(self.fx.home)['phase'],'capturing')
        (self.fx.home/'operation.lock').write_text('999999',encoding='ascii')
        from scripts import experimental_operation_lock
        with patch.object(compose_nsfirewall_protocol,'recover_before_capture') as recover:
            with self.assertRaisesRegex(experimental_operation_lock.LockError,'^LOCK_ALREADY_PRESENT$'):self.invoke()
            recover.assert_not_called()
        self.assertTrue((self.fx.home/'operation.lock').exists())

    def test_unsigned_wrong_version_and_wrong_installation_are_refused(self):
        m=fixtures.manifest('1.1.0',['1.0.0']);different=self.fx.bundle(m,'different')
        with patch.object(compose_nsfirewall_protocol,'recover_before_capture') as recover:
            with self.assertRaisesRegex(ValueError,'^FENCE_RECOVERY_SIGNED_VERSION_MISMATCH$'):
                uterctl.main(['fence-recover-redis','--home',str(self.fx.home), '--bundle',str(different),
                              '--key',str(self.fx.pub),'--backup-key',str(self.key),'--executor-key',str(self.fx.pub)])
            recover.assert_not_called()
        state=uterctl.read(self.fx.home/'state.json');state['pending']=m;uterctl.write(self.fx.home/'state.json',state)
        with patch.object(compose_nsfirewall_protocol,'recover_before_capture') as recover:
            with self.assertRaisesRegex(ValueError,'^FENCE_RECOVERY_INSTALLATION_UNSUPPORTED$'):self.invoke()
            recover.assert_not_called()

    def test_protocol_failure_never_clears_or_resumes(self):
        with patch.object(compose_nsfirewall_protocol,'recover_before_capture',side_effect=RuntimeError('failure')), \
             patch.object(compose_nsfirewall_adapter.Adapter,'close') as close, \
             patch.object(uterctl,'deploy') as deploy:
            with self.assertRaises(RuntimeError):self.invoke()
        close.assert_called_once();deploy.assert_not_called()
        self.assertEqual(journal.read(self.fx.home)['phase'],'isolated')
        self.assertFalse((self.fx.home/'operation.lock').exists())

    def test_rejects_symlink_secret_or_secret_inside_home(self):
        link=self.fx.root/'linked-key';link.symlink_to(self.key)
        inside=self.fx.home/'key';inside.write_bytes(b'k'*32);inside.chmod(0o600)
        for key in (link,inside):
            with self.subTest(key=key),patch.object(compose_nsfirewall_protocol,'recover_before_capture') as recover:
                with self.assertRaises(ValueError):
                    uterctl.main(['fence-recover-redis','--home',str(self.fx.home),'--bundle',str(self.bundle),
                                  '--key',str(self.fx.pub),'--backup-key',str(key),'--executor-key',str(self.fx.pub)])
                recover.assert_not_called()

    def build_signed_executor(self):
        private=self.fx.root/'executor-private.pem'
        private.write_bytes(self.fx.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
        manifest=dict(fixtures.manifest(),tooling_schema=1)
        source=self.fx.root/'executor-manifest.json';source.write_text(json.dumps(manifest),encoding='utf-8')
        result=self.fx.root/'executor';builder.build(source,result,private)
        return result

    def isolated_invoke(self,executor,*,isolated=True,env=None):
        flags=['-I'] if isolated else []
        return subprocess.run([sys.executable,*flags,'-B',str(executor/'uterctl.py'),'fence-recover-redis',
            '--home',str(self.fx.home),'--bundle',str(self.bundle),'--key',str(self.fx.pub),
            '--backup-key',str(self.key),'--executor-key',str(self.fx.pub)],capture_output=True,text=True,timeout=15,env=env)

    def test_tampered_signed_executor_stops_before_any_recovery(self):
        executor=self.build_signed_executor()
        path=executor/'scripts/compose_nsfirewall_adapter.py'
        path.write_text(path.read_text()+'\n# tampered\n',encoding='utf-8')
        result=self.isolated_invoke(executor)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('inventory mismatch',result.stderr)
        self.assertEqual(journal.read(self.fx.home)['phase'],'isolated')
        self.assertFalse((self.fx.home/'operation.lock').exists())

    @unittest.skipUnless(_host_proc_visible(),'requires access to host PID namespace')
    def test_verified_isolated_executor_loads_only_its_signed_modules(self):
        executor=self.build_signed_executor()
        state=uterctl.read(self.fx.home/'state.json');state['pending']=fixtures.manifest('1.1.0',['1.0.0'])
        uterctl.write(self.fx.home/'state.json',state)
        fake=self.fx.root/'injected';(fake/'scripts').mkdir(parents=True)
        canary=self.fx.root/'injected-ran'
        (fake/'scripts/__init__.py').write_text(f'from pathlib import Path; Path({str(canary)!r}).write_text("bad")')
        env=dict(os.environ,PYTHONPATH=str(fake))
        result=self.isolated_invoke(executor,env=env)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('FENCE_RECOVERY_INSTALLATION_UNSUPPORTED',result.stderr)
        self.assertFalse(canary.exists())
        self.assertEqual(journal.read(self.fx.home)['phase'],'isolated')
        self.assertFalse((self.fx.home/'operation.lock').exists())

    def test_nonisolated_python_cannot_execute_recovery(self):
        executor=self.build_signed_executor()
        result=self.isolated_invoke(executor,isolated=False)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('FENCE_EXECUTOR_ISOLATED_PYTHON_REQUIRED',result.stderr)
        self.assertEqual(journal.read(self.fx.home)['phase'],'isolated')
        self.assertFalse((self.fx.home/'operation.lock').exists())
