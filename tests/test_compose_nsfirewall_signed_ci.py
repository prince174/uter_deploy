import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import compose_nsfirewall_signed_ci as ci


class SignedNamespaceCITests(unittest.TestCase):
    def test_local_or_nonhosted_cannot_reach_workloads(self):
        for environ in ({}, {'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'self-hosted','RUNNER_OS':'Linux',
                             'UTER_CI_STRICT_RUNNER':'true','BACKEND':'compose'}):
            with self.subTest(environ=environ),mock.patch.dict(os.environ,environ,clear=True), \
                 mock.patch.object(ci.subprocess,'Popen') as process, mock.patch.object(ci.uterctl,'verify') as signed:
                with self.assertRaises(ci.SignedComposeFenceCheckFailure):
                    ci.verify('/unknown','/unknown','/unknown',{})
                process.assert_not_called();signed.assert_not_called()

    def test_writer_timeout_is_blocked_not_false_closed_socket(self):
        self.assertIn("except TimeoutError:print('BLOCKED',flush=True)",ci.CLIENT)
        self.assertIn('except TimeoutError:raise',ci.CLIENT)

    def test_unexpected_error_cannot_disclose_private_data(self):
        with mock.patch.object(ci,'PHASE','GUARD'),mock.patch.object(ci,'_verify',side_effect=ValueError('secret')):
            with self.assertRaisesRegex(ci.SignedComposeFenceCheckFailure,'COMPOSE_SIGNED_CI_GUARD_FAILED') as error:
                ci.verify('/unknown','/unknown','/unknown',{})
            self.assertNotIn('secret',str(error.exception))

    def test_only_exact_known_exception_category_is_exposed(self):
        name='NS_FENCE_CAPABILITIES_UNSUPPORTED'
        for message,expected in ((name,ci.DIAGNOSTICS[name]),(name+' secret','COMPOSE_SIGNED_CI_GUARD_FAILED')):
            with self.subTest(message=message),mock.patch.object(ci,'PHASE','GUARD'), \
                 mock.patch.object(ci,'_verify',side_effect=ci.fence.NamespaceFenceError(message)):
                with self.assertRaises(ci.SignedComposeFenceCheckFailure) as error:
                    ci.verify('/unknown','/unknown','/unknown',{})
                self.assertEqual(str(error.exception),expected)

    def test_start_diagnostic_never_forwards_untrusted_stderr(self):
        valid=b'uterctl: StartError: FENCE_START_WRITER_EXIT_UNVERIFIED\n'
        self.assertEqual(ci._start_diagnostic(valid),ci.START_DIAGNOSTICS['FENCE_START_WRITER_EXIT_UNVERIFIED'])
        detail=b'uterctl: StartError: FENCE_START_RECHECK_PLAN_ENDPOINT_ID\n'
        self.assertEqual(ci._start_diagnostic(detail),ci.START_DIAGNOSTICS['FENCE_START_RECHECK_PLAN_ENDPOINT_ID'])
        for raw in (b'uterctl: StartError: FENCE_START_WRITER_EXIT_UNVERIFIED secret\n',
                    b'uterctl: StartError: FENCE_START_UNKNOWN\n',
                    b'secret\n'+valid,valid+b'secret\n',b'\xff'):
            self.assertIsNone(ci._start_diagnostic(raw))

    @unittest.skipUnless(os.name=='posix','POSIX lock check')
    def test_ci_stale_lock_requires_exact_fixture_and_killed_child_pid(self):
        env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','UTER_CI_STRICT_RUNNER':'true'}
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);home=root/'work'/'fixture';home.mkdir(parents=True)
            lock=home/'operation.lock';lock.write_text('1234');lock.chmod(0o600)
            with mock.patch.object(ci,'ROOT',root),mock.patch.dict(os.environ,env,clear=True):
                with self.assertRaises(ci.SignedComposeFenceCheckFailure):ci._ci_clear_killed_child_lock(home,1235)
                self.assertTrue(lock.exists())
                ci._ci_clear_killed_child_lock(home,1234)
                self.assertFalse(lock.exists())
                lock.symlink_to(root/'victim')
                with self.assertRaises(ci.SignedComposeFenceCheckFailure):ci._ci_clear_killed_child_lock(home,1234)
                self.assertTrue(lock.is_symlink())

    @unittest.skipUnless(os.name=='posix','POSIX child status')
    def test_recovery_timeout_kills_and_reaps_ci_child(self):
        with mock.patch.object(ci.time,'monotonic',side_effect=[0,301]), \
             mock.patch.object(ci.os,'waitpid',side_effect=[(0,0),(1234,9)]) as wait, \
             mock.patch.object(ci.os,'kill') as kill:
            with self.assertRaisesRegex(ci.SignedComposeFenceCheckFailure,'RECOVERY_TIMEOUT'):
                ci._ci_wait_recovery_child(1234)
            kill.assert_called_once_with(1234,ci.signal.SIGKILL)
            self.assertEqual(wait.call_args_list,[mock.call(1234,ci.os.WNOHANG),mock.call(1234,0)])


if __name__=='__main__':unittest.main()
