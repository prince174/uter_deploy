import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

if sys.platform.startswith('linux'):
    from scripts import experimental_operation_lock_ci as probe
else:
    probe=None


@unittest.skipUnless(sys.platform.startswith('linux'),'Linux process semantics required')
class ExperimentalOperationLockCITests(unittest.TestCase):
    def test_untrusted_environment_stops_before_creating_fixture(self):
        with mock.patch.dict(os.environ,{},clear=True), \
             mock.patch.object(probe.tempfile,'TemporaryDirectory') as directory:
            with self.assertRaisesRegex(probe.ProbeError,'CI_GUARD'):probe.run()
            directory.assert_not_called()

    def test_legacy_probe_never_removes_a_foreign_sentinel(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);path=home/probe.lock.SENTINEL
            path.write_text('other')
            self.assertFalse(probe.legacy_attempt(home))
            self.assertEqual(path.read_text(),'other')
            path.unlink();self.assertTrue(probe.legacy_attempt(home));self.assertTrue(path.exists())

    def test_host_namespace_guard_rejects_nested_pid_numbers(self):
        env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux',
             'UTER_CI_STRICT_RUNNER':'true'}
        def contents(path,*args,**kwargs):
            return 'systemd\n' if str(path)=='/proc/1/comm' else 'NSpid:\t123\t1\n'
        with mock.patch.dict(os.environ,env,clear=True),mock.patch.object(probe.os,'geteuid',return_value=0), \
             mock.patch.object(probe.lock,'_host_pid_namespace',return_value=True), \
             mock.patch.object(Path,'read_text',contents):
            with self.assertRaisesRegex(probe.ProbeError,'PID_NAMESPACE_UNVERIFIED'):
                probe.require_hosted_environment()

    def test_private_fixture_exercises_actual_child_death_and_reclaim(self):
        # Unit exercise uses actual Linux processes and a private temp directory;
        # only its host-identity precondition is mocked for unprivileged WSL.
        with mock.patch.object(probe,'require_hosted_environment'), \
             mock.patch.object(probe.lock,'_host_pid_namespace',return_value=True):
            probe.run()


if __name__=='__main__':unittest.main()
