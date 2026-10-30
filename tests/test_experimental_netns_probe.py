import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock

path = Path(__file__).resolve().parents[1] / 'scripts' / 'experimental_netns_probe.py'
spec = importlib.util.spec_from_file_location('experimental_netns_probe', path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class SyntheticNetnsTests(unittest.TestCase):
    env = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux'}

    def test_guard_blocks_nonhosted_and_overrides(self):
        probe.guard(self.env)
        for field, value in [('GITHUB_ACTIONS', 'false'), ('RUNNER_ENVIRONMENT', 'self-hosted'),
                             ('RUNNER_OS', 'Windows'), ('DOCKER_HOST', 'unix:///tmp/docker.sock'),
                             ('DOCKER_CONTEXT', 'remote')]:
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                probe.guard({**self.env, field: value})

    def test_guard_fails_before_any_command(self):
        with mock.patch.dict(probe.os.environ, {}, clear=True), mock.patch.object(probe, 'cmd') as cmd:
            with self.assertRaises(RuntimeError): probe.main()
            cmd.assert_not_called()

    def test_reject_remote_daemon_before_resource_creation(self):
        with mock.patch.dict(probe.os.environ, self.env, clear=True), \
             mock.patch.object(probe, 'cmd', side_effect=['default', '[{"Endpoints":{"docker":{"Host":"tcp://elsewhere:2375"}}}]']), \
             mock.patch.object(probe, 'docker') as docker:
            with self.assertRaises(RuntimeError): probe.main()
            docker.assert_not_called()

    def test_cleanup_requires_matching_id_and_owner(self):
        ident, owner = 'a' * 64, 'b' * 32
        for kind in ('container', 'network'):
            with self.subTest(kind=kind):
                with mock.patch.object(probe, 'docker', return_value=ident + ' wrong') as docker:
                    with self.assertRaises(RuntimeError): probe.safe_cleanup(kind, ident, owner)
                    self.assertEqual(docker.call_count, 1)
                with mock.patch.object(probe, 'docker', side_effect=[ident + ' ' + owner, '']) as docker:
                    probe.safe_cleanup(kind, ident, owner)
                    self.assertEqual(docker.call_count, 2)

    def test_cleanup_rejects_malformed_id_without_docker(self):
        with mock.patch.object(probe, 'docker') as docker:
            with self.assertRaises(RuntimeError): probe.safe_cleanup('container', 'bad', 'owner')
            docker.assert_not_called()

    def test_image_references_are_pinned(self):
        for image in (probe.REDIS, probe.PYTHON):
            self.assertRegex(image, r'@sha256:[0-9a-f]{64}$')

    def test_captures_outputs_and_has_timeout(self):
        completed = subprocess.CompletedProcess(['x'], 0, b'ok', b'')
        with mock.patch.object(probe.subprocess, 'run', return_value=completed) as run:
            self.assertEqual(probe.cmd(['x']), 'ok')
            self.assertEqual(run.call_args.kwargs['timeout'], probe.TIMEOUT)
            self.assertEqual(run.call_args.kwargs['stdout'], subprocess.PIPE)
            self.assertEqual(run.call_args.kwargs['stderr'], subprocess.PIPE)


if __name__ == '__main__': unittest.main()
