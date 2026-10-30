import subprocess
import unittest
from unittest import mock

from scripts import experimental_rdb_stdin_ci as probe


class StdinChecks(unittest.TestCase):
    def test_pipe_valid_corrupt_and_truncated_without_logging_output(self):
        source = b'REDIS0012' + bytes(range(64))
        seen = []
        def execute(args, **kwargs):
            self.assertEqual(args, ['docker', '--context', 'default', 'exec', '-i',
                                    'a' * 64, 'redis-check-rdb', '/dev/stdin'])
            self.assertIs(kwargs['stdout'], subprocess.DEVNULL)
            self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
            self.assertFalse(kwargs['check'])
            self.assertEqual(kwargs['timeout'], 50)
            seen.append(kwargs['input'])
            return subprocess.CompletedProcess(args, (0, 1, 1)[len(seen) - 1])
        probe.verify_stream('a' * 64, source, execute)
        self.assertEqual(seen[0], source)
        self.assertNotEqual(seen[1], source)
        self.assertEqual(seen[1][:-1], source[:-1])
        self.assertEqual(seen[2], source[:-8])

    def test_invalid_input_never_spawns(self):
        for container, source in [('a', b'REDIS0012' + bytes(64)), ('a' * 64, b'bad')]:
            with self.subTest(container=container), mock.patch.object(probe.subprocess, 'run') as run:
                with self.assertRaises(RuntimeError):
                    probe.verify_stream(container, source, run)
                run.assert_not_called()

    def test_wrong_valid_and_invalid_exit_status_rejected(self):
        source = b'REDIS0012' + bytes(range(64))
        for statuses in ((1,), (0, 0), (0, 1, 0)):
            results = iter(statuses)
            def execute(args, **kwargs):
                return subprocess.CompletedProcess(args, next(results))
            with self.subTest(statuses=statuses), self.assertRaises(RuntimeError):
                probe.verify_stream('a' * 64, source, execute)

    def test_cleanup_requires_exact_resource_ownership(self):
        env = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux'}
        container, owner = 'a' * 64, 'b' * 32
        details = b'[{"Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}}}]'
        for identity, can_remove in ((f'{container} {owner}', True), (f'{container} wrong', False)):
            calls = [b'default', details, container.encode(), RuntimeError('exec failed'), identity.encode()]
            if can_remove:
                calls.append(container.encode())
            with self.subTest(identity=identity), mock.patch.dict(probe.os.environ, env, clear=True), \
                    mock.patch.object(probe.uuid, 'uuid4', return_value=mock.Mock(hex=owner)), \
                    mock.patch.object(probe.shared, 'run', side_effect=calls) as run, \
                    mock.patch('time.sleep'), mock.patch.object(probe, 'range', return_value=range(1), create=True):
                with self.assertRaises(RuntimeError) as error:
                    probe.main()
                self.assertEqual('cleanup unconfirmed' in str(error.exception), not can_remove)
                self.assertEqual(any('rm' in call.args[0] for call in run.call_args_list), can_remove)

    def test_unhosted_stops_before_docker(self):
        with mock.patch.dict(probe.os.environ, {}, clear=True), mock.patch.object(probe.shared, 'run') as run:
            with self.assertRaises(RuntimeError):
                probe.main()
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()


