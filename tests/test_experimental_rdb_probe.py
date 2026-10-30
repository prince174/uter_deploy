import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock


path = Path(__file__).resolve().parents[1] / "scripts" / "experimental_rdb_probe.py"
spec = importlib.util.spec_from_file_location("experimental_rdb_probe", path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeHarnessTests(unittest.TestCase):
    def test_valid_corrupt_and_truncated_payloads_are_only_piped(self):
        snapshot = b"REDIS0012" + bytes(range(40))
        calls = []

        def fake(cmd, *, input, stdout, stderr, check, timeout):
            self.assertEqual(cmd, ["probe-binary", "12345"])
            self.assertIs(stdout, subprocess.PIPE)
            self.assertIs(stderr, subprocess.PIPE)
            self.assertFalse(check)
            self.assertEqual(timeout, probe.TIMEOUT_SECONDS)
            calls.append(input)
            return subprocess.CompletedProcess(cmd, (0, 3, 1)[len(calls) - 1], b"", b"")

        probe.verify_probe("probe-binary", snapshot, 12345, execute=fake)
        self.assertEqual(calls[0], snapshot)
        self.assertEqual(calls[1][:-1], snapshot[:-1])
        self.assertNotEqual(calls[1][-1], snapshot[-1])
        self.assertEqual(calls[2], snapshot[:-8])

    def test_unexpected_output_or_exit_status_rejects_experiment(self):
        snapshot = b"REDIS0012" + bytes(range(40))
        for status, output, error in [(1, b"", b""), (0, b"sensitive", b""), (0, b"", b"sensitive")]:
            with self.subTest(status=status, output=bool(output), error=bool(error)):
                def fake(cmd, **kwargs):
                    return subprocess.CompletedProcess(cmd, status, output, error)
                with self.assertRaises(RuntimeError):
                    probe.verify_probe("probe-binary", snapshot, 12345, execute=fake)

    def test_runner_guard_rejects_nonhosted_or_explicit_docker_host(self):
        allowed = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                   "RUNNER_OS": "Linux"}
        probe.runner_guard(allowed)
        probe.runner_guard({**allowed, "DOCKER_CONTEXT": "default"})
        for field, value in (("GITHUB_ACTIONS", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"),
                             ("RUNNER_OS", "Windows"), ("DOCKER_HOST", "unix:///tmp/docker.sock"),
                             ("DOCKER_CONTEXT", "remote")):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                probe.runner_guard({**allowed, field: value})

    def test_main_guard_stops_before_all_docker_calls(self):
        with mock.patch.dict(probe.os.environ, {}, clear=True), mock.patch.object(probe, "run") as run:
            with self.assertRaises(RuntimeError):
                probe.main("binary")
            run.assert_not_called()

    def test_nondefault_context_cannot_run_container(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}
        with mock.patch.dict(probe.os.environ, env, clear=True), mock.patch.object(probe, "run", return_value=b"remote\n") as run:
            with self.assertRaises(RuntimeError):
                probe.main("binary")
            self.assertEqual(run.call_args_list, [mock.call(["docker", "context", "show"])])

    def test_default_context_must_use_local_linux_socket(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}
        remote = b'[{"Endpoints":{"docker":{"Host":"tcp://example:2375"}}}]'
        with mock.patch.dict(probe.os.environ, env, clear=True), \
                mock.patch.object(probe, "run", side_effect=[b"default", remote]) as run:
            with self.assertRaises(RuntimeError):
                probe.main("binary")
            self.assertEqual(run.call_count, 2)

    def test_cleanup_requires_exact_id_and_owner_label(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}
        container = "a" * 64
        owner = "b" * 32
        for inspection, should_remove in ((f"{container} {owner}", True),
                                           (f"{container} wrong", False),
                                           (f"{'c' * 64} {owner}", False)):
            details = b'[{"Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}}}]'
            results = [b"default", details, container.encode(), RuntimeError("stop"), inspection.encode()]
            if should_remove:
                results.append(container.encode())
            with self.subTest(inspection=inspection), mock.patch.dict(probe.os.environ, env, clear=True), \
                    mock.patch.object(probe.uuid, "uuid4", return_value=mock.Mock(hex=owner)), \
                    mock.patch.object(probe, "run", side_effect=results) as run, \
                    mock.patch.object(probe.time, "sleep"):
                # Force the retry loop to terminate immediately with a synthetic exception.
                with mock.patch.object(probe, "range", return_value=range(1), create=True):
                    with self.assertRaises(RuntimeError) as error:
                        probe.main("binary")
                self.assertEqual("cleanup unconfirmed" in str(error.exception), not should_remove)
                if should_remove:
                    self.assertEqual(run.call_args.args[0], ["docker", "--context", "default", "rm", "-f", container])
                else:
                    self.assertFalse(any("rm" in call.args[0] for call in run.call_args_list))

    def test_run_failure_has_unconfirmed_cleanup(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}
        details = b'[{"Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}}}]'
        for result in (subprocess.TimeoutExpired("docker", 50), b"unexpected-id"):
            with self.subTest(result=result), mock.patch.dict(probe.os.environ, env, clear=True), \
                    mock.patch.object(probe, "run", side_effect=[b"default", details, result]):
                with self.assertRaisesRegex(RuntimeError, "cleanup unconfirmed"):
                    probe.main("binary")

    def test_failed_removal_has_unconfirmed_cleanup(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}
        container, owner = "a" * 64, "b" * 32
        details = b'[{"Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}}}]'
        results = [b"default", details, container.encode(), RuntimeError("stop"),
                   f"{container} {owner}".encode(), RuntimeError("rm failed")]
        with mock.patch.dict(probe.os.environ, env, clear=True), \
                mock.patch.object(probe.uuid, "uuid4", return_value=mock.Mock(hex=owner)), \
                mock.patch.object(probe, "run", side_effect=results), \
                mock.patch.object(probe.time, "sleep"), \
                mock.patch.object(probe, "range", return_value=range(1), create=True):
            with self.assertRaisesRegex(RuntimeError, "cleanup unconfirmed"):
                probe.main("binary")

    def test_rejects_unknown_or_short_snapshots_without_execution(self):
        def fail(*args, **kwargs):
            self.fail("probe must not run")
        for snapshot in (b"REDIS0011" + bytes(40), b"REDIS0012short",
                         b"REDIS0012" + bytes(40)):
            with self.assertRaises(RuntimeError):
                probe.verify_probe("probe-binary", snapshot, 12345, execute=fail)


if __name__ == "__main__":
    unittest.main()
