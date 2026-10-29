import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import scheduled_backup_ci as ci


class ScheduledBackupCITests(unittest.TestCase):
    def test_local_execution_is_rejected_before_resource_access(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}, clear=True), \
                patch.object(ci, 'call') as command:
            with self.assertRaisesRegex(ci.StageError, 'DISPOSABLE_GITHUB_HOSTED_RUNNER_REQUIRED'):
                ci.main()
            command.assert_not_called()
        fixture = Path(__file__).resolve().parent/'fixtures/scheduled_backup_upstream.py'
        env = dict(os.environ, GITHUB_ACTIONS='false')
        result = subprocess.run([sys.executable, str(fixture)], env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'GitHub-hosted', result.stderr)

    def test_mismatched_identity_must_fail_with_expected_category(self):
        class Result:
            returncode = 1
            stderr = b'{"result":"failed","code":"RUNTIME_IDENTITY_MISMATCH"}'
        with patch.object(ci.subprocess, 'run', return_value=Result()):
            ci.rejected_backup(['fake'], {})
        for code, payload in [(0, Result.stderr), (1, b'{"result":"failed","code":"OTHER"}'),
                              (1, b'untrusted text')]:
            result = Result()
            result.returncode, result.stderr = code, payload
            with self.subTest(code=code, payload=payload), patch.object(ci.subprocess, 'run', return_value=result):
                with self.assertRaises(ci.StageError):
                    ci.rejected_backup(['fake'], {})

    def test_compose_workload_count_required(self):
        with patch.object(ci, 'call', return_value=b'id3\nid1\nid2\n'):
            self.assertEqual(ci.workload_ids('compose', 'uter-bk-test', 'unused', {}), ['id1', 'id2', 'id3'])
        with patch.object(ci, 'call', return_value=b'id1\nid2\n'):
            with self.assertRaisesRegex(ci.StageError, 'EXPECTED_THREE_RUNNING_CONTAINERS'):
                ci.workload_ids('compose', 'uter-bk-test', 'unused', {})

    def test_kubernetes_requires_ready_deployments_and_uses_bound_context(self):
        response = json.dumps({'metadata': {'uid': 'deployment-uid'},
                               'spec': {'replicas': 1}, 'status': {'readyReplicas': 1}}).encode()
        with patch.object(ci, 'call', return_value=response) as command:
            self.assertEqual(len(ci.workload_ids('kubernetes', 'uter-bk-test', 'cluster-test', {})), 3)
            self.assertTrue(all(call.args[0][:4] == ['kubectl', '--context', 'kind-cluster-test', '-n']
                                for call in command.call_args_list))
        bad = json.dumps({'metadata': {'uid': 'x'}, 'spec': {'replicas': 1}, 'status': {}}).encode()
        with patch.object(ci, 'call', return_value=bad):
            with self.assertRaisesRegex(ci.StageError, 'EXPECTED_READY_DEPLOYMENT'):
                ci.workload_ids('kubernetes', 'uter-bk-test', 'cluster-test', {})

    def test_audit_continuity_checks_first_entry_and_non_decreasing_length(self):
        before = {'audit_first': 'a'*64, 'audit_lines': 3}
        ci.check_audit_continuity(before, {'audit_first': 'a'*64, 'audit_lines': 4})
        for after in ({'audit_first': 'b'*64, 'audit_lines': 4},
                      {'audit_first': 'a'*64, 'audit_lines': 2},
                      {'audit_first': 'a'*64, 'audit_lines': '4'}):
            with self.subTest(after=after), self.assertRaises(ci.StageError):
                ci.check_audit_continuity(before, after)

    def test_synthetic_data_code_uses_stdin_and_has_no_fixture_credentials(self):
        result = json.dumps({'audit_first': 'a'*64, 'audit_lines': 4}).encode()
        for backend in ('compose', 'kubernetes'):
            for action in ('write', 'verify'):
                with self.subTest(backend=backend, action=action), patch.object(ci, 'call', return_value=result) as command:
                    self.assertEqual(ci.check_data(backend, 'uter-bk-test', 'cluster-test', {}, action)['audit_lines'], 4)
                    args, kwargs = command.call_args
                    self.assertEqual(args[0][-2:], ['python', '-'])
                    code = kwargs['input_data'].decode()
                    compile(code, 'data-fixture', 'exec')
                    self.assertIn('REDIS_PASSWORD_FILE', code)
                    self.assertNotIn('Bearer ', code)
        with self.assertRaises(ValueError):
            ci.check_data('compose', 'uter-bk-test', 'unused', {}, 'delete')

    def test_released_images_are_checked_against_signed_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work, destination = root/'work', root/'private'
            (work/'download').mkdir(parents=True)
            (work/'signed').mkdir()
            destination.mkdir()
            (work/'download/publisher-public.pem').write_bytes(b'fixture key')
            fingerprint = __import__('hashlib').sha256(b'fixture key').hexdigest()
            manifest = {'images': {'guardrail': 'a', 'agent': 'b', 'redis': 'c'}}
            def extract(archive, checksum, output, **kwargs):
                output.mkdir()
                (output/'images.json').write_text(json.dumps(manifest['images']))
            with patch.object(ci, 'PUBLISHER_FINGERPRINT', fingerprint), \
                 patch.object(ci.uterctl, 'verify', return_value=manifest), \
                 patch.object(ci, 'extract_inputs', side_effect=extract) as unpack:
                _, _, _, actual = ci.copy_verified_release(work, destination)
            self.assertEqual(actual, manifest)
            self.assertEqual(unpack.call_count, 1)

    def test_workflow_pins_published_release_and_never_exposes_secrets(self):
        path = Path(__file__).resolve().parents[1]/'.github/workflows/scheduled-backup.yml'
        workflow = path.read_text(encoding='utf-8')
        self.assertIn('backend: [compose, kubernetes]', workflow)
        self.assertIn(ci.PUBLISHER_FINGERPRINT, workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertNotIn('secrets.', workflow)
        self.assertIn('driver/scripts/scheduled_backup_ci.py', workflow)
        self.assertIn('workflow_dispatch:', workflow)


if __name__ == '__main__':
    unittest.main()
