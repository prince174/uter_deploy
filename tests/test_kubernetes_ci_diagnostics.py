import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from scripts import adopt_backup_ci as ci


class KubernetesCiEvidenceTests(unittest.TestCase):
    def test_categories_never_record_names_messages_or_unknown_reasons(self):
        secret = 'TOKEN_SHOULD_NEVER_BE_PUBLISHED'
        pods = [{'metadata': {'name': secret}, 'spec': {'env': secret}, 'status': {
            'phase': 'Pending', 'message': secret, 'containerStatuses': [
                {'state': {'waiting': {'reason': 'ImagePullBackOff', 'message': secret}}},
                {'state': {'waiting': {'reason': secret}}}]}}]
        pvcs = [{'metadata': {'name': secret}, 'status': {'phase': 'Pending', 'message': secret}}]
        events = [{'type': 'Warning', 'reason': 'FailedScheduling', 'message': secret},
                  {'type': 'Warning', 'reason': secret, 'message': secret},
                  {'type': 'Normal', 'reason': 'Failed', 'message': secret}]
        result = ci.kubernetes_categories(pods, pvcs, events)
        self.assertEqual(result, {'pod_phases': {'Pending': 1},
            'container_waiting': {'ImagePullBackOff': 1, 'Other': 1},
            'pvc_phases': {'Pending': 1}, 'warning_events': {'FailedScheduling': 1, 'Other': 1}})
        self.assertNotIn(secret, json.dumps(result))

    def test_collection_targets_explicit_namespace_and_marks_failed_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            responses = [SimpleNamespace(returncode=0, stdout=b'{"items":[]}'),
                         SimpleNamespace(returncode=1, stdout=b'password-should-not-leak'),
                         SimpleNamespace(returncode=0, stdout=b'{"items":[]}')]
            with patch.object(ci.subprocess, 'run', side_effect=responses) as run:
                ci.collect_kubernetes_categories(['kubectl', '--context', 'test-context'], 'test-namespace', Path(tmp))
            for invocation in run.call_args_list:
                self.assertEqual(invocation.args[0][:5], ['kubectl', '--context', 'test-context', '-n', 'test-namespace'])
            evidence = (Path(tmp)/'kubernetes-categories.json').read_text()
            self.assertEqual(json.loads(evidence)['unavailable'], ['pvc'])
            self.assertNotIn('password-should-not-leak', evidence)

    def test_cleanup_uses_original_project_and_namespace_after_reading_secret_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); home = root/'home'; runtime = home/'runtime'; runtime.mkdir(parents=True)
            (runtime/'redis-password').write_text('redis-sensitive')
            (runtime/'audit-hmac-key').write_text('audit-sensitive')
            calls = []
            def run(args, **kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=0, stdout=b'{"items":[]}', stderr=b'')
            with patch.object(ci.subprocess, 'run', side_effect=run):
                ci.finish_disposable_test(home, root, {'images': {}}, 'compose', ['kubectl', '--context', 'ctx'],
                    'actual-project', 'actual-cluster', 'token', 'auth', True, False)
            compose = [args for args in calls if args[:2] == ['docker', 'compose']]
            self.assertTrue(any('down' in args for args in compose))
            self.assertTrue(all(args[args.index('--project-name')+1] == 'actual-project' for args in compose))
            kube = [args for args in calls if args[0] == 'kubectl']
            self.assertEqual(len(kube), 3)
            self.assertTrue(all(args[args.index('-n')+1] == 'actual-project' for args in kube))
            self.assertIn(['kind', 'delete', 'cluster', '--name', 'actual-cluster'], calls)
            for item in root.glob('*.*'):
                self.assertNotIn('redis-sensitive', item.read_text())
                self.assertNotIn('audit-sensitive', item.read_text())

    def test_cleanup_runs_even_if_collecting_categories_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(ci, 'collect_kubernetes_categories', side_effect=OSError('full disk')), \
                 patch.object(ci.subprocess, 'run') as run:
                with self.assertRaises(OSError):
                    ci.finish_disposable_test(root/'missing-home', root, None, 'kubernetes', ['kubectl'],
                        'test-ns', 'test-cluster', 'token', 'auth', True, True)
            self.assertEqual([call.args[0] for call in run.call_args_list], [
                ['kind', 'delete', 'cluster', '--name', 'test-cluster'],
                ['docker', 'rm', '-f', 'uter-real-llm-ci']])


if __name__ == '__main__':
    unittest.main()
