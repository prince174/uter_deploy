import unittest
from unittest.mock import patch

from scripts import experimental_kube_fence_ci as experiment


class SyntheticKubernetesFenceTests(unittest.TestCase):
    def test_only_exact_synthetic_shutdown_marker_matches(self):
        self.assertTrue(experiment.marker_valid('abc-123', 'abc-123'))
        for marker, uid in (('missing', 'abc-123'), ('other', 'abc-123'),
                            ('', ''), ('../../unsafe', '../../unsafe'),
                            ('a' * 65, 'a' * 65)):
            self.assertFalse(experiment.marker_valid(marker, uid))

    def test_loopback_template_persists_through_deployment_restarts(self):
        document = experiment.deployment(bind='127.0.0.1')
        template = document['spec']['template']['spec']
        container = template['containers'][0]
        self.assertEqual(document['spec']['strategy'], {'type':'Recreate'})
        self.assertIn('127.0.0.1', container['args'])
        self.assertIn('always', container['args'])
        self.assertEqual(template['volumes'][0]['persistentVolumeClaim']['claimName'], 'synthetic-data')
        self.assertFalse(template['automountServiceAccountToken'])

    def test_hung_case_has_no_shutdown_marker_operation(self):
        spec = experiment.deployment(hanging=True)['spec']['template']['spec']
        self.assertEqual(spec['terminationGracePeriodSeconds'], 5)
        command = spec['containers'][0]['lifecycle']['preStop']['exec']['command']
        self.assertEqual(command[-1], 'sleep 30')

    def test_runner_guard_precedes_all_external_calls(self):
        with patch.dict(experiment.os.environ, {}, clear=True), patch.object(experiment.safe, 'cmd') as command:
            with self.assertRaises(RuntimeError):
                experiment.main()
            command.assert_not_called()

    def test_client_diagnostics_are_bounded_categories_without_raw_output(self):
        self.assertEqual(experiment.client_failure_category(b'FIXTURE_AUTH_FAILED secret'), 'FIXTURE_AUTH_FAILED')
        self.assertEqual(experiment.client_failure_category(b'Error from server: secret'), 'KUBECTL_EXEC_FAILED')
        self.assertEqual(experiment.client_failure_category(b'Traceback: private data'), 'FIXTURE_EXCEPTION')
        self.assertEqual(experiment.client_failure_category(b'private data'), 'NO_FIXED_DIAGNOSTIC')


if __name__ == '__main__':
    unittest.main()
