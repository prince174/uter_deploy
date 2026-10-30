import unittest
import copy
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
        self.assertIn({'name':'SYNTHETIC_BIND','value':'127.0.0.1'}, container['env'])
        self.assertIn('--appendfsync always', container['args'][0])
        self.assertIn('if wait "$child"', container['args'][0])
        self.assertIn('intent-$POD_UID', container['args'][0])
        self.assertIn('marker-$POD_UID', container['args'][0])
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

    def test_original_fixture_runs_redis_as_pid_one_without_supervisor(self):
        original=experiment.original_deployment()
        container=original['spec']['template']['spec']['containers'][0]
        self.assertEqual(container['command'],['sh','-ec'])
        self.assertTrue(container['args'][0].startswith('exec redis-server --appendonly yes'))
        self.assertNotIn('lifecycle',container)
        self.assertIn('--bind 127.0.0.1',experiment.original_deployment('127.0.0.1')
                      ['spec']['template']['spec']['containers'][0]['args'][0])
        with self.assertRaises(ValueError): experiment.original_deployment('::')

    def test_original_termination_requires_exact_clean_process_and_is_never_accepted_if_forced(self):
        pod={'metadata':{'uid':'pod-1','deletionTimestamp':'now'},
             'status':{'containerStatuses':[{'name':'redis','containerID':'containerd://original',
                 'restartCount':0,'state':{'terminated':{'exitCode':0,'signal':0,'reason':'Completed'}}}]}}
        check=lambda item,forced=False: experiment.termination_observed(item,'pod-1','containerd://original',forced=forced)
        self.assertTrue(check(pod));self.assertFalse(check(pod,forced=True))
        cases=[]
        for target,key,value in ((('metadata',),'uid','other'),(('metadata',),'deletionTimestamp',None),
                                 (('status','containerStatuses',0),'containerID','other'),
                                 (('status','containerStatuses',0),'restartCount',1),
                                 (('status','containerStatuses',0,'state','terminated'),'exitCode',137),
                                 (('status','containerStatuses',0,'state','terminated'),'signal',9),
                                 (('status','containerStatuses',0,'state','terminated'),'reason','OOMKilled')):
            altered=copy.deepcopy(pod);node=altered
            for component in target: node=node[component]
            node[key]=value;cases.append(altered)
        for item in cases:
            with self.subTest(item=item):self.assertFalse(check(item))
        self.assertFalse(check(None))


if __name__ == '__main__':
    unittest.main()
