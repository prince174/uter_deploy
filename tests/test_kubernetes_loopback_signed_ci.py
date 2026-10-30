import json
import os
import unittest
from unittest.mock import Mock, patch

from scripts import kubernetes_loopback_signed_ci as experiment


class KubernetesLoopbackTests(unittest.TestCase):
    def setUp(self):
        self.uid='11111111-1111-1111-1111-111111111111'
        self.operation='a'*32
        self.plan={'pod':'redis-pod'}
        self.api=Mock(context=experiment.CONTEXT,namespace=experiment.SITE)
        self.deployment={'metadata':{'name':experiment.DEPLOYMENT,'namespace':experiment.SITE,
                                     'uid':self.uid,'resourceVersion':'42'},'spec':{'replicas':1}}
        self.reads=[{'spec':{'replicas':0}},{'items':[]},{'spec':{'replicas':0}},{'items':[]},self.deployment]

    def request(self):
        return experiment.request_loopback('/fixture','/bundle','/key',self.plan,self.operation,self.api,{'schema':1})

    def patches(self):
        return (patch.object(experiment,'guard'),patch.object(experiment.finalizer,'_validate_plan'),
                patch.object(experiment.finalizer,'_check_journal'),patch.object(experiment.finalizer,'_verify_live'),
                patch.object(experiment.snapshot,'verify'),patch.object(experiment.snapshot,'_query',side_effect=self.reads))

    def test_loopback_patch_checks_uid_version_and_original_command(self):
        patchers=self.patches()
        with patchers[0],patchers[1],patchers[2],patchers[3],patchers[4],patchers[5]:
            result=self.request()
        self.assertEqual(result,{'result':'loopback_requested','redis_isolated':False,'safe_to_upgrade':False})
        args=self.api._call.call_args.args[0]
        self.assertEqual(args[:3],['--request-timeout=20s','patch','deployment/'+experiment.DEPLOYMENT])
        operations=json.loads(args[-1]);tests={x['path']:x['value'] for x in operations if x['op']=='test'}
        self.assertEqual(tests['/metadata/uid'],self.uid)
        self.assertEqual(tests['/metadata/resourceVersion'],'42')
        self.assertEqual(tests['/spec/template/spec/containers/0/args'],[experiment.identity.COMMAND])
        self.assertEqual(operations[-1]['value'],[experiment.LOOPBACK_COMMAND])

    def test_running_writers_or_ambiguous_api_fails_without_patch(self):
        for change in ('replicas','pods','guard'):
            with self.subTest(change=change):
                self.setUp()
                if change=='replicas': self.reads[0]['spec']['replicas']=1
                if change=='pods': self.reads[1]['items']=[{'metadata':{'name':'still-running'}}]
                patchers=list(self.patches())
                if change=='guard': patchers[0]=patch.object(experiment,'guard',side_effect=ValueError('private'))
                with patchers[0],patchers[1],patchers[2],patchers[3],patchers[4],patchers[5]:
                    with self.assertRaisesRegex(experiment.KubernetesLoopbackCIError,'^KUBE_LOOPBACK_CI_REQUEST_UNCERTAIN$'):
                        self.request()
                self.api._call.assert_not_called()

    def test_patch_timeout_does_not_remove_finalizer_or_advance_journal(self):
        self.api._call.side_effect=TimeoutError('potentially accepted')
        patchers=self.patches()
        with patchers[0],patchers[1] as valid,patchers[2] as check,patchers[3],patchers[4],patchers[5]:
            with self.assertRaises(experiment.KubernetesLoopbackCIError):self.request()
        self.assertEqual(self.api._call.call_count,1)
        self.assertEqual(check.call_args.args[-1],'isolating')
        self.api.patch.assert_not_called()

    def test_bad_resource_versions_are_rejected_before_patch(self):
        for version in ('', '-1', 'abc', 1, None):
            with self.subTest(version=version),self.assertRaises(experiment.KubernetesLoopbackCIError):
                experiment.deployment_patch(self.uid,version)

    def test_guard_rejects_non_ci_before_any_runtime_query(self):
        with patch.dict(os.environ,{},clear=True), \
             patch.object(experiment.adopt_backup_ci,'runner_guard',side_effect=ValueError('not CI')), \
             patch.object(experiment.snapshot,'verify') as snapshot, \
             patch.object(experiment.uterctl,'verify') as verify:
            with self.assertRaisesRegex(experiment.KubernetesLoopbackCIError,'^KUBE_LOOPBACK_CI_UNVERIFIED$'):
                experiment.verify('/not-a-home','/not-a-bundle','/not-a-key',{})
            snapshot.assert_not_called();verify.assert_not_called()

    def test_verify_sanitizes_uncertain_error(self):
        with patch.object(experiment,'_verify',side_effect=ValueError('secret content')):
            with self.assertRaisesRegex(experiment.KubernetesLoopbackCIError,'^KUBE_LOOPBACK_CI_UNVERIFIED$') as error:
                experiment.verify('/fixture','/bundle','/key',{})
        self.assertNotIn('secret',str(error.exception))

    def test_ci_kubectl_bounds_watches_and_keeps_request_window(self):
        env={'UTER_CI_STRICT_RUNNER':'true','UTER_CI_VERIFY_KUBE_LOOPBACK':'true','BACKEND':'kubernetes'}
        with patch.dict(os.environ,env,clear=True),patch.object(experiment.adopt_backup_ci,'runner_guard'), \
             patch.object(experiment.install_recovery,'run_readonly',return_value='synthetic\n') as run:
            self.assertEqual(experiment._ci_kube_command(['get','pods']), 'synthetic')
            self.assertIn('--request-timeout=20s',run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs['timeout'],30)
            self.assertEqual(experiment._ci_kube_command(['rollout','status','deployment/x','--timeout=180s'],timeout=210),'synthetic')
            self.assertIn('--request-timeout=0',run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs['timeout'],210)
            self.assertEqual(experiment._ci_kube_command(['rollout','status','deployment/x','--timeout=300s'],timeout=330),'synthetic')
            self.assertEqual(run.call_args.kwargs['timeout'],330)
        with self.assertRaisesRegex(experiment.KubernetesLoopbackCIError,'KUBE_LOOPBACK_CI_ARGUMENT'):
            experiment._ci_kube_command(['get','pods'],timeout=999)

    def test_ci_kubectl_runner_errors_are_sanitized(self):
        env={'UTER_CI_STRICT_RUNNER':'true','UTER_CI_VERIFY_KUBE_LOOPBACK':'true','BACKEND':'kubernetes'}
        with patch.dict(os.environ,env,clear=True),patch.object(experiment.adopt_backup_ci,'runner_guard'), \
             patch.object(experiment.install_recovery,'run_readonly',side_effect=ValueError('secret details')):
            with self.assertRaisesRegex(experiment.KubernetesLoopbackCIError,'^KUBE_LOOPBACK_CI_COMMAND$') as error:
                experiment._ci_kube_command(['get','pods'])
            self.assertNotIn('secret',str(error.exception))


if __name__=='__main__':unittest.main()
