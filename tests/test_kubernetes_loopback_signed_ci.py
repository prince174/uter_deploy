import contextlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import kubernetes_loopback_signed_ci as experiment


class KubernetesLoopbackTests(unittest.TestCase):
    def test_ci_health_rejects_changed_identity_or_unhealthy_redis(self):
        cluster='7a1ae129-82a8-490f-86e3-84dfd735d330'
        pvc='099ae129-82a8-490f-86e3-84dfd735d330'
        def query(args):
            return {'metadata':{'uid':cluster if 'namespace' in args else pvc}}
        def healthy(command):
            return 'PONG' if command=='ping' else 'aof_enabled:1\naof_last_write_status:ok\n'
        with patch.object(experiment.snapshot,'_query',side_effect=query), \
             patch.object(experiment.snapshot,'verify') as verify:
            experiment._ci_confirm_identity_health(cluster,pvc,{},healthy)
            verify.assert_called_once()
        for case in ('cluster','pvc','ping','aof'):
            def altered_query(args):
                value=query(args)
                if (case=='cluster' and 'namespace' in args) or (case=='pvc' and 'persistentvolumeclaim' in args):
                    value['metadata']['uid']='00000000-0000-0000-0000-000000000000'
                return value
            def altered_redis(command):
                return 'bad' if case==command else healthy(command)
            with self.subTest(case=case),patch.object(experiment.snapshot,'_query',side_effect=altered_query), \
                 patch.object(experiment.snapshot,'verify'):
                with self.assertRaises(experiment.KubernetesLoopbackCIError):
                    experiment._ci_confirm_identity_health(cluster,pvc,{},altered_redis)
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

    def intent_fault(self,home,plan,operation,api):
        self.intent_calls+=1
        if self.intent_calls==1:
            try: api.patch_deployment('test',[])
            except TimeoutError: pass
        raise experiment.loopback_intent.LoopbackIntentError('fault')

    def test_loopback_uses_intent_and_classifies_the_injected_after_success_fault(self):
        patchers=self.patches()
        self.intent_calls=0
        with contextlib.ExitStack() as stack:
            for item in patchers: stack.enter_context(item)
            prepare=stack.enter_context(patch.object(experiment.loopback_intent,'prepare',
                                        return_value={'uid':self.uid,'original_rv':'42'}))
            request=stack.enter_context(patch.object(experiment.loopback_intent,'request',side_effect=self.intent_fault))
            stack.enter_context(patch.object(experiment.loopback_intent,'_reject_existing_attempt',
                                side_effect=experiment.loopback_intent.LoopbackIntentError('attempt')))
            classify=stack.enter_context(patch.object(experiment.loopback_intent,'classify',
                return_value={'state':'loopback_spec_observed','redis_isolated':False,'safe_to_update':False}))
            result=self.request()
        self.assertEqual(result,{'result':'loopback_requested','redis_isolated':False,'safe_to_upgrade':False})
        self.assertEqual(prepare.call_count,1)
        self.assertEqual(request.call_count,2)
        self.api.patch_deployment.assert_called_once()
        self.assertEqual(classify.call_count,1)

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

    def test_unclassifiable_after_success_fault_does_not_remove_finalizer(self):
        patchers=self.patches()
        self.intent_calls=0
        with contextlib.ExitStack() as stack:
            for item in patchers: stack.enter_context(item)
            stack.enter_context(patch.object(experiment.loopback_intent,'prepare',return_value={'uid':self.uid,'original_rv':'42'}))
            stack.enter_context(patch.object(experiment.loopback_intent,'request',side_effect=self.intent_fault))
            stack.enter_context(patch.object(experiment.loopback_intent,'_reject_existing_attempt',
                                side_effect=experiment.loopback_intent.LoopbackIntentError('attempt')))
            stack.enter_context(patch.object(experiment.loopback_intent,'classify',side_effect=ValueError('changed')))
            with self.assertRaises(experiment.KubernetesLoopbackCIError):self.request()
        self.api.patch.assert_not_called()

    def test_fault_before_real_patch_cannot_count_as_after_success(self):
        with contextlib.ExitStack() as stack:
            for item in self.patches(): stack.enter_context(item)
            stack.enter_context(patch.object(experiment.loopback_intent,'prepare',return_value={'uid':self.uid,'original_rv':'42'}))
            stack.enter_context(patch.object(experiment.loopback_intent,'request',
                                side_effect=experiment.loopback_intent.LoopbackIntentError('early')))
            stack.enter_context(patch.object(experiment.loopback_intent,'classify',
                return_value={'state':'loopback_spec_observed','redis_isolated':False,'safe_to_update':False}))
            with self.assertRaisesRegex(experiment.KubernetesLoopbackCIError,'REQUEST_UNCERTAIN'):
                self.request()
        self.api.patch_deployment.assert_not_called()

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

    def test_client_failure_category_is_fixed_and_never_returns_raw_stderr(self):
        for code in ('CI_CLIENT_MISSING_ENV','CI_CLIENT_CONNECT','CI_CLIENT_AUTH','CI_CLIENT_PING'):
            self.assertEqual(experiment._client_failure(('private '+code).encode()),code.removeprefix('CI_'))
        self.assertEqual(experiment._client_failure(b'private details'), 'CLIENT_EXEC')

    def test_probe_policy_selects_only_redis_and_one_random_client_label(self):
        token='b'*32
        policy=experiment._ci_probe_policy(token)
        spec=policy['spec']
        self.assertEqual(spec['podSelector']['matchLabels'],{
            'app.kubernetes.io/instance':experiment.SITE,'app.kubernetes.io/name':'redis'})
        self.assertEqual(spec['ingress'],[{'from':[{'podSelector':{'matchLabels':{'uter.io/ci-redis-probe':token}}}],
                                           'ports':[{'protocol':'TCP','port':6379}]}])
        for bad in ('', 'b'*31, '../foreign', None):
            with self.subTest(bad=bad),self.assertRaises(experiment.KubernetesLoopbackCIError):
                experiment._ci_probe_policy(bad)

    def test_cleanup_uses_server_enforced_uid_precondition(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'work').mkdir()
            observed=[]
            def fake(args,timeout=30):
                if args[0]=='get': return ''
                options=json.loads(Path(args[-1]).read_text())
                observed.append((args,options))
                return '{"kind":"Status","status":"Success"}'
            with patch.object(experiment,'ROOT',root),patch.object(experiment,'_ci_kube_command',side_effect=fake):
                experiment._ci_delete_uid('policy','uter-ci-loopback-policy-'+'a'*16,self.uid)
                experiment._ci_delete_uid('pod','uter-ci-loopback-probe',self.uid)
                for item in ('foreign','../../prod'):
                    with self.assertRaises(experiment.KubernetesLoopbackCIError):
                        experiment._ci_delete_uid('pod',item,self.uid)
            self.assertEqual(len(observed),2)
            for args,options in observed:
                self.assertEqual(options,{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':self.uid}})
                self.assertEqual(args[0],'delete')
                self.assertTrue(args[1].startswith('--raw=/'))

    def test_pod_deletion_response_requires_uid_and_disappearance(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'work').mkdir();name='uter-ci-loopback-probe'
            meta={'name':name,'namespace':experiment.SITE,'uid':self.uid,
                  'deletionTimestamp':'2026-10-30T12:00:00Z'}
            accepted=json.dumps({'kind':'Pod','metadata':meta})
            still_present=json.dumps({'kind':'Pod','metadata':meta})
            with patch.object(experiment,'ROOT',root), \
                 patch.object(experiment,'_ci_kube_command',side_effect=[accepted,still_present,'']), \
                 patch.object(experiment.time,'sleep'):
                experiment._ci_delete_uid('pod',name,self.uid)
            for altered in ({**meta,'uid':'00000000-0000-0000-0000-000000000000'},
                            {**meta,'name':'other'}, {**meta,'namespace':'other'},
                            {**meta,'deletionTimestamp':None}):
                with self.subTest(meta=altered),patch.object(experiment,'ROOT',root), \
                     patch.object(experiment,'_ci_kube_command',return_value=json.dumps({'kind':'Pod','metadata':altered})):
                    with self.assertRaisesRegex(experiment.KubernetesLoopbackCIError,'CLEANUP_UNCERTAIN'):
                        experiment._ci_delete_uid('pod',name,self.uid)
                    self.assertEqual(experiment.PHASE,'DELETE_POD_RESPONSE')
            with patch.object(experiment,'ROOT',root), \
                 patch.object(experiment,'_ci_kube_command',side_effect=[accepted,still_present]), \
                 patch.object(experiment.time,'monotonic',side_effect=[0,91]):
                with self.assertRaisesRegex(experiment.KubernetesLoopbackCIError,'CLEANUP_UNCERTAIN'):
                    experiment._ci_delete_uid('pod',name,self.uid)
                self.assertEqual(experiment.PHASE,'DELETE_POD_VERIFY_TIMEOUT')

    def test_ci_delete_empty_list_is_only_diagnosed_not_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'work').mkdir()
            success='{"kind":"Status","status":"Success"}'
            empty='{"apiVersion":"v1","kind":"List","items":[]}'
            with patch.object(experiment,'ROOT',root), \
                 patch.object(experiment,'_ci_kube_command',side_effect=[success,empty]):
                with self.assertRaises(experiment.KubernetesLoopbackCIError):
                    experiment._ci_delete_uid('pod','uter-ci-loopback-probe',self.uid)
            self.assertEqual(experiment.PHASE,'DELETE_POD_VERIFY_EMPTY_LIST')

    def test_ci_delete_verify_emits_only_fixed_get_or_format_categories(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'work').mkdir()
            success='{"kind":"Status","status":"Success"}'
            for result,category in ((ValueError('sensitive detail'),'DELETE_POD_VERIFY_GET'),
                                    ('not json','DELETE_POD_VERIFY_FORMAT'),
                                    ('{"metadata":{"name":"other"}}','DELETE_POD_VERIFY_FORMAT'),
                                    (json.dumps({'kind':'ConfigMap','metadata':{'name':'uter-ci-loopback-probe',
                                      'namespace':experiment.SITE,'uid':'099ae129-82a8-490f-86e3-84dfd735d330'}}),
                                     'DELETE_POD_VERIFY_FORMAT')):
                with self.subTest(category=category),patch.object(experiment,'ROOT',root), \
                     patch.object(experiment,'_ci_kube_command',side_effect=[success,result]):
                    with self.assertRaises(experiment.KubernetesLoopbackCIError) as error:
                        experiment._ci_delete_uid('pod','uter-ci-loopback-probe',self.uid)
                    self.assertEqual(experiment.PHASE,category)
                    self.assertEqual(str(error.exception),'KUBE_LOOPBACK_CI_CLEANUP_UNCERTAIN')

    def test_cleanup_failure_categories_are_fixed_and_do_not_expose_response(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'work').mkdir()
            for kind,name,output,stage in (
                ('policy','uter-ci-loopback-policy-'+'a'*16,ValueError('secret'), 'DELETE_POLICY_COMMAND'),
                ('policy','uter-ci-loopback-policy-'+'a'*16,'{"private":"secret"}', 'DELETE_POLICY_RESPONSE'),
                ('pod','uter-ci-loopback-probe',ValueError('secret'), 'DELETE_POD_COMMAND'),
                ('pod','uter-ci-loopback-probe','not-json-secret', 'DELETE_POD_RESPONSE')):
                with self.subTest(stage=stage),patch.object(experiment,'ROOT',root), \
                     patch.object(experiment,'_ci_kube_command',side_effect=output if isinstance(output,Exception) else None,
                                  return_value=output):
                    with self.assertRaisesRegex(experiment.KubernetesLoopbackCIError,'CLEANUP_UNCERTAIN') as error:
                        experiment._ci_delete_uid(kind,name,self.uid)
                    self.assertEqual(experiment.PHASE,stage)
                    self.assertNotIn('secret',str(error.exception))


if __name__=='__main__':unittest.main()
