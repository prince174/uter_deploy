import os
import unittest
from unittest.mock import patch

from scripts import kubernetes_redis_identity_ci as ci


class KubernetesIdentityCITests(unittest.TestCase):
    def setUp(self):
        self.env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux',
                  'BACKEND':'kubernetes','UTER_CI_STRICT_RUNNER':'true'}

    def test_guard_prevents_runtime_access_on_other_hosts(self):
        for bad in ({},{**self.env,'RUNNER_ENVIRONMENT':'self-hosted'},
                    {**self.env,'DOCKER_HOST':'tcp://remote'}, {**self.env,'BACKEND':'compose'}):
            with self.subTest(bad=bad), patch.dict(os.environ,bad,clear=True), patch.object(ci,'_query') as query:
                with self.assertRaisesRegex(ci.IdentityCheckFailure,'RUNNER_REQUIRED'):
                    ci.verify({})
                query.assert_not_called()

    def test_queries_only_expected_resources_and_never_read_secrets(self):
        owner=ci.SITE+'-redis-ab123'
        outputs=[{'metadata':{'uid':'11111111-1111-1111-1111-111111111111'}}, {'metadata':{}},
                 {'items':[{'metadata':{'ownerReferences':[{'kind':'ReplicaSet','name':owner,'controller':True}]}}]},
                 {'metadata':{}}, {'metadata':{'uid':'22222222-2222-2222-2222-222222222222'}}]
        safe={'result':'matching_snapshot_observed','redis_isolated':False,'cluster_authenticated':False,
              'writers_excluded':False,'safe_to_upgrade':False}
        with patch.dict(os.environ,self.env,clear=True), patch.object(ci,'_query',side_effect=outputs) as query, \
             patch.object(ci.identity,'verify_snapshot',return_value=safe) as verify:
            ci.verify({'images':{'redis':'synthetic'}})
        self.assertEqual(query.call_count,5)
        for call in query.call_args_list:
            self.assertNotIn('secret', ' '.join(call.args[0]).lower())
        self.assertEqual(verify.call_args.kwargs['expected_pvc_uid'],'22222222-2222-2222-2222-222222222222')

    def test_rejects_ambiguous_pods_or_attempted_authorization(self):
        outputs=[{'metadata':{'uid':'uid'}}, {'metadata':{}}, {'items':[]}]
        with patch.dict(os.environ,self.env,clear=True), patch.object(ci,'_query',side_effect=outputs):
            with self.assertRaisesRegex(ci.IdentityCheckFailure,'UNVERIFIED'): ci.verify({})

    def test_queries_use_bounded_readonly_runner_and_fixed_errors(self):
        with patch.object(ci.install_recovery,'run_readonly',return_value='{"items": []}') as run:
            self.assertEqual(ci._query(['get','pods']), {'items':[]})
        self.assertEqual(run.call_args.kwargs['timeout'],30)
        with patch.object(ci.install_recovery,'run_readonly',side_effect=ValueError('secret')):
            with self.assertRaisesRegex(ci.IdentityCheckFailure,'^KUBE_IDENTITY_CI_QUERY_FAILED$') as error:
                ci._query(['get','pods'])
            self.assertNotIn('secret',str(error.exception))


if __name__=='__main__': unittest.main()
