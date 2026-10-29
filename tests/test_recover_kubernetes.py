import os
import unittest
from unittest.mock import patch
from scripts import recover_kubernetes, recovery_kube_volumes


class KubernetesRecoveryTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix','Linux runtime required')
    def test_refuses_invalid_name_before_cluster_access(self):
        with patch.object(recover_kubernetes,'run') as run:
            with self.assertRaisesRegex(ValueError,'namespace name'):
                recover_kubernetes.restore('/old','/backup','/key','/pub','/new','../bad','context',18001)
            run.assert_not_called()

    def test_maps_secrets_configmaps_and_pvc_sizes(self):
        values={'guardrailSecret':'old-g','agentSecret':'old-a','redisSecret':'old-r',
                'policyConfigMap':'old-p','profileConfigMap':'old-m','imagePullSecrets':[{'name':'old-reg'}]}
        mapping=recover_kubernetes.resource_mapping(values,'new-test')
        items=[]
        for name in mapping:
            kind='ConfigMap' if name in ('old-p','old-m') else 'Secret'
            data={'key':'value'}
            if name=='old-p': data['upstream-ca.pem']='public-ca-content'
            if name=='old-g': data['SSL_CERT_FILE']='/app/policies/upstream-ca.pem'
            items.append({'kind':kind,'metadata':{'name':name,'resourceVersion':'sensitive-metadata'},'data':data})
        for suffix,size in (('redis','2Gi'),('guardrail','10Gi')):
            items.append({'kind':'PersistentVolumeClaim','metadata':{'name':'old-'+suffix},
                          'spec':{'resources':{'requests':{'storage':size}}}})
        objects,sizes=recover_kubernetes.prepare_objects(items,mapping,'old','new-test')
        self.assertEqual(sizes,{'redis':'2Gi','audit':'10Gi'})
        self.assertEqual(len(objects),6)
        self.assertTrue(all(x['metadata']['namespace']=='new-test' for x in objects))
        self.assertTrue(all('resourceVersion' not in x['metadata'] for x in objects))
        self.assertEqual(values['guardrailSecret'],'new-test-guardrail-env')
        self.assertEqual(values['imagePullSecrets'],[{'name':'new-test-registry-0'}])
        restored_policy=next(x for x in objects if x['metadata']['name']=='new-test-policies')
        restored_guard=next(x for x in objects if x['metadata']['name']=='new-test-guardrail-env')
        self.assertEqual(restored_policy['data']['upstream-ca.pem'],'public-ca-content')
        self.assertEqual(restored_guard['data']['SSL_CERT_FILE'],'/app/policies/upstream-ca.pem')

    def test_missing_secret_refuses_recovery(self):
        with self.assertRaisesRegex(ValueError,'Incomplete Kubernetes recovery resources'):
            recover_kubernetes.prepare_objects([],{'old-secret':'new-secret'},'old','new-test')

    def test_volume_recovery_rejects_invalid_identity_before_cluster_access(self):
        with patch.object(recovery_kube_volumes,'run') as run:
            with self.assertRaisesRegex(ValueError,'recovery identity'):
                recovery_kube_volumes.populate(['kubectl','--context','ctx'],'new-test','new-test',
                                              'invalid',{},'/tmp',{'redis':'2Gi','audit':'10Gi'},'',[])
            run.assert_not_called()

    def test_duplicate_secret_reference_is_refused(self):
        values={'guardrailSecret':'same','agentSecret':'same','redisSecret':'r',
                'policyConfigMap':'p','profileConfigMap':'m'}
        with self.assertRaisesRegex(ValueError,'duplicate'):
            recover_kubernetes.resource_mapping(values,'new-test')

    def test_volume_recovery_refuses_namespace_without_ownership_marker(self):
        with patch.object(recovery_kube_volumes,'run',return_value=b'{"metadata":{"labels":{}}}') as run:
            with self.assertRaisesRegex(ValueError,'ownership'):
                recovery_kube_volumes.populate(['kubectl','--context','ctx'],'new-test','new-test',
                                              'a'*32,{},'/tmp',{'redis':'2Gi','audit':'10Gi'},'',[])
            self.assertEqual(run.call_count,1)
            self.assertEqual(run.call_args.args[0][3:6],['get','namespace','new-test'])
