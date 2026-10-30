import base64
import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import kubernetes_maintenance_preflight as preflight


class KubernetesPreflightTests(unittest.TestCase):
    def setUp(self):
        self.site = 'uter-test'
        self.secret_uid = '11111111-1111-1111-1111-111111111111'
        self.deploy = {'agent':'22222222-2222-2222-2222-222222222222',
                       'guardrail':'33333333-3333-3333-3333-333333333333'}
        self.manifest = {'images': {name:'registry.example/'+name+'@sha256:'+'a'*64 for name in ('agent','guardrail')}}
        self.secret = {'kind':'Secret','type':'Opaque','metadata':{'uid':self.secret_uid},
                       'data':{'key':base64.b64encode(b'x'*64).decode()}}
        self.pods = {}
        for index, service in enumerate(('agent','guardrail'), start=4):
            env = [{'name':'UTER_MAINTENANCE_ENABLED','value':'true'},
                   {'name':'UTER_MAINTENANCE_KEY_FILE','value':'/run/uter-maintenance/key'},
                   {'name':'WEB_CONCURRENCY','value':'1'}]
            self.pods[service] = {'kind':'Pod','metadata': {'name':self.site+'-'+service+'-abcd-xyz',
                'namespace':self.site,'uid':str(index)*8+'-'+str(index)*4+'-'+str(index)*4+'-'+str(index)*4+'-'+str(index)*12,
                'ownerReferences':[{'kind':'ReplicaSet','name':self.site+'-'+service+'-abcd','uid':str(index)*8+'-'+str(index)*4+'-'+str(index)*4+'-'+str(index)*4+'-'+str(index)*12,'controller':True}]},
                'spec': {'automountServiceAccountToken':False,
                    'securityContext':{'runAsNonRoot':True,'runAsUser':10001,'runAsGroup':10001,'fsGroup':10001,
                                       'seccompProfile':{'type':'RuntimeDefault'}},
                    'containers':[{'name':service,'image':self.manifest['images'][service],'env':env,
                    'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
                    'volumeMounts':[{'name':'maintenance-key','mountPath':'/run/uter-maintenance','readOnly':True}]}],
                    'volumes':[{'name':'maintenance-key','secret':{'secretName':self.site+'-maintenance','defaultMode':288}}]},
                'status':{'phase':'Running','containerStatuses':[{'name':service,'ready':True,'restartCount':0,
                    'imageID':self.manifest['images'][service],
                    'containerID':'containerd://'+'a'*64,'state':{'running':{}}}]}}
        self.session = SimpleNamespace(_executor=object(), _record={'schema':2,'object_uids':{'secret/'+self.site+'-maintenance':self.secret_uid}},
            _inner=SimpleNamespace(bundle='bundle',publisher_key='publisher'), manifest=self.manifest,
            site=self.site,writer_uids=self.deploy,reverify=lambda:None,_get_configured_object=lambda *_:self.secret,
            _query=self.query)

    def query(self, args):
        if args[1] == 'pods':
            service = args[-1].split('=')[-1]
            return {'items':[copy.deepcopy(self.pods[service])]}
        if args[1] == 'replicaset':
            service = 'guardrail' if 'guardrail' in args[2] else 'agent'
            return {'kind':'ReplicaSet','metadata':{'namespace':self.site,
                'uid':self.pods[service]['metadata']['ownerReferences'][0]['uid'],
                'ownerReferences':[{'kind':'Deployment','name':self.site+'-'+service,'uid':self.deploy[service],'controller':True}]}}
        raise AssertionError

    def run_check(self):
        def deployment(session, service, uid):
            return {'uid':uid},{'replicas':1}
        with patch.object(preflight.maintenance_protocol,'verify_capability',return_value=self.manifest), \
             patch.object(preflight.writers,'_deployment',side_effect=deployment):
            return preflight.observe(self.session)

    def test_verified_preflight_still_cannot_authorize_start(self):
        result = self.run_check()
        self.assertEqual(set(result['writers']), {'agent','guardrail'})
        self.assertIs(result['safe_to_start'], False)
        self.assertIs(result['redis_isolated'], False)

    def test_rejects_duplicate_env_or_unpinned_secret(self):
        self.pods['agent']['spec']['containers'][0]['env'].append({'name':'WEB_CONCURRENCY','value':'2'})
        with self.assertRaises(preflight.PreflightError): self.run_check()
        self.pods['agent']['spec']['containers'][0]['env'].pop()
        self.secret['metadata']['uid']='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        with self.assertRaises(preflight.PreflightError): self.run_check()

    def test_rejects_changed_or_unavailable_writer(self):
        self.pods['guardrail']['status']['containerStatuses'][0]['restartCount']=1
        with self.assertRaises(preflight.PreflightError): self.run_check()

    def test_liveness_cannot_restart_a_draining_writer(self):
        self.pods['agent']['spec']['containers'][0]['livenessProbe']={'httpGet':{'path':'/health'}}
        with self.assertRaises(preflight.PreflightError): self.run_check()

    def test_digest_must_match_the_running_image(self):
        self.pods['guardrail']['status']['containerStatuses'][0]['imageID']='registry.example/wrong@sha256:'+'b'*64
        with self.assertRaises(preflight.PreflightError): self.run_check()


if __name__ == '__main__': unittest.main()
