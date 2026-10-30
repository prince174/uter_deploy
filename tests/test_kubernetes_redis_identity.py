import copy
import unittest

from scripts import kubernetes_redis_identity as identity


class RedisIdentityTests(unittest.TestCase):
    def setUp(self):
        self.site='uter-test';self.image='registry.example/redis@sha256:'+'a'*64
        self.cluster='11111111-1111-1111-1111-111111111111'
        self.deploy_uid='22222222-2222-2222-2222-222222222222'
        self.rs_uid='33333333-3333-3333-3333-333333333333'
        self.pod_uid='44444444-4444-4444-4444-444444444444'
        self.pvc_uid='55555555-5555-5555-5555-555555555555'
        self.labels={'app.kubernetes.io/instance':self.site,'app.kubernetes.io/name':'redis'}
        self.spec={'automountServiceAccountToken':False,
                   'containers':[{'name':'redis','image':self.image,'command':['sh','-ec'],'args':[identity.COMMAND],
                                  'env':[{'name':'REDIS_PASSWORD','valueFrom':{'secretKeyRef':{'name':self.site+'-redis-secret','key':'password'}}}],
                                  'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
                                  'volumeMounts':[{'name':'tmp','mountPath':'/tmp'},{'name':'data','mountPath':'/data'}]}],
                   'volumes':[{'name':'tmp','emptyDir':{}},{'name':'data','persistentVolumeClaim':{'claimName':self.site+'-redis'}}]}
        self.manifest={'images':{'redis':self.image}}
        self.deployment={'kind':'Deployment','metadata':{'name':self.site+'-redis','namespace':self.site,'uid':self.deploy_uid,'generation':4},
                         'spec':{'replicas':1,'strategy':{'type':'Recreate'},'template':{'metadata':{'labels':self.labels},'spec':copy.deepcopy(self.spec)}},
                         'status':{'observedGeneration':4}}
        self.rsname=self.site+'-redis-f4cc22'
        self.rs={'kind':'ReplicaSet','metadata':{'name':self.rsname,'namespace':self.site,'uid':self.rs_uid,
                  'ownerReferences':[{'kind':'Deployment','name':self.site+'-redis','uid':self.deploy_uid,'controller':True}]},
                 'spec':{'replicas':1,'template':{'spec':copy.deepcopy(self.spec)}}}
        self.pod={'kind':'Pod','metadata':{'name':self.rsname+'-pod','namespace':self.site,'uid':self.pod_uid,'labels':self.labels,
                  'ownerReferences':[{'kind':'ReplicaSet','name':self.rsname,'uid':self.rs_uid,'controller':True}]},
                  'spec':copy.deepcopy(self.spec),'status':{'phase':'Running','containerStatuses':[{'name':'redis','ready':True,
                    'restartCount':0,'state':{'running':{}},'imageID':'docker-pullable://'+self.image}]}}
        self.pvc={'kind':'PersistentVolumeClaim','metadata':{'name':self.site+'-redis','namespace':self.site,'uid':self.pvc_uid},
                  'status':{'phase':'Bound'}}

    def verify(self):
        return identity.verify_snapshot(site=self.site,manifest=self.manifest,cluster_uid=self.cluster,expected_cluster_uid=self.cluster,
                                        expected_pvc_uid=self.pvc_uid,
                                        deployment=self.deployment,replicaset=self.rs,pod=self.pod,pvc=self.pvc)

    def test_matching_snapshot_never_authorizes_transition(self):
        self.assertEqual(self.verify(),{'result':'matching_snapshot_observed','redis_isolated':False,
                                        'cluster_authenticated':False,'writers_excluded':False,'safe_to_upgrade':False})

    def test_adversarial_runtime_changes_are_refused(self):
        for change in ('cluster','deployment_owner','rs_owner','image','runtime_image','new_container','new_env',
                       'host_network','init','ephemeral','volume','secret','restarts','privilege','strategy','pvc','pvc_uid'):
            with self.subTest(change=change):
                self.setUp()
                if change=='cluster': self.cluster='not-a-uid'
                elif change=='deployment_owner': self.rs['metadata']['ownerReferences'][0]['uid']=self.pod_uid
                elif change=='rs_owner': self.pod['metadata']['ownerReferences'][0]['uid']=self.deploy_uid
                elif change=='image': self.pod['spec']['containers'][0]['image']='registry.example/evil@sha256:'+'b'*64
                elif change=='runtime_image': self.pod['status']['containerStatuses'][0]['imageID']='sha256:'+'c'*64
                elif change=='new_container': self.pod['spec']['containers'].append({'name':'sidecar'})
                elif change=='new_env': self.pod['spec']['containers'][0]['env'].append({'name':'LD_PRELOAD','value':'secret'})
                elif change=='host_network': self.pod['spec']['hostNetwork']=True
                elif change=='init': self.pod['spec']['initContainers']=[{'name':'init'}]
                elif change=='ephemeral': self.pod['spec']['ephemeralContainers']=[{'name':'debugger'}]
                elif change=='volume': self.pod['spec']['volumes'][1]['persistentVolumeClaim']['claimName']='other'
                elif change=='secret': self.pod['spec']['containers'][0]['env'][0]['valueFrom']['secretKeyRef']['name']='other'
                elif change=='restarts': self.pod['status']['containerStatuses'][0]['restartCount']=1
                elif change=='privilege': self.pod['spec']['containers'][0]['securityContext']['privileged']=True
                elif change=='strategy': self.deployment['spec']['strategy']['type']='RollingUpdate'
                elif change=='pvc': self.pvc['status']['phase']='Lost'
                else: self.pvc['metadata']['uid']='66666666-6666-6666-6666-666666666666'
                with self.assertRaisesRegex(identity.KubernetesRedisIdentityError,'^KUBE_REDIS_IDENTITY_UNVERIFIED$'):
                    self.verify()

    def test_other_cluster_uid_and_different_signed_digest_refused(self):
        kwargs={'site':self.site,'manifest':self.manifest,'cluster_uid':self.cluster,
                'expected_cluster_uid':'99999999-9999-9999-9999-999999999999','expected_pvc_uid':self.pvc_uid,
                'deployment':self.deployment,'replicaset':self.rs,'pod':self.pod,'pvc':self.pvc}
        with self.assertRaises(identity.KubernetesRedisIdentityError): identity.verify_snapshot(**kwargs)
        self.manifest['images']['redis']='registry.example/redis@sha256:'+'b'*64
        with self.assertRaises(identity.KubernetesRedisIdentityError): self.verify()


if __name__=='__main__': unittest.main()
