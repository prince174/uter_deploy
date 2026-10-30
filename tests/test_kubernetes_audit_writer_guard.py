import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import kubernetes_audit_writer_guard as guard


class AuditWriterGuardTests(unittest.TestCase):
    def setUp(self):
        self.op='a'*32;self.key=b'k'*32;self.spec={'replicas':0}
        self.plan_pod={'schema':1,'context':'test','namespace':'uter-test','pod':'uter-test-redis-a-b',
            'uid':'11111111-1111-1111-1111-111111111111','resource_version':'1',
            'container_id':'containerd://'+'b'*64,'spec_sha256':'c'*64}
        self.session=SimpleNamespace(home='home',site='uter-test',api=SimpleNamespace(context='test'),
            _executor=('signed',),_record={'schema':2},
            manifest={'version':'1'},profile={'pin':'x'},inventory_digest='i',config_sha256='c',key_digest='k',
            writer_uids={'guardrail':'u1','agent':'u2'},_scope=lambda:None)
        self.plan={'operation':self.op,'site':'uter-test','context':'test',
            'redis_plan_sha256':guard.finalizer.plan_hash(self.plan_pod),'redis_uid':self.plan_pod['uid'],
            'manifest_sha256':guard.writers._hash(self.session.manifest),'profile_sha256':guard.writers._hash(self.session.profile),
            'inventory_sha256':'i','config_sha256':'c','key_sha256':'k',
            'writers':{s:{'uid':uid,'stopped':guard.writers._hash(self.spec)} for s,uid in self.session.writer_uids.items()}}
        self.data={guard.writers.NAME:self.plan,guard.NAME:{'schema':1,'operation':self.op,
                                                           'writer_plan_sha256':guard.writers._hash(self.plan)}}
        for service in guard.writers.SERVICES:
            pod={'operation':self.op,'service':service,'writer_plan_sha256':guard.writers._hash(self.plan)}
            digest=guard.writers._hash(pod)
            self.data['kubernetes-writer-pod-'+service+'.json']=pod
            self.data['kubernetes-writer-observed-'+service+'.json']={'operation':self.op,'pod_plan_sha256':digest,'resource_version':'2'}
            self.data['kubernetes-writer-release-'+service+'-attempt.json']={'operation':self.op,'pod_plan_sha256':digest}
        def query(args):
            if args[1]=='pods':return {'items':[]}
            service=args[2].rsplit('-',1)[1]
            return {'metadata':{'uid':self.session.writer_uids[service],'resourceVersion':'3'},
                    'status':{'observedGeneration':4}}
        self.session._query=query

    def test_live_stopped_deployments_and_hmac_evidence_are_required(self):
        def deployment(session,service,uid):return {'uid':uid,'resourceVersion':'3','generation':4},self.spec
        with patch.object(guard.journal,'read',return_value={'resource':self.plan_pod['uid']}), \
             patch.object(guard.finalizer,'read_plan',return_value=self.plan_pod), \
             patch.object(guard.finalizer,'_check_journal'),patch.object(guard.writers,'_deployment',side_effect=deployment), \
             patch.object(guard.writers,'_read',side_effect=lambda home,name,key:copy.deepcopy(self.data[name])):
            self.assertEqual(guard.verify(self.session,self.op,self.key),
                {'writers_stopped_observed':True,'continuous_exclusion':False,'safe_to_backup':False})
            self.data['kubernetes-writer-release-agent-attempt.json']['operation']='other'
            with self.assertRaises(guard.WriterGuardError):guard.verify(self.session,self.op,self.key)
            self.data['kubernetes-writer-release-agent-attempt.json']['operation']=self.op
            original=self.session._query
            self.session._query=lambda args:{'items':[{'metadata':{'uid':'unexpected'}}]} if args[1]=='pods' else original(args)
            with self.assertRaises(guard.WriterGuardError):guard.verify(self.session,self.op,self.key)
