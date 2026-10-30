import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import kubernetes_fence_finalizer as finalizer
from scripts import kubernetes_writer_quiesce as quiesce
from scripts import redis_fence_journal as journal


class FakeAPI:
    def __init__(self,session):self.session=session;self.context='kind-test';self.namespace='test';self.calls=[];self.fail=None
    def get(self,name):return copy.deepcopy(self.session.redis_pod)
    def _call(self,args):
        self.calls.append(copy.deepcopy(args));service=args[2].rsplit('-',1)[1]
        if self.fail=='before':raise TimeoutError
        ops=json.loads(args[-1]);self.session.deployments[service]['spec']['replicas']=ops[-1]['value']
        self.session.deployments[service]['metadata']['resourceVersion']='92'
        self.session.deployments[service]['status']={'observedGeneration':1}
        if self.fail=='after':raise TimeoutError
        return b'{}'


class FakeSession:
    def __init__(self,home):
        self.home=home;self.site='test';self.api=FakeAPI(self);self.reverify_calls=0
        self.manifest={'images':{service:'example/'+service+'@sha256:'+'a'*64 for service in ('guardrail','agent')}}
        self.profile={'context':'kind-test'};self.inventory_digest='a'*64;self.config_sha256='b'*64;self.key_digest='c'*64
        self.deployments={};self.pods={}
        for service,uid in (('guardrail','099ae129-82a8-490f-86e3-84dfd735d330'),
                            ('agent','099ae129-82a8-490f-86e3-84dfd735d331')):
            labels={'app.kubernetes.io/instance':'test','app.kubernetes.io/name':service}
            self.deployments[service]={'kind':'Deployment','metadata':{'name':'test-'+service,'namespace':'test',
                    'uid':uid,'resourceVersion':'90','generation':1},'spec':{'replicas':1,'strategy':{'type':'Recreate'},
                    'selector':{'matchLabels':labels},'template':{'metadata':{'labels':labels},'spec':{
                        'automountServiceAccountToken':False,'containers':[{'name':service,
                        'image':self.manifest['images'][service]}]}}},'status':{'observedGeneration':1,'replicas':1}}
            self.pods[service]=[]
    def reverify(self):self.reverify_calls+=1;return {'safe_to_update':False}
    def _query(self,args):
        if args[1]=='deployment':return copy.deepcopy(self.deployments[args[2].rsplit('-',1)[1]])
        if args[1]=='pods':return {'items':copy.deepcopy(self.pods[args[-1].split('=')[-1]])}
        raise ValueError


@unittest.skipUnless(os.name=='posix','private journal requires POSIX')
class WriterQuiesceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.home=Path(self.tmp.name)
        held=patch('scripts.kubernetes_writer_finalizer.assert_held');self.held=held.start();self.addCleanup(held.stop)
        self.key=b'k'*32;self.session=FakeSession(self.home)
        pod={'metadata':{'name':'redis-123','namespace':'test','uid':'7a1ae129-82a8-490f-86e3-84dfd735d330','resourceVersion':'77'},
             'spec':{'containers':[{'name':'redis'}]},'status':{'phase':'Running','containerStatuses':[{'name':'redis',
             'containerID':'containerd://'+'b'*64,'restartCount':0,'state':{'running':{'startedAt':'now'}}}]}}
        self.session.redis_pod=pod
        self.plan=finalizer.plan_from_pod('kind-test','test','redis-123',pod);finalizer.persist_plan(self.home,self.plan)
        self.record=journal.create(self.home,backend='kubernetes',site='test',resource=self.plan['uid'],
                                   plan_sha256=finalizer.plan_hash(self.plan))
        self.operation=self.record['operation']
        self.uids={s:self.session.deployments[s]['metadata']['uid'] for s in quiesce.SERVICES}

    def prepare(self):return quiesce.prepare(self.home,self.session,self.operation,self.uids,self.key)
    def stop(self,service):return quiesce.stop(self.home,self.session,self.operation,service,self.key)

    def test_plan_and_two_cas_patches_never_authorize_redis_update(self):
        self.assertFalse(self.prepare()['safe_to_update'])
        for service in quiesce.SERVICES:
            self.assertFalse(self.stop(service)['safe_to_update'])
        # Without exact Pod termination receipts, absence alone is not proof.
        with self.assertRaises(quiesce.QuiesceError):
            quiesce.observe_stopped(self.home,self.session,self.operation,self.key)
        self.assertEqual(len(self.session.api.calls),2)
        for args,service in zip(self.session.api.calls,quiesce.SERVICES):
            ops=json.loads(args[-1]);self.assertEqual(ops[0],{'op':'test','path':'/metadata/uid','value':self.uids[service]})
            self.assertEqual(ops[-1],{'op':'replace','path':'/spec/replicas','value':0})
        self.assertEqual(journal.read(self.home)['phase'],'prepared')

    def test_timeout_before_or_after_patch_is_never_retried(self):
        for failure in ('before','after'):
            with self.subTest(failure=failure):
                self.setUp();self.prepare();self.session.api.fail=failure
                with self.assertRaises(quiesce.QuiesceError):self.stop('agent')
                self.session.api.fail=None
                expected='running_spec_observed' if failure=='before' else 'stopped_spec_observed'
                self.assertEqual(quiesce.classify(self.home,self.session,self.operation,'agent',self.key)['state'],expected)
                with self.assertRaises(quiesce.QuiesceError):self.stop('agent')
                self.assertEqual(len(self.session.api.calls),1)

    def test_changed_uid_image_spec_or_pod_cannot_be_silently_resumed(self):
        self.prepare()
        for field in ('uid','image','replicas'):
            saved=copy.deepcopy(self.session.deployments['agent'])
            if field=='uid':self.session.deployments['agent']['metadata']['uid']='77777777-7777-7777-7777-777777777777'
            if field=='image':self.session.deployments['agent']['spec']['template']['spec']['containers'][0]['image']='evil'
            if field=='replicas':self.session.deployments['agent']['spec']['replicas']=2
            with self.subTest(field=field),self.assertRaises(quiesce.QuiesceError):self.stop('agent')
            self.session.deployments['agent']=saved
        self.assertEqual(self.session.api.calls,[])
        for service in quiesce.SERVICES:self.stop(service)
        self.session.pods['agent']=[{'metadata':{'name':'unexpected'}}]
        with self.assertRaisesRegex(quiesce.QuiesceError,'KUBE_WRITERS_NOT_QUIESCED'):
            quiesce.observe_stopped(self.home,self.session,self.operation,self.key)

    def test_marker_write_failure_preserves_marker_and_prevents_patch(self):
        self.prepare()
        with patch.object(quiesce.os,'fsync',side_effect=OSError('disk')):
            with self.assertRaises(quiesce.QuiesceError):self.stop('agent')
        self.assertTrue((self.home/'kubernetes-writer-agent-attempt.json').exists())
        with self.assertRaises(quiesce.QuiesceError):self.stop('agent')
        self.assertEqual(self.session.api.calls,[])

    def test_unverified_finalizer_prevents_writer_stop(self):
        self.prepare();self.held.side_effect=ValueError('unknown')
        with self.assertRaises(quiesce.QuiesceError):self.stop('agent')
        self.assertFalse((self.home/'kubernetes-writer-agent-attempt.json').exists())
        self.assertEqual(self.session.api.calls,[])

    def test_changed_pin_executor_or_record_is_rejected(self):
        self.prepare()
        for attr,value in (('inventory_digest','d'*64),('config_sha256','d'*64),('key_digest','d'*64)):
            original=getattr(self.session,attr);setattr(self.session,attr,value)
            with self.subTest(attr=attr),self.assertRaises(quiesce.QuiesceError):self.stop('agent')
            setattr(self.session,attr,original)
        path=self.home/quiesce.NAME;path.write_text('malformed');path.chmod(0o600)
        with self.assertRaises(quiesce.QuiesceError):self.stop('agent')
        self.assertEqual(self.session.api.calls,[])
