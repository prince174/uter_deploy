import os
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import kubernetes_redis_reverse_finalizer as reverse


@unittest.skipUnless(os.name=='posix','authenticated records require POSIX')
class ReversePlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.home=Path(self.tmp.name)
        self.operation='a'*32;self.key=b'k'*32;self.uid='22222222-2222-2222-2222-222222222222'
        self.old='11111111-1111-1111-1111-111111111111';self.name='uter-test-redis-abcd-efgh'
        self.spec={'containers':[{'name':'redis'}]};self.cid='containerd://'+'b'*64
        self.pod={'kind':'Pod','metadata':{'name':self.name,'namespace':'uter-test','uid':self.uid,'resourceVersion':'22'},'spec':self.spec,
                  'status':{'phase':'Running','containerStatuses':[{'name':'redis','containerID':self.cid,
                  'restartCount':0,'ready':True,'state':{'running':{}}}]}}
        owner=self
        class API:
            def __init__(inner):inner.calls=0;inner.fail_after=False
            def get(inner,name):return copy.deepcopy(owner.pod)
            def patch(inner,name,ops):
                inner.calls+=1;meta=owner.pod['metadata']
                if ops[-1]['op']=='add':meta['finalizers']=ops[-1]['value']
                else:meta['finalizers']=[]
                meta['resourceVersion']=str(int(meta['resourceVersion'])+1)
                if inner.fail_after:raise TimeoutError
        self.api=API()
        self.session=SimpleNamespace(_executor=('signed',),_record={'schema':2},_key_path='key',home=self.home,
            site='uter-test',_profile_digest='c'*64,_query=lambda args:self.pod,api=self.api,_scope=lambda:None)
        reverse.storage._write(self.home,reverse.backup.RECEIPT,{'operation':self.operation},self.key)

    def test_signed_backup_and_exact_loopback_identity_are_bound(self):
        state={'phase':'isolating','operation':self.operation,'resource':self.old}
        observed={'pod_spec_sha256':reverse.original._digest(self.spec),'container_id':self.cid}
        with patch.object(reverse.backup_installation,'safe_file',return_value=self.key), \
             patch.object(reverse.backup,'verify_receipt'),patch.object(reverse.loopback,'_observe',return_value=observed), \
             patch.object(reverse.journal,'read',return_value=state):
            self.assertEqual(reverse.prepare(self.session,self.operation,self.name,self.uid,'destination',self.key),
                             {'reverse_pod_plan_saved':True,'safe_to_resume':False})
            record=reverse._record(self.session,self.operation,self.key)
            self.assertEqual(record['uid'],self.uid);self.assertEqual(record['old_uid'],self.old)
            with self.assertRaises(reverse.ReverseFinalizerError):
                reverse.prepare(self.session,self.operation,self.name,self.uid,'destination',self.key)

    def test_hold_and_release_observe_exact_termination_and_never_replay(self):
        state={'phase':'isolating','operation':self.operation,'resource':self.old}
        observed={'pod_spec_sha256':reverse.original._digest(self.spec),'container_id':self.cid}
        with patch.object(reverse.backup_installation,'safe_file',return_value=self.key), \
             patch.object(reverse.backup,'verify_receipt'),patch.object(reverse.loopback,'_observe',return_value=observed), \
             patch.object(reverse.journal,'read',return_value=state):
            reverse.prepare(self.session,self.operation,self.name,self.uid,'destination',self.key)
            self.assertFalse(reverse.hold(self.session,self.operation,self.key)['safe_to_resume'])
            self.pod['metadata']['deletionTimestamp']='now'
            self.pod['status']['containerStatuses'][0]['state']={'terminated':{'exitCode':0,'signal':0,'reason':'Completed'}}
            self.assertFalse(reverse.observe(self.session,self.operation,self.key)['aof_durable'])
            self.pod['status']['containerStatuses'][0]['state']['terminated']['exitCode']=137
            with self.assertRaises(reverse.ReverseFinalizerError):reverse.release(self.session,self.operation,self.key)
            self.assertEqual(self.api.calls,1)
            self.pod['status']['containerStatuses'][0]['state']['terminated']['exitCode']=0
            self.api.fail_after=True
            with self.assertRaises(reverse.ReverseFinalizerError):reverse.release(self.session,self.operation,self.key)
            count=self.api.calls;self.api.fail_after=False
            with self.assertRaises(reverse.ReverseFinalizerError):reverse.release(self.session,self.operation,self.key)
            self.assertEqual(self.api.calls,count)
