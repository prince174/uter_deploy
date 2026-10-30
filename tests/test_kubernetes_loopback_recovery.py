import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import kubernetes_fence_finalizer as finalizer
from scripts import kubernetes_loopback_intent as forward
from scripts import kubernetes_loopback_recovery as recovery
from scripts import kubernetes_loopback_signed_ci as ci
from scripts import kubernetes_redis_identity as identity
from scripts import redis_fence_journal as journal
from tests.test_kubernetes_fence_finalizer import FakeAPI


class API(FakeAPI):
    def __init__(self,pod,deployment):
        super().__init__(pod);self.deployment=copy.deepcopy(deployment);self.patches=[];self.failure=None
    def get_deployment(self,name):return copy.deepcopy(self.deployment)
    def patch_deployment(self,name,ops):
        self.patches.append(copy.deepcopy(ops))
        if self.failure=='before':raise TimeoutError
        if ops[-1]['value']==[identity.COMMAND]:self.deployment['metadata']['resourceVersion']='82'
        else:self.deployment['metadata']['resourceVersion']='81'
        self.deployment['spec']['template']['spec']['containers'][0]['args']=ops[-1]['value']
        if self.failure=='after':raise TimeoutError


@unittest.skipUnless(os.name=='posix','private journal requires POSIX')
class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.home=self.root/'work'/'fixture';self.home.mkdir(mode=0o700,parents=True)
        pod={'metadata':{'name':'redis-123','namespace':'test','uid':'7a1ae129-82a8-490f-86e3-84dfd735d330','resourceVersion':'77'},
             'spec':{'containers':[{'name':'redis'}]},'status':{'phase':'Running','containerStatuses':[{'name':'redis',
             'containerID':'containerd://'+'b'*64,'restartCount':0,'state':{'running':{'startedAt':'now'}}}]}}
        deployment={'kind':'Deployment','metadata':{'name':'test-redis','namespace':'test',
                    'uid':'099ae129-82a8-490f-86e3-84dfd735d330','resourceVersion':'80'},
                    'spec':{'replicas':1,'template':{'spec':{'containers':[{'name':'redis','args':[identity.COMMAND]}]}}}}
        self.plan=finalizer.plan_from_pod('kind-test','test','redis-123',pod)
        finalizer.persist_plan(self.home,self.plan)
        record=journal.create(self.home,backend='kubernetes',site='test',resource=self.plan['uid'],
                              plan_sha256=finalizer.plan_hash(self.plan))
        self.operation=record['operation'];self.api=API(pod,deployment)
        finalizer.hold(self.home,self.plan,self.operation,self.api)
        forward.prepare(self.home,self.plan,self.operation,self.api)
        forward.request(self.home,self.plan,self.operation,self.api)
        self.api.patches.clear()

    def prepare(self):return recovery.prepare(self.home,self.plan,self.operation,self.api)
    def request(self):return recovery.request(self.home,self.plan,self.operation,self.api)
    def classify(self):return recovery.classify(self.home,self.plan,self.operation,self.api)

    def test_success_records_intent_before_one_cas_patch_without_resuming_writers(self):
        rec=self.prepare();self.assertEqual(rec['resource_version'],'81')
        result=self.request()
        self.assertEqual(result,{'state':'original_spec_observed','redis_healthy':False,'safe_to_resume':False})
        self.assertEqual(self.api.patches[0][:2],[{'op':'test','path':'/metadata/uid','value':rec['uid']},
                         {'op':'test','path':'/metadata/resourceVersion','value':'81'}])
        self.assertEqual(journal.read(self.home)['phase'],'isolating')
        with self.assertRaises(recovery.RecoveryError):self.request()
        self.assertEqual(len(self.api.patches),1)

    def test_timeout_before_or_after_patch_never_retries(self):
        for mode in ('before','after'):
            with self.subTest(mode=mode):
                self.setUp()
                self.prepare();self.api.failure=mode
                with self.assertRaises(recovery.RecoveryError):self.request()
                self.assertEqual(self.classify()['state'],'loopback_observed' if mode=='before' else 'original_spec_observed')
                self.api.failure=None
                with self.assertRaises(recovery.RecoveryError):self.request()
                self.assertEqual(len(self.api.patches),1)

    def test_identity_or_spec_change_and_invalid_record_fail_closed(self):
        self.prepare();original=copy.deepcopy(self.api.deployment)
        for field in ('uid','spec','rv'):
            self.api.deployment=copy.deepcopy(original)
            if field=='uid':self.api.deployment['metadata']['uid']='099ae129-82a8-490f-86e3-84dfd735d331'
            if field=='spec':self.api.deployment['spec']['replicas']=2
            if field=='rv':self.api.deployment['metadata']['resourceVersion']='83'
            with self.subTest(field=field),self.assertRaises(recovery.RecoveryError):self.request()
        self.api.deployment=original
        (self.home/recovery.NAME).unlink();(self.home/recovery.NAME).symlink_to(self.home/'missing')
        with self.assertRaises(recovery.RecoveryError):self.request()
        self.assertEqual(self.api.patches,[])

    def test_uncertain_marker_fsync_prevents_all_api_patches_and_retry(self):
        self.prepare()
        with patch.object(recovery.os,'fsync',side_effect=OSError('disk')):
            with self.assertRaises(recovery.RecoveryError):self.request()
        self.assertTrue((self.home/recovery.ATTEMPT_NAME).exists())
        with self.assertRaises(recovery.RecoveryError):self.request()
        self.assertEqual(self.api.patches,[])

    @unittest.skipUnless(hasattr(os,'fork'),'requires fork and SIGKILL')
    def test_disposable_ci_kills_patch_controller_and_keeps_attempt_marker(self):
        self.prepare()
        env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux',
             'UTER_CI_STRICT_RUNNER':'true','UTER_CI_VERIFY_KUBE_LOOPBACK':'true','BACKEND':'kubernetes'}
        with patch.object(ci,'ROOT',self.root),patch.object(ci.adopt_backup_ci,'runner_guard'), \
             patch.dict(os.environ,env,clear=True):
            ci._ci_crash_recovery_after_patch(self.home,self.plan,self.operation,self.api)
        self.assertFalse((self.home/'operation.lock').exists())
        self.assertTrue((self.home/recovery.ATTEMPT_NAME).exists())
        self.assertEqual(journal.read(self.home)['phase'],'isolating')
        with self.assertRaises(recovery.RecoveryError):self.request()
        self.assertEqual(self.api.patches,[])
