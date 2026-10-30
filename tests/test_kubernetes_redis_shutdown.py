import copy
import os
import tempfile
from pathlib import Path
import unittest

from scripts import kubernetes_fence_finalizer as finalizer
from scripts import kubernetes_redis_shutdown as shutdown
from scripts import redis_fence_journal as journal
from tests.test_kubernetes_fence_finalizer import FakeAPI


@unittest.skipUnless(os.name == 'posix', 'journal requires POSIX')
class ShutdownObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.pod = {'metadata': {'name':'redis-123', 'namespace':'test',
                                 'uid':'7a1ae129-82a8-490f-86e3-84dfd735d330', 'resourceVersion':'77'},
                    'spec': {'containers':[{'name':'redis','image':'example@sha256:'+'a'*64}]},
                    'status': {'phase':'Running','containerStatuses':[{'name':'redis',
                                'containerID':'containerd://'+'b'*64,'restartCount':0,
                                'state':{'running':{'startedAt':'now'}}}]}}
        self.plan = finalizer.plan_from_pod('kind-test','test','redis-123',self.pod)
        finalizer.persist_plan(self.home,self.plan)
        self.record = journal.create(self.home,backend='kubernetes',site='test',resource=self.plan['uid'],
                                     plan_sha256=finalizer.plan_hash(self.plan))
        self.api = FakeAPI(self.pod)
        finalizer.hold(self.home,self.plan,self.record['operation'],self.api)
        self.api.pod['metadata']['deletionTimestamp'] = '2026-10-30T11:00:00Z'
        self.api.pod['status']['containerStatuses'][0]['state'] = {
            'terminated': {'reason':'Completed','exitCode':0,'signal':0}}

    def observe(self):
        return shutdown.observe(self.home,self.plan,self.record['operation'],self.api)

    def test_clean_exit_only_observes_and_never_authorizes_or_changes_journal(self):
        patches = copy.deepcopy(self.api.patches)
        self.assertEqual(self.observe(),{'result':'termination_observed','redis_isolated':False,
                                         'unforced_deletion_verified':False,'aof_durable':False,
                                         'safe_to_upgrade':False})
        self.assertEqual(journal.read(self.home)['phase'],'isolating')
        self.assertEqual(self.api.patches,patches)

    def test_unknown_or_dangerous_termination_fails_closed(self):
        original = copy.deepcopy(self.api.pod)
        for field,value in (('exitCode',137),('exitCode',True),('signal',9),('reason','OOMKilled'),
                            ('reason','Error'),('exitCode',None)):
            with self.subTest(field=field,value=value):
                self.api.pod=copy.deepcopy(original)
                self.api.pod['status']['containerStatuses'][0]['state']['terminated'][field]=value
                with self.assertRaisesRegex(shutdown.ShutdownObservationError,'^KUBE_REDIS_SHUTDOWN_UNVERIFIED$'):
                    self.observe()
                self.assertEqual(journal.read(self.home)['phase'],'isolating')
        self.api.pod=copy.deepcopy(original)
        self.api.pod['status']['containerStatuses'][0]['state']={'running':{}}
        with self.assertRaises(shutdown.ShutdownObservationError): self.observe()

    def test_changed_identity_or_finalizer_fails_closed(self):
        original = copy.deepcopy(self.api.pod)
        for change in ('uid','spec','finalizer','container_id','restart','deletion','extra_status','context'):
            self.api.pod=copy.deepcopy(original)
            self.api.context='kind-test'
            item=self.api.pod['status']['containerStatuses'][0]
            if change=='uid': self.api.pod['metadata']['uid']='00000000-0000-0000-0000-000000000000'
            elif change=='spec': self.api.pod['spec']['containers'][0]['image']='changed'
            elif change=='finalizer': self.api.pod['metadata']['finalizers']=['other']
            elif change=='container_id': item['containerID']='containerd://'+'c'*64
            elif change=='restart': item['restartCount']=1
            elif change=='deletion': self.api.pod['metadata'].pop('deletionTimestamp')
            elif change=='extra_status': self.api.pod['status']['containerStatuses'].append(copy.deepcopy(item))
            else: self.api.context='other-cluster'
            with self.subTest(change=change), self.assertRaises(shutdown.ShutdownObservationError): self.observe()
            self.assertEqual(journal.read(self.home)['phase'],'isolating')

    def test_api_errors_or_wrong_operation_are_fixed_diagnostics(self):
        self.api.failure='get'
        with self.assertRaisesRegex(shutdown.ShutdownObservationError,'^KUBE_REDIS_SHUTDOWN_UNVERIFIED$'):
            self.observe()
        self.api.failure=None
        with self.assertRaises(shutdown.ShutdownObservationError):
            shutdown.observe(self.home,self.plan,'0'*32,self.api)


if __name__=='__main__': unittest.main()
