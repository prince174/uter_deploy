import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import kubernetes_fence_finalizer as common
from scripts import kubernetes_writer_finalizer as writer
from scripts import kubernetes_writer_quiesce as quiesce
from scripts import redis_fence_journal as journal
from tests.test_kubernetes_writer_quiesce import FakeAPI,FakeSession


class API(FakeAPI):
    def _call(self,args):
        if args[2].startswith('pod/'):
            self.calls.append(copy.deepcopy(args));ops=json.loads(args[-1]);name=args[2][4:]
            service=next(x for x,p in self.session.writer_pods.items() if p['metadata']['name']==name)
            pod=self.session.writer_pods[service]
            if self.fail=='before':raise TimeoutError
            if ops[-1]['op']=='add':pod['metadata']['finalizers']=ops[-1]['value']
            else:pod['metadata']['finalizers']=[]
            pod['metadata']['resourceVersion']=str(int(pod['metadata']['resourceVersion'])+1)
            if self.fail=='after':raise TimeoutError
            return b'{}'
        result=super()._call(args)
        service=args[2].rsplit('-',1)[1];pod=self.session.writer_pods[service]
        pod['metadata']['deletionTimestamp']='2026-01-01T00:00:00Z'
        pod['metadata']['resourceVersion']=str(int(pod['metadata']['resourceVersion'])+1)
        pod['status']['containerStatuses'][0]['state']={'terminated':{'exitCode':0,'reason':'Completed'}}
        return result


class Session(FakeSession):
    def __init__(self,home):
        super().__init__(home);self.api=API(self);self.writer_pods={};self.writer_rs={}
        for index,service in enumerate(quiesce.SERVICES):
            dep=self.deployments[service];rsname='test-'+service+'-abc123';rsuid='7a1ae129-82a8-490f-86e3-84dfd735d33'+str(index)
            labels={'app.kubernetes.io/instance':'test','app.kubernetes.io/name':service}
            self.writer_rs[service]={'kind':'ReplicaSet','metadata':{'name':rsname,'namespace':'test','uid':rsuid,
                'ownerReferences':[{'kind':'Deployment','name':'test-'+service,'uid':dep['metadata']['uid'],'controller':True}]}}
            self.writer_pods[service]={'kind':'Pod','metadata':{'name':rsname+'-pod','namespace':'test',
                'uid':'8a1ae129-82a8-490f-86e3-84dfd735d33'+str(index),'resourceVersion':'75','labels':labels,
                'ownerReferences':[{'kind':'ReplicaSet','name':rsname,'uid':rsuid,'controller':True}]},
                'spec':{'automountServiceAccountToken':False,'containers':[{'name':service,'image':self.manifest['images'][service]}]},
                'status':{'phase':'Running','containerStatuses':[{'name':service,'ready':True,'restartCount':0,
                    'containerID':'containerd://'+'b'*64,'state':{'running':{}}}]}}
    def _query(self,args):
        if args[1]=='pod':return copy.deepcopy(next(p for p in self.writer_pods.values() if p['metadata']['name']==args[2]))
        if args[1]=='pods':
            service=args[-1].split('=')[-1]
            return {'items':[copy.deepcopy(self.writer_pods[service])] if service in self.writer_pods else []}
        if args[1]=='replicaset':return copy.deepcopy(next(p for p in self.writer_rs.values() if p['metadata']['name']==args[2]))
        return super()._query(args)


@unittest.skipUnless(os.name=='posix','private journal requires POSIX')
class WriterFinalizerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.home=Path(self.tmp.name)
        self.key=b'k'*32;self.session=Session(self.home)
        pod={'metadata':{'name':'redis-123','namespace':'test','uid':'7a1ae129-82a8-490f-86e3-84dfd735d330','resourceVersion':'77'},
             'spec':{'containers':[{'name':'redis'}]},'status':{'phase':'Running','containerStatuses':[{'name':'redis',
             'containerID':'containerd://'+'b'*64,'restartCount':0,'state':{'running':{'startedAt':'now'}}}]}}
        self.session.redis_pod=pod
        self.plan=common.plan_from_pod('kind-test','test','redis-123',pod);common.persist_plan(self.home,self.plan)
        rec=journal.create(self.home,backend='kubernetes',site='test',resource=self.plan['uid'],plan_sha256=common.plan_hash(self.plan))
        self.operation=rec['operation'];uids={s:self.session.deployments[s]['metadata']['uid'] for s in quiesce.SERVICES}
        quiesce.prepare(self.home,self.session,self.operation,uids,self.key)

    def prepare(self,service):return writer.prepare(self.home,self.session,self.operation,service,self.key)
    def hold(self,service):return writer.hold(self.home,self.session,self.operation,service,self.key)
    def observe(self,service):return writer.observe(self.home,self.session,self.operation,service,self.key)
    def release(self,service):return writer.release(self.home,self.session,self.operation,service,self.key)

    def test_prepared_finalizer_observes_zero_exit_before_single_release(self):
        self.prepare('agent');self.hold('agent')
        result=quiesce.stop(self.home,self.session,self.operation,'agent',self.key)
        self.assertFalse(result['safe_to_update'])
        observed=self.observe('agent');self.assertTrue(observed['result']=='writer_termination_observed')
        self.assertFalse(observed['audit_durability_verified']);self.assertFalse(observed['safe_to_backup'])
        release=self.release('agent');self.assertTrue(release['termination_verified']);self.assertFalse(release['safe_to_backup'])
        with self.assertRaises(writer.WriterFinalizerError):self.release('agent')
        podpatches=[args for args in self.session.api.calls if args[2].startswith('pod/')]
        self.assertEqual(len(podpatches),2)
        operations=json.loads(podpatches[-1][-1])
        self.assertEqual(operations[0]['path'],'/metadata/uid')
        self.assertEqual(operations[-1]['op'],'remove')

    def test_nonzero_exit_or_changed_container_never_releases_finalizer(self):
        self.prepare('agent');self.hold('agent');quiesce.stop(self.home,self.session,self.operation,'agent',self.key)
        original=copy.deepcopy(self.session.writer_pods['agent'])
        for change in ('exit','signal','reason','container','spec'):
            self.session.writer_pods['agent']=copy.deepcopy(original)
            item=self.session.writer_pods['agent']['status']['containerStatuses'][0]
            if change=='exit':item['state']['terminated']['exitCode']=143
            if change=='signal':item['state']['terminated']['signal']=9
            if change=='reason':item['state']['terminated']['reason']='Error'
            if change=='container':item['containerID']='containerd://'+'c'*64
            if change=='spec':self.session.writer_pods['agent']['spec']['hostNetwork']=True
            with self.subTest(change=change),self.assertRaises(writer.WriterFinalizerError):self.release('agent')
        self.assertFalse((self.home/'kubernetes-writer-release-agent-attempt.json').exists())
        self.assertEqual(len([x for x in self.session.api.calls if x[2].startswith('pod/')]),1)

    def test_both_terminated_receipts_and_no_pods_still_cannot_authorize_backup(self):
        for service in quiesce.SERVICES:self.prepare(service);self.hold(service)
        for service in quiesce.SERVICES:quiesce.stop(self.home,self.session,self.operation,service,self.key)
        for service in quiesce.SERVICES:self.observe(service);self.release(service);self.session.writer_pods.pop(service)
        result=quiesce.observe_stopped(self.home,self.session,self.operation,self.key)
        self.assertEqual(result,{'writers_stopped_observed':True,'continuous_exclusion':False,
            'old_writer_termination_observed':True,'unforced_deletion_verified':False,'audit_durability_verified':False,
            'redis_isolated':False,'safe_to_backup':False,'safe_to_update':False})

    def test_timeout_after_hold_is_not_retried(self):
        self.prepare('agent');self.session.api.fail='after'
        with self.assertRaises(writer.WriterFinalizerError):self.hold('agent')
        self.session.api.fail=None
        with self.assertRaises(writer.WriterFinalizerError):self.hold('agent')
        self.assertEqual(len(self.session.api.calls),1)
        self.assertTrue((self.home/'kubernetes-writer-hold-agent-attempt.json').exists())

    def test_timeout_after_release_is_not_retried(self):
        self.prepare('agent');self.hold('agent');quiesce.stop(self.home,self.session,self.operation,'agent',self.key)
        self.session.api.fail='after'
        with self.assertRaises(writer.WriterFinalizerError):self.release('agent')
        self.session.api.fail=None
        with self.assertRaises(writer.WriterFinalizerError):self.release('agent')
        self.assertEqual(len([x for x in self.session.api.calls if x[2].startswith('pod/')]),2)
        self.assertTrue((self.home/'kubernetes-writer-release-agent-attempt.json').exists())

    def test_nonzero_exit_has_bounded_diagnostic_without_contents(self):
        self.prepare('agent');self.hold('agent');quiesce.stop(self.home,self.session,self.operation,'agent',self.key)
        self.session.writer_pods['agent']['status']['containerStatuses'][0]['state']['terminated']['exitCode']=143
        with self.assertRaises(writer.WriterFinalizerError) as error:self.observe('agent')
        self.assertEqual(error.exception.stage,'EXIT_CODE')
        self.assertEqual(str(error.exception),'KUBE_WRITER_TERMINATION_UNVERIFIED')

    def test_fsync_failure_blocks_patch(self):
        self.prepare('agent')
        with patch.object(quiesce.os,'fsync',side_effect=OSError('disk')):
            with self.assertRaises(writer.WriterFinalizerError):self.hold('agent')
        self.assertEqual(self.session.api.calls,[])
        with self.assertRaises(writer.WriterFinalizerError):self.hold('agent')
