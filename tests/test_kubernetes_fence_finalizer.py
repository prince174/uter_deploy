import copy
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts import kubernetes_fence_finalizer as finalizer
from scripts import redis_fence_journal as journal


class FakeAPI:
    context='kind-test'
    namespace='test'
    def __init__(self,pod): self.pod=copy.deepcopy(pod);self.failure=None;self.patches=[]
    def get(self,name):
        if self.failure=='get': raise finalizer.FinalizerError('KUBE_FINALIZER_API_UNCERTAIN')
        return copy.deepcopy(self.pod)
    def patch(self,name,ops):
        self.patches.append(copy.deepcopy(ops))
        if self.failure=='before': raise finalizer.FinalizerError('KUBE_FINALIZER_API_UNCERTAIN')
        meta=self.pod['metadata']
        for op in ops:
            key=op['path'].split('/')[-1]
            if op['op']=='test' and meta[key]!=op['value']:
                raise finalizer.FinalizerError('KUBE_FINALIZER_API_UNCERTAIN')
            if op['op']=='add':meta['finalizers']=op['value']
            if op['op']=='remove':meta['finalizers'].pop(0)
        meta['resourceVersion']=str(int(meta['resourceVersion'])+1)
        if self.failure=='after': raise finalizer.FinalizerError('KUBE_FINALIZER_API_UNCERTAIN')


@unittest.skipUnless(os.name=='posix','journal requires POSIX')
class KubernetesFinalizerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.home=Path(self.temp.name)
        self.pod={'metadata':{'name':'redis-123','namespace':'test',
                              'uid':'7a1ae129-82a8-490f-86e3-84dfd735d330','resourceVersion':'77'},
                  'spec':{'containers':[{'name':'redis','image':'example@sha256:'+'a'*64}]},
                  'status':{'phase':'Running','containerStatuses':[{'name':'redis','containerID':'containerd://'+'b'*64,
                              'restartCount':0,'state':{'running':{'startedAt':'now'}}}]}}
        self.plan=finalizer.plan_from_pod('kind-test','test','redis-123',self.pod)
        finalizer.persist_plan(self.home,self.plan)
        self.record=journal.create(self.home,backend='kubernetes',site='test',resource=self.plan['uid'],
                                   plan_sha256=finalizer.plan_hash(self.plan))
        self.api=FakeAPI(self.pod)

    def hold(self): return finalizer.hold(self.home,self.plan,self.record['operation'],self.api)
    def release(self): return finalizer.release_unchanged(self.home,self.plan,self.record['operation'],self.api)

    def test_hold_and_remove_only_own_finalizer_without_asserting_isolation(self):
        self.assertEqual(self.hold(),{'result':'finalizer_held','redis_isolated':False})
        self.assertEqual(journal.read(self.home)['phase'],'isolating')
        self.assertEqual(self.release(),{'result':'own_finalizer_removed','redis_isolated':False,'transaction_restored':False})
        self.assertEqual(self.api.pod['metadata']['finalizers'],[])
        self.assertEqual(journal.read(self.home)['phase'],'aborting')

    def test_uncertain_mutation_before_or_after_side_effect_retains_journal_and_never_returns_success(self):
        for failure in ('before','after'):
            with self.subTest(failure=failure):
                with tempfile.TemporaryDirectory() as home:
                    finalizer.persist_plan(home,self.plan)
                    record=journal.create(home,backend='kubernetes',site='test',resource=self.plan['uid'],
                                          plan_sha256=finalizer.plan_hash(self.plan))
                    api=FakeAPI(self.pod);api.failure=failure
                    with self.assertRaisesRegex(finalizer.FinalizerError,'API_UNCERTAIN'):
                        finalizer.hold(home,self.plan,record['operation'],api)
                    self.assertEqual(journal.read(home)['phase'],'isolating')
                    self.assertEqual(bool(api.pod['metadata'].get('finalizers')),failure=='after')

    def test_release_refuses_any_changed_or_terminating_pod_without_patching(self):
        cases=[('uid','other'),('deletionTimestamp','now'),('resourceVersion','bad')]
        for key,value in cases:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as home:
                finalizer.persist_plan(home,self.plan)
                record=journal.create(home,backend='kubernetes',site='test',resource=self.plan['uid'],
                                      plan_sha256=finalizer.plan_hash(self.plan))
                api=FakeAPI(self.pod);finalizer.hold(home,self.plan,record['operation'],api)
                api.pod['metadata'][key]=value
                with self.assertRaisesRegex(finalizer.FinalizerError,'STATE_CHANGED'):
                    finalizer.release_unchanged(home,self.plan,record['operation'],api)
                self.assertEqual(len(api.patches),1);self.assertEqual(journal.read(home)['phase'],'isolating')

    def test_release_rejects_restart_spec_or_external_finalizer_change(self):
        for change in ('restart','spec','finalizer'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as home:
                finalizer.persist_plan(home,self.plan)
                record=journal.create(home,backend='kubernetes',site='test',resource=self.plan['uid'],
                                      plan_sha256=finalizer.plan_hash(self.plan))
                api=FakeAPI(self.pod);finalizer.hold(home,self.plan,record['operation'],api)
                if change=='restart':api.pod['status']['containerStatuses'][0]['restartCount']=1
                elif change=='spec':api.pod['spec']['containers'][0]['image']='changed'
                else:api.pod['metadata']['finalizers'].append('someone.example/finalizer')
                with self.assertRaises(finalizer.FinalizerError):
                    finalizer.release_unchanged(home,self.plan,record['operation'],api)
                self.assertEqual(len(api.patches),1);self.assertEqual(journal.read(home)['phase'],'isolating')

    def test_wrong_context_or_plan_never_mutates(self):
        self.api.context='wrong'
        with self.assertRaisesRegex(finalizer.FinalizerError,'CONTEXT_MISMATCH'):self.hold()
        self.assertEqual(self.api.patches,[]);self.assertEqual(journal.read(self.home)['phase'],'prepared')
        self.api.context='kind-test';altered=dict(self.plan,pod='another')
        with self.assertRaisesRegex(finalizer.FinalizerError,'PLAN_MISMATCH'):
            finalizer.hold(self.home,altered,self.record['operation'],self.api)
        self.assertEqual(self.api.patches,[])

    def test_patch_timeout_on_release_keeps_aborting_marker(self):
        self.hold();self.api.failure='after'
        with self.assertRaisesRegex(finalizer.FinalizerError,'API_UNCERTAIN'):self.release()
        self.assertEqual(journal.read(self.home)['phase'],'aborting')

    def test_initial_foreign_finalizer_or_nonrunning_pod_rejected(self):
        for mutation in ('finalizer','terminated','restart'):
            with self.subTest(mutation=mutation):
                pod=copy.deepcopy(self.pod)
                if mutation=='finalizer':pod['metadata']['finalizers']=['another/finalizer']
                elif mutation=='terminated':pod['status']['containerStatuses'][0]['state']={'terminated':{'exitCode':0}}
                else:pod['status']['containerStatuses'][0]['restartCount']=1
                with self.assertRaises(finalizer.FinalizerError):
                    finalizer.plan_from_pod('kind-test','test','redis-123',pod)

    def test_output_never_exposes_live_pod_values_on_bad_snapshot(self):
        pod=copy.deepcopy(self.pod);pod['metadata']['uid']='secret-data'
        with self.assertRaises(finalizer.FinalizerError) as error:
            finalizer.plan_from_pod('kind-test','test','redis-123',pod)
        self.assertNotIn('secret-data',str(error.exception))

    def test_durable_plan_is_private_and_refuses_overwrite_or_tampering(self):
        self.assertEqual(finalizer.read_plan(self.home),self.plan)
        path=self.home/finalizer.PLAN_NAME
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        with self.assertRaisesRegex(finalizer.FinalizerError,'PLAN_WRITE_UNCERTAIN'):
            finalizer.persist_plan(self.home,self.plan)
        path.chmod(0o644)
        with self.assertRaisesRegex(finalizer.FinalizerError,'PLAN_UNSAFE'):self.hold()
        self.assertEqual(self.api.patches,[])

    def test_plan_symlink_and_hardlink_are_rejected(self):
        path=self.home/finalizer.PLAN_NAME;other=self.home/'other'
        os.link(path,other)
        with self.assertRaisesRegex(finalizer.FinalizerError,'PLAN_UNSAFE'):self.hold()
        other.unlink();path.unlink();path.symlink_to(other)
        with self.assertRaisesRegex(finalizer.FinalizerError,'PLAN_UNREADABLE'):self.hold()
        self.assertEqual(self.api.patches,[])

    def test_recovery_plan_must_still_match_journal_hash(self):
        path=self.home/finalizer.PLAN_NAME
        path.write_text(__import__('json').dumps(dict(self.plan,resource_version='78')))
        with self.assertRaisesRegex(finalizer.FinalizerError,'PLAN_MISMATCH'):self.hold()
        self.assertEqual(journal.read(self.home)['phase'],'prepared')
        self.assertEqual(self.api.patches,[])

    def test_failed_post_mutation_read_keeps_uncertain_journal(self):
        api=self.api;original=api.get;calls=[]
        def fail_second(name):
            calls.append(name)
            if len(calls)>1:raise finalizer.FinalizerError('KUBE_FINALIZER_API_UNCERTAIN')
            return original(name)
        api.get=fail_second
        with self.assertRaisesRegex(finalizer.FinalizerError,'API_UNCERTAIN'):self.hold()
        self.assertEqual(len(api.patches),1);self.assertTrue(api.pod['metadata']['finalizers'])
        self.assertEqual(journal.read(self.home)['phase'],'isolating')

    def test_timeout_kills_owned_credential_descendant_and_remains_uncertain(self):
        self._check_owned_descendant(early_exit=False)

    def test_successful_client_also_stops_owned_credential_descendant(self):
        self._check_owned_descendant(early_exit=True)

    def _check_owned_descendant(self,early_exit):
        executable=self.home/'kubectl'; marker=self.home/'descendant-write'; pidfile=self.home/'descendant-pid'
        executable.write_text(
            '#!/usr/bin/env python3\n'
            'import os,pathlib,subprocess,sys,time\n'
            'p=subprocess.Popen([sys.executable,"-c",'
            '"import os,pathlib,time;time.sleep(1);pathlib.Path(os.environ[\\\"MARKER\\\"]).write_text(\\\"bad\\\")"],'
            'stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n'
            'pathlib.Path(os.environ["PIDFILE"]).write_text(str(p.pid))\n'
            'if os.environ["EARLY"]=="yes":print("ok",flush=True);sys.exit(0)\n'
            'time.sleep(30)\n',encoding='utf-8')
        executable.chmod(0o700)
        env=dict(os.environ,PATH=str(self.home)+os.pathsep+os.environ['PATH'],
                 MARKER=str(marker),PIDFILE=str(pidfile),EARLY='yes' if early_exit else 'no')
        api=finalizer.Kubectl(context='kind-test',namespace='test',env=env)
        with patch.object(finalizer,'API_TIMEOUT',.4):
            if early_exit:self.assertEqual(api._call(['version']),b'ok\n')
            else:
                with self.assertRaisesRegex(finalizer.FinalizerError,'API_UNCERTAIN'):api._call(['version'])
        self.assertTrue(pidfile.exists())
        time.sleep(1.1)
        self.assertFalse(marker.exists())
