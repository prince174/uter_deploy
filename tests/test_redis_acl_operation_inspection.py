import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import maintenance_evidence, redis_acl_operation_inspection as inspection, redis_fence_journal


class FixtureSession:
    def __init__(self,home,key_path):
        self.home=home;self.site='uter-ci';self._key_path=key_path;self._executor=object()
    def _guard(self): pass
    def reverify(self): pass
    def _query(self,args):
        if args[1]=='pods': return {'items':[self.pod]}
        return self.pod


class OperationInspectionTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        root=Path(tmp.name);self.home=root/'home';self.home.mkdir(mode=0o700)
        self.key=b'k'*32;key_path=root/'key';key_path.write_bytes(self.key);key_path.chmod(0o600)
        self.session=FixtureSession(self.home,key_path)
        self.operation='a'*32;self.plan_hash='b'*64;self.uid='11111111-1111-1111-1111-111111111111'
        spec={'containers':[{'name':'redis'}]}
        self.plan={'uid':self.uid,'namespace':self.session.site,'pod':'uter-ci-redis-abcd-xyz',
                   'container_id':'containerd://'+'e'*64,'spec_sha256':inspection.finalizer._digest(spec)}
        self.session.pod={'metadata':{'uid':self.uid,'name':self.plan['pod'],'namespace':self.session.site},'spec':spec,
            'status':{'phase':'Running','containerStatuses':[{'name':'redis','containerID':self.plan['container_id'],
                'restartCount':0,'state':{'running':{}}}]}}
        redis_fence_journal.create(self.home,backend='kubernetes',site=self.session.site,resource=self.uid,
            plan_sha256=self.plan_hash,operation=self.operation)
        self.recorder=maintenance_evidence.Recorder(self.home,self.key,operation=self.operation,
            backend='kubernetes',plan_sha256=self.plan_hash,lock_guard=lambda:True)
        self.base={'schema':1,'operation':self.operation,'backend':'kubernetes','site':self.session.site,
            'resource':self.uid,'plan_sha256':self.plan_hash,'admin_user':'uter-maint-test',
            'run_id':'c'*40,'client_id':'7','profile':'minimal-ci'}
        patches=[patch.object(inspection.coordinator,'BoundSession',FixtureSession),
                 patch.object(inspection.finalizer,'read_plan',return_value=self.plan),
                 patch.object(inspection.finalizer,'plan_hash',return_value=self.plan_hash),
                 patch.object(inspection.redis_acl_experiment,'inspect_after_failure',return_value={
                     'observation':'default_off_clients_present','retry_allowed':False,'recovery_automated':False,
                     'safe_to_backup':False,'safe_to_update':False})]
        for item in patches: item.start();self.addCleanup(item.stop)
    def mark(self,stage):
        self.recorder._write('redis-acl-intent-'+stage+'.json',{**self.base,'stage':stage})
    def check(self,key=None):
        return inspection.inspect(self.session,self.operation,self.key if key is None else key,lambda *_:None,
            admin_user='uter-maint-test',expected_run_id='c'*40,expected_client_id='7')
    def test_authenticated_intent_never_authorizes_update(self):
        self.mark('disable-default')
        self.assertFalse(self.check()['safe_to_update'])
        self.assertFalse(self.check()['retry_allowed'])
    def test_missing_tampered_or_wrong_key_fails_closed(self):
        with self.assertRaises(inspection.InspectionError): self.check()
        self.mark('disable-default')
        with self.assertRaises(inspection.InspectionError): self.check(b'x'*32)
        (self.home/'redis-acl-intent-disable-default.json').write_text('{}')
        with self.assertRaises(inspection.InspectionError): self.check()
    def test_tampered_kill_intent_and_process_identity_rejected(self):
        self.mark('disable-default');self.mark('kill-default')
        with self.assertRaises(inspection.InspectionError):
            inspection.inspect(self.session,self.operation,self.key,lambda *_:None,
                admin_user='uter-maint-test',expected_run_id='d'*40,expected_client_id='7')
        (self.home/'redis-acl-intent-kill-default.json').write_text('{}')
        with self.assertRaises(inspection.InspectionError): self.check()
    def test_never_returns_unsafe_diagnostic_flags(self):
        self.mark('disable-default')
        with patch.object(inspection.redis_acl_experiment,'inspect_after_failure',return_value={
                'observation':'default_off_only_admin','retry_allowed':False,'recovery_automated':False,
                'safe_to_backup':True,'safe_to_update':False}):
            with self.assertRaises(inspection.InspectionError): self.check()
    def test_replaced_redis_pod_is_rejected(self):
        self.mark('disable-default')
        self.session.pod['metadata']['uid']='22222222-2222-2222-2222-222222222222'
        with self.assertRaises(inspection.InspectionError): self.check()
        self.session.pod['metadata']['uid']=self.uid
        self.session.pod['status']['containerStatuses'][0]['containerID']='containerd://'+'f'*64
        with self.assertRaises(inspection.InspectionError): self.check()


if __name__ == '__main__': unittest.main()
