import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

from scripts import compose_maintenance_coordinator as coordinator
from scripts import redis_fence_journal as journal

_real_restart_check=coordinator._writers_restart_disabled

@unittest.skipUnless(os.name=='posix','durable private journal')
class PreparedCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name);self.home.chmod(0o700);self.key=b'k'*32
        self.record=journal.create(self.home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
        self.plan={'operation':self.record['operation'],'fixture':'plan'}
        self.writers={'agent':{'id':'c'*64},'guardrail':{'id':'d'*64}}
        self.intent=dict(self.writers);self.adapter=Mock()
        self.events=[];self.states={service:'running' for service in self.writers}
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        for obj,name,value in (
            (coordinator.backup_snapshot,'_require_fenced_operation_lock',None),
            (coordinator.maintenance_protocol,'verify_capability',{'version':'fixture'}),
            (coordinator.plans,'read',self.plan),
            (coordinator.fence,'Adapter',self.adapter),
            (coordinator.start,'_observe',(self.plan,self.writers,'e'*64)),
            (coordinator.start,'read_intent',self.intent),
            (coordinator,'_writers_restart_disabled',None)):
            self.stack.enter_context(patch.object(obj,name,return_value=value))

    def request(self,*,service,method,container_id,identity_guard):
        self.assertTrue(identity_guard())
        self.assertEqual(container_id,self.writers[service]['id'])
        if method=='POST':
            # Every POST must follow the fsynced write-once intent; Guardrail
            # additionally follows the Agent's persisted final receipt.
            self.assertTrue(list(self.home.glob('maintenance-intent-*.json')))
            if service=='guardrail':self.assertTrue(list(self.home.glob('maintenance-receipt-*.json')))
            self.states[service]='quiesced';state='draining'
        else:state=self.states[service]
        self.events.append((service,method))
        evidence=None
        if state=='quiesced':
            evidence=({'requests_drained':True,'redis':'not_used','audit':'guardrail_owned'} if service=='agent'
                      else {'redis_closed':True,'audit':{'last_seq':1,'last_hash':'f'*64,'verified':True,'fsynced':True}})
        value={'protocol':1,'boot_id':('1' if service=='agent' else '2')*32,'state':state,
               'safe_to_stop':state=='quiesced','active_requests':0,'error':None,'evidence':evidence}
        return (202 if state=='draining' else 200),json.dumps(value).encode()

    def test_missing_ingress_proof_refuses_before_transport_or_evidence(self):
        with patch.object(coordinator.maintenance_transport,'request') as request:
            with self.assertRaises(coordinator.ComposeMaintenanceError):
                coordinator.collect_prepared(self.home,'bundle','publisher',self.key)
        request.assert_not_called()
        self.assertEqual(journal.read(self.home),self.record)
        self.assertFalse(list(self.home.glob('maintenance-*.json')))
        self.adapter.close.assert_called_once()

    def test_mocked_guard_drives_real_recorder_in_order_without_authorizing_update(self):
        with patch.object(coordinator,'_verify_ingress',return_value=True), \
             patch.object(coordinator.maintenance_transport,'request',side_effect=self.request):
            result=coordinator.collect_prepared(self.home,'bundle','publisher',self.key)
        self.assertEqual(set(result),{'c'*64,'d'*64})
        self.assertLess(self.events.index(('agent','POST')),self.events.index(('guardrail','POST')))
        self.assertEqual(len(list(self.home.glob('maintenance-intent-*.json'))),2)
        self.assertEqual(len(list(self.home.glob('maintenance-receipt-*.json'))),2)
        self.assertEqual(journal.read(self.home),self.record)

    def test_guard_lost_after_agent_post_keeps_intent_and_never_calls_guardrail_post(self):
        def guard(*_):
            return ('agent','POST') not in self.events
        with patch.object(coordinator,'_verify_ingress',side_effect=guard), \
             patch.object(coordinator.maintenance_transport,'request',side_effect=self.request):
            with self.assertRaises(coordinator.ComposeMaintenanceError):
                coordinator.collect_prepared(self.home,'bundle','publisher',self.key)
        self.assertEqual(self.events.count(('agent','POST')),1)
        self.assertNotIn(('guardrail','POST'),self.events)
        self.assertEqual(len(list(self.home.glob('maintenance-intent-*.json'))),1)
        self.assertEqual(journal.read(self.home),self.record)

    def test_identity_change_refuses_before_protocol_or_evidence(self):
        changed=dict(self.writers,agent={'id':'e'*64})
        with patch.object(coordinator.start,'_observe',return_value=(self.plan,changed,'e'*64)), \
             patch.object(coordinator.maintenance_transport,'request') as request:
            with self.assertRaises(coordinator.ComposeMaintenanceError):
                coordinator.collect_prepared(self.home,'bundle','publisher',self.key)
        request.assert_not_called()
        self.assertEqual(journal.read(self.home),self.record)
        self.assertFalse(list(self.home.glob('maintenance-*.json')))

    def test_restart_policy_requires_exact_no_without_retry(self):
        for policy in ({'Name':'unless-stopped','MaximumRetryCount':0},
                       {'Name':'no','MaximumRetryCount':1}, None):
            with self.subTest(policy=policy), \
                 patch.object(coordinator.start.diagnostic,'_docker',return_value='fixture'), \
                 patch.object(coordinator.start.diagnostic,'_json',return_value=policy):
                with self.assertRaises(coordinator.ComposeMaintenanceError):
                    _real_restart_check(self.writers)
