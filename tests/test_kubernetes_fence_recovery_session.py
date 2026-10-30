import json
import os
import sys
import unittest
from unittest.mock import patch

from tests import test_kubernetes_fence_coordinator as fixtures
from scripts import kubernetes_fence_finalizer as finalizer, redis_fence_journal as journal
if sys.platform.startswith('linux'):
    from scripts import kubernetes_fence_recovery_session as recovery
else:
    recovery=None


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os,'memfd_create'),'Linux memfd required')
class RecoverySessionTests(fixtures.OperatorSessionTests):
    def setUp(self):
        super().setUp()
        self.record.update(schema=2,audit_pvc_uid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',kubectl_sha256='f'*64)
        self.profile.unlink();fixtures.store.create(self.profile,b'k'*32,self.record)
        self.objects['audit']={'kind':'PersistentVolumeClaim','metadata':{'name':'uter-test-guardrail',
            'namespace':'uter-test','uid':self.record['audit_pvc_uid']},'status':{'phase':'Bound'}}
        original_query=self.inner._query
        self.inner._query=lambda args:self.objects['audit'] if args==['get','pvc','uter-test-guardrail'] else original_query(args)
        self.plan={'schema':1,'context':'test','namespace':'uter-test','pod':self.pod,
                   'uid':self.patch[0]['value'],'resource_version':'42',
                   'container_id':'containerd://'+'b'*64,'spec_sha256':'c'*64}
        finalizer.persist_plan(self.home,self.plan)
        self.op=journal.create(self.home,backend='kubernetes',site='uter-test',resource=self.plan['uid'],
                               plan_sha256=finalizer.plan_hash(self.plan))['operation']
        self.executor_identity=({'version':'test'},'d'*64,'e'*64)

    def test_seal_binds_recovery_without_authorizing_update(self):
        with self.open() as session:
            session._executor=(self.bundle,self.pub,self.executor_identity)
            with patch.object(recovery.coordinator,'_executor_identity',return_value=self.executor_identity):
                self.assertEqual(recovery.seal_before_mutation(session,self.op,b'k'*32),
                                 {'recovery_binding_saved':True,'safe_to_update':False})
                with self.assertRaises(recovery.RecoverySessionError):recovery.seal_before_mutation(session,self.op,b'k'*32)

    def test_recovery_session_rechecks_pin_after_nonpristine_state(self):
        class API:
            context='test';namespace='uter-test'
            def __init__(inner,*args,**kw):pass
            def _call(inner,args):
                kind=args[2];name=args[3]
                result=self.objects['audit'] if kind=='pvc' and name=='uter-test-guardrail' else (
                    self.objects[name] if kind=='namespace' else self.objects[kind])
                return json.dumps(result).encode()
        with self.open() as original:
            original._executor=(self.bundle,self.pub,self.executor_identity)
            with patch.object(recovery.coordinator,'_executor_identity',return_value=self.executor_identity):
                recovery.seal_before_mutation(original,self.op,b'k'*32)
                journal.advance(self.home,operation=self.op,expected='prepared',next_phase='isolating')
                state={'current':self.manifest,'pending':None,'adopted_installer':True}
                cfg={'backend':'kubernetes','name':'uter-test','context':'test'}
                site={'backend':'helm','name':'uter-test','namespace':'uter-test','context':'test'}
                with patch.object(recovery.uterctl,'read',side_effect=[state,cfg]), \
                     patch.object(recovery.uterctl,'site_config',return_value=site), \
                     patch.object(recovery.finalizer,'Kubectl',API), \
                     patch.object(recovery.preflight.Session,'reverify',side_effect=AssertionError('must not require pristine state')):
                    with recovery.checked_recovery_session(self.home,self.bundle,self.pub,self.config,self.profile,self.key,
                                executor_bundle=self.bundle,executor_key=self.pub) as resumed:
                        self.assertEqual(resumed.site,'uter-test')
                        self.assertEqual(journal.read(self.home)['phase'],'isolating')
                (self.home/recovery.NAME).write_text('{}')
                with patch.object(recovery.uterctl,'read',side_effect=[state,cfg]), \
                     patch.object(recovery.uterctl,'site_config',return_value=site), \
                     patch.object(recovery.finalizer,'Kubectl',API):
                    with self.assertRaises(recovery.RecoverySessionError):
                        with recovery.checked_recovery_session(self.home,self.bundle,self.pub,self.config,self.profile,self.key,
                                    executor_bundle=self.bundle,executor_key=self.pub):pass

    def test_missing_recovery_binding_refuses(self):
        with self.open() as session:
            session._executor=(self.bundle,self.pub,self.executor_identity)
            with patch.object(recovery.coordinator,'_executor_identity',return_value=self.executor_identity):
                with self.assertRaises(recovery.RecoverySessionError):recovery.seal_before_mutation(session,'f'*32,b'k'*32)
