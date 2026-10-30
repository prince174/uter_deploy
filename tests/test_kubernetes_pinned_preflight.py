import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
import uterctl
from tests.test_kubernetes_fence_pin import KubernetesPinTests
from tests.test_kubernetes_redis_identity import RedisIdentityTests

if sys.platform.startswith('linux'):
    from scripts import kubernetes_pinned_preflight as preflight
else:
    preflight=None


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os,'memfd_create'),'Linux sealed memfd required')
class PinnedPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):KubernetesPinTests.setUpClass()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.home=Path(self.tmp.name)
        k=KubernetesPinTests();k.setUp();r=RedisIdentityTests();r.setUp()
        self.raw=yaml.safe_dump(k.config).encode();self.profile=dict(k.profile,
            kube_system_uid=r.cluster,namespace_uid='66666666-6666-6666-6666-666666666666',
            redis_pvc_uid=r.pvc_uid,redis_deployment_uid=r.deploy_uid)
        self.manifest=r.manifest;self.site=r.site
        (self.home/'key').write_text('synthetic-public-key');(self.home/'key').chmod(0o600)
        self.objects={'kube-system':{'kind':'Namespace','metadata':{'name':'kube-system','uid':r.cluster}},
                      r.site:{'kind':'Namespace','metadata':{'name':r.site,'uid':self.profile['namespace_uid']}},
                      r.site+'-redis':r.deployment,'pvc':r.pvc,'pods':{'items':[r.pod]},'replicaset':r.rs}
        (self.home/'runtime').mkdir()
        uterctl.write(self.home/'state.json',{'current':self.manifest,'pending':None,'adopted_installer':True})
        uterctl.write(self.home/'install.json',{'backend':'kubernetes','name':r.site,'context':'test'})
        uterctl.write(self.home/'runtime'/'site.json',{'backend':'helm','name':r.site,'namespace':r.site,
                       'context':'test','smoke_command':['synthetic']})
        class API:
            def __init__(inner,*args,**kwargs):inner.calls=[];inner.kwargs=kwargs
            def _call(inner,args):
                inner.calls.append(args)
                kind=args[2]
                if kind=='namespace':value=self.objects[args[3]]
                elif kind=='deployment':value=self.objects[self.site+'-redis']
                elif kind in ('pvc','pods','replicaset'):value=self.objects[kind]
                else:raise ValueError
                return json.dumps(value).encode()
        self.api_class=API

    def test_exact_sealed_config_and_live_objects_are_rechecked_under_lock(self):
        with uterctl.locked(self.home),patch.object(uterctl,'verify',return_value=self.manifest), \
             patch.object(preflight.finalizer,'Kubectl',self.api_class):
            with preflight.checked_session(self.home,self.home/'bundle',self.home/'key',self.raw,self.profile) as session:
                self.assertEqual(session.reverify()['safe_to_update'],False)
                self.assertIsInstance(session.api.kwargs['config_fd'],int)
                self.assertEqual(len(session.api.calls),12)
                changed=copy.deepcopy(self.objects['pvc']);changed['metadata']['uid']='77777777-7777-7777-7777-777777777777'
                self.objects['pvc']=changed
                with self.assertRaises(preflight.PreflightError):session.reverify()

    def test_wrong_pin_or_absent_lock_refuses_before_api(self):
        with patch.object(uterctl,'verify',return_value=self.manifest),patch.object(preflight.finalizer,'Kubectl') as api:
            with self.assertRaises(preflight.PreflightError):
                with preflight.checked_session(self.home,self.home/'bundle',self.home/'key',self.raw,self.profile):pass
            api.assert_not_called()
        bad=dict(self.profile,ca_sha256='0'*64)
        with uterctl.locked(self.home),patch.object(uterctl,'verify',return_value=self.manifest), \
             patch.object(preflight.finalizer,'Kubectl') as api:
            with self.assertRaises(ValueError):
                with preflight.checked_session(self.home,self.home/'bundle',self.home/'key',self.raw,bad):pass
            api.assert_not_called()

    def test_changed_trusted_key_or_signed_manifest_blocks_next_observation(self):
        with uterctl.locked(self.home),patch.object(uterctl,'verify',return_value=self.manifest) as verify, \
             patch.object(preflight.finalizer,'Kubectl',self.api_class):
            with preflight.checked_session(self.home,self.home/'bundle',self.home/'key',self.raw,self.profile) as session:
                baseline=len(session.api.calls)
                (self.home/'key').write_text('other-key')
                with self.assertRaises(preflight.PreflightError):session.reverify()
                self.assertEqual(len(session.api.calls),baseline)
                (self.home/'key').write_text('synthetic-public-key')
                verify.return_value={'images':{'redis':'different'}}
                with self.assertRaises(preflight.PreflightError):session.reverify()
                self.assertEqual(len(session.api.calls),baseline)
