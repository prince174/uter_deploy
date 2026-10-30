from contextlib import contextmanager
import hashlib
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
    from scripts import (kubernetes_fence_coordinator as coordinator,
                         kubernetes_fence_profile_store as store,
                         kubernetes_sealed_config as sealed)
else:
    coordinator=store=sealed=None


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os,'memfd_create'),'Linux sealed memfd required')
class OperatorSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):KubernetesPinTests.setUpClass()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.home=self.root/'home';self.home.mkdir(mode=0o700);self.bundle=self.root/'bundle';self.bundle.mkdir()
        (self.bundle/'checksums.json').write_text('{}')
        self.pub=self.root/'publisher.pem';self.pub.write_text('synthetic-public');self.pub.chmod(0o600)
        self.key=self.root/'key';self.key.write_bytes(b'k'*32);self.key.chmod(0o600)
        p=KubernetesPinTests();p.setUp();r=RedisIdentityTests();r.setUp()
        self.raw=yaml.safe_dump(p.config).encode();self.config=self.root/'kubeconfig';self.config.write_bytes(self.raw);self.config.chmod(0o600)
        self.api_profile=dict(p.profile,kube_system_uid=r.cluster,namespace_uid='66666666-6666-6666-6666-666666666666',
                              redis_pvc_uid=r.pvc_uid,redis_deployment_uid=r.deploy_uid)
        self.manifest={'version':'0.1.6',**r.manifest}
        self.record={'schema':1,'site':r.site,'api':self.api_profile,
                     'writer_uids':{'agent':'77777777-7777-7777-7777-777777777777',
                                    'guardrail':'88888888-8888-8888-8888-888888888888'},
                     'release_version':'0.1.6',
                     'inventory_sha256':hashlib.sha256((self.bundle/'checksums.json').read_bytes()).hexdigest(),
                     'publisher_sha256':hashlib.sha256(self.pub.read_bytes()).hexdigest()}
        self.profile=self.root/'profile';store.create(self.profile,b'k'*32,self.record)
        self.objects={'kube-system':{'kind':'Namespace','metadata':{'name':'kube-system','uid':r.cluster}},
                      r.site:{'kind':'Namespace','metadata':{'name':r.site,'uid':self.api_profile['namespace_uid']}},
                      'pvc':r.pvc,'deployment':r.deployment}
        self.calls=[]
        class API:
            context='test';namespace=r.site
            def patch(inner,*args):self.calls.append(args);return None
        class Inner:
            home=self.home;site=r.site;manifest=self.manifest;profile=self.api_profile
            bundle=self.bundle;publisher_key=self.pub;key_digest=self.record['publisher_sha256']
            inventory_digest=self.record['inventory_sha256'];api=API()
            def _query(inner,args):
                kind=args[1]
                return self.objects[args[2]] if kind=='namespace' else self.objects[kind]
            def reverify(inner):return {'safe_to_update':False}
        self.inner=Inner()

    @contextmanager
    def open(self):
        with sealed.sealed(self.raw,self.api_profile) as (fd,digest):
            self.inner.config_fd=fd;self.inner.config_sha256=digest
            @contextmanager
            def fake_session(*args):yield self.inner
            with uterctl.locked(self.home),patch.object(coordinator.preflight,'checked_session',fake_session), \
                 patch.object(uterctl,'verify',return_value=self.manifest):
                with coordinator.checked_session(self.home,self.bundle,self.pub,self.config,self.profile,self.key) as session:
                    yield session

    def test_profile_change_blocks_before_mutating_request(self):
        with self.open() as session:
            self.profile.write_text('{"changed":true}')
            with self.assertRaises(coordinator.CoordinatorError):session.api.patch('x',[])
            self.assertEqual(self.calls,[])

    def test_profile_change_after_request_makes_outcome_uncertain(self):
        with self.open() as session:
            def mutate(*args):self.calls.append(args);self.profile.write_text('{"changed":true}')
            session.api._api.patch=mutate
            with self.assertRaises(coordinator.CoordinatorError):session.api.patch('x',[])
            self.assertEqual(len(self.calls),1)

    def test_pinned_pvc_change_blocks_before_request(self):
        with self.open() as session:
            self.objects['pvc']['metadata']['uid']='99999999-9999-9999-9999-999999999999'
            with self.assertRaises(coordinator.CoordinatorError):session.api.patch('x',[])
            self.assertEqual(self.calls,[])

    def test_missing_profile_never_reaches_preflight(self):
        self.profile.unlink()
        with patch.object(coordinator.preflight,'checked_session') as preflight:
            with self.assertRaises(coordinator.CoordinatorError):
                with coordinator.checked_session(self.home,self.bundle,self.pub,self.config,self.profile,self.key):pass
            preflight.assert_not_called()
