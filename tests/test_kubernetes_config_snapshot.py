import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import kubernetes_config_snapshot as config


@unittest.skipUnless(os.name=='posix','authenticated records require POSIX')
class ConfigSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.home=Path(self.temp.name)
        self.key=b'k'*32;self.op='a'*32
        self.names=['configmap/policy','pvc/uter-test-guardrail','pvc/uter-test-redis','secret/password']
        self.items={name:{'kind':'Secret' if name.startswith('secret/') else 'ConfigMap',
            'metadata':{'uid':'uid-'+str(i),'resourceVersion':'10'},'data':{'sensitive':'not-a-real-secret'}}
                    for i,name in enumerate(self.names)}
        self.session=SimpleNamespace(_executor=('signed',),_record={'schema':2},_key_path='key',home=self.home,
            _profile_digest='d'*64,manifest={},reverify=lambda:None,_scope=lambda:None)
        class Writer:
            manifest={'files':{}}
            def put(inner,label,stream):self.label=label;self.raw=stream.read()
        self.writer=Writer()

    def test_exact_versions_are_rechecked_and_written_to_supplied_writer(self):
        with patch.object(config.backup_installation,'safe_file',return_value=self.key), \
             patch.object(config.finalizer,'read_plan',return_value={}),patch.object(config.finalizer,'_check_journal'), \
             patch.object(config,'_objects',return_value=self.names),patch.object(config,'_read',side_effect=lambda s,n:self.items[n]), \
             patch.object(config.writer_guard,'verify'):
            self.assertFalse(config.prepare(self.session,self.op,self.key)['safe_to_backup'])
            self.assertEqual(config.capture(self.session,self.op,self.key,self.writer),
                {'kubernetes_component_captured':True,'complete_backup':False,'safe_to_update':False})
            self.assertEqual(self.label,'kubernetes');self.assertEqual(len(json.loads(self.raw)['items']),4)
            self.items['secret/password']['metadata']['resourceVersion']='11'
            with self.assertRaisesRegex(config.ConfigSnapshotError,'^KUBE_CONFIG_CAPTURE_UNVERIFIED$'):
                config.capture(self.session,self.op,self.key,self.writer)

    def test_undeclared_object_list_is_rejected(self):
        self.session.site='uter-test';self.session.api=SimpleNamespace(context='test')
        self.session._record={'object_uids':{'secret/password':'1','configmap/policy':'2'}}
        site={'backend':'helm','name':'uter-test','namespace':'uter-test','context':'test'}
        with patch.object(config.uterctl,'site_config',return_value=site), \
             patch.object(config.backup_snapshot,'kube_objects',return_value=self.names+['secret/extra']):
            with self.assertRaises(ValueError):config._objects(self.session)
