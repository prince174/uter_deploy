import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import uterctl
from scripts import update_installation as updater
from scripts.bundle import build


@unittest.skipUnless(os.name == 'posix', 'Managed update requires POSIX')
class OfflineManagedUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root/'home'; (self.home/'runtime').mkdir(parents=True)
        self.backups = self.root/'backups'; self.backups.mkdir(mode=0o700)
        self.keys = self.root/'keys'; self.keys.mkdir(mode=0o700)
        self.backup_key = self.keys/'backup.key'
        signer = Ed25519PrivateKey.generate()
        private = self.keys/'private.pem'; self.public = self.keys/'public.pem'
        private.write_bytes(signer.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
        self.public.write_bytes(signer.public_key().public_bytes(serialization.Encoding.PEM,
                                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
        self.images = {service: 'registry.example/'+service+'@sha256:'+'b'*64
                       for service in ('guardrail','agent','redis')}
        self.ids = {service: 'sha256:'+'c'*64 for service in self.images}
        self.old = {'schema':1,'config_schema':1,'tooling_schema':1,'status':'released','version':'1.0.0',
                    'source_commit':'a'*40,'data_epoch':1,'upgrade_from':[], 'images':self.images,
                    'image_config_ids':self.ids}
        self.new = dict(self.old, version='1.1.0', upgrade_from=['1.0.0'])
        for label, manifest in [('old',self.old),('new',self.new)]:
            source=self.root/(label+'.json'); source.write_text(json.dumps(manifest))
            build(source,self.root/label,private)
        self.cfg={'backend':'compose','name':'uter-test','context':'default','port':18000,'images':self.images}
        uterctl.write(self.home/'install.json',self.cfg)
        self.calls=[]

    def readonly(self, command, **kwargs):
        self.calls.append(command)
        if 'context' in command and 'inspect' in command:
            return json.dumps('unix:///var/run/docker.sock')
        ref=command[-1]
        if '{{json .Descriptor.Digest}}' in command:
            return json.dumps(ref.rsplit('@',1)[-1])
        return json.dumps({'id':'sha256:'+'c'*64,'refs':[ref],'os':'linux','arch':'amd64'})

    def update(self, **kwargs):
        with patch.dict(os.environ, {'DOCKER_HOST':''}), \
             patch.object(updater.install_recovery,'run_readonly',side_effect=self.readonly):
            return updater.update(self.home,self.root/'new',self.public,self.backups,self.backup_key,
                                  current_bundle=self.root/'old',create_backup_key=True,offline=True,**kwargs)

    def adopt_fixture(self, home, bundle, key):
        uterctl.write(Path(home)/'state.json',{'current':self.old,'previous':None,'pending':None,'adopted_installer':True})

    def apply_fixture(self, argv):
        self.assertIn('--offline',argv)
        self.assertEqual(argv[0],'apply')
        uterctl.write(self.home/'state.json',{'current':self.new,'previous':self.old,'pending':None,
                                            'adopted_installer':True,'last_backup':{'id':'fixture'}})

    def test_success_passes_offline_after_verifying_old_and_new_images(self):
        with patch.object(updater.adopt_managed,'adopt',side_effect=self.adopt_fixture) as adopt, \
             patch.object(updater.uterctl,'main',side_effect=self.apply_fixture) as apply:
            result=self.update()
        self.assertEqual(result['version'],'1.1.0')
        self.assertEqual(adopt.call_count,1); self.assertEqual(apply.call_count,1)
        inspections=[item for item in self.calls if 'image' in item and 'inspect' in item]
        self.assertEqual(len(inspections),6)
        self.assertFalse(any('pull' in command for command in self.calls))

    def test_missing_or_wrong_image_fails_before_key_adoption_or_update(self):
        original=self.readonly
        def wrong(command, **kwargs):
            if 'image' in command and 'inspect' in command:
                return json.dumps({'id':'sha256:'+'d'*64,'refs':[command[-1]],'os':'linux','arch':'amd64'})
            return original(command,**kwargs)
        self.readonly=wrong
        with patch.object(updater.adopt_managed,'adopt') as adopt, patch.object(updater.uterctl,'main') as apply:
            with self.assertRaisesRegex(ValueError,'not available locally'):
                self.update()
            adopt.assert_not_called();apply.assert_not_called()
        self.assertFalse(self.backup_key.exists());self.assertFalse((self.home/'state.json').exists())
        self.assertEqual(list(self.backups.iterdir()),[])

    def test_containerd_descriptor_representation_is_supported(self):
        original=self.readonly
        def descriptor(command, **kwargs):
            if 'image' in command and 'inspect' in command:
                digest=command[-1].rsplit('@',1)[-1]
                if '{{json .Descriptor.Digest}}' in command:
                    return json.dumps(digest)
                return json.dumps({'id':digest,'refs':[],'os':'linux','arch':'amd64'})
            return original(command,**kwargs)
        self.readonly=descriptor
        with patch.object(updater.adopt_managed,'adopt',side_effect=self.adopt_fixture), \
             patch.object(updater.uterctl,'main',side_effect=self.apply_fixture):
            self.assertEqual(self.update()['version'],'1.1.0')

    def test_kubernetes_rejected_before_network_and_mutations(self):
        self.cfg.update(backend='kubernetes',context='kind-other')
        uterctl.write(self.home/'install.json',self.cfg)
        with patch.object(updater.adopt_managed,'adopt') as adopt, patch.object(updater.uterctl,'main') as apply:
            with self.assertRaisesRegex(ValueError,'Compose only'):
                self.update()
            adopt.assert_not_called();apply.assert_not_called()
        self.assertEqual(self.calls,[]);self.assertFalse(self.backup_key.exists())

    def test_foreign_or_missing_context_rejected_before_mutations(self):
        for context in ('other',''):
            with self.subTest(context=context):
                self.cfg['context']=context;uterctl.write(self.home/'install.json',self.cfg)
                with patch.object(updater.adopt_managed,'adopt') as adopt:
                    with self.assertRaisesRegex(ValueError,'Compose only'):
                        self.update()
                    adopt.assert_not_called()
                self.assertFalse(self.backup_key.exists());self.assertEqual(self.calls,[])

    def test_adopted_installation_requires_matching_signed_current_bundle(self):
        uterctl.write(self.home/'state.json',{'current':self.old,'pending':None,'adopted_installer':True})
        uterctl.write(self.home/'runtime/site.json',{'backend':'compose','name':'uter-test','namespace':'uter-test',
                     'context':'default','smoke_command':['true']})
        (self.home/'releases').mkdir()
        shutil.copytree(self.root/'old',self.home/'releases'/'1.0.0')
        (self.home/'releases'/'1.0.0'/'compose/compose.yaml').write_text('changed')
        with patch.object(updater.uterctl,'main') as apply:
            with self.assertRaisesRegex(ValueError,'inventory mismatch'):
                self.update()
            apply.assert_not_called()
        self.assertEqual(self.calls,[]); self.assertFalse(self.backup_key.exists())

    def test_remote_docker_host_is_refused_before_query(self):
        with patch.dict(os.environ, {'DOCKER_HOST':'tcp://example:2375'}), \
             patch.object(updater.install_recovery,'run_readonly') as call:
            with self.assertRaisesRegex(ValueError,'local Unix Docker'):
                updater.verify_offline_images(self.cfg,(self.old,self.new))
            call.assert_not_called()

    def test_wrong_platform_or_nonmatching_reference_is_refused(self):
        for value in ({'id':'sha256:'+'c'*64,'refs':list(self.images.values()),'os':'windows','arch':'amd64'},
                      {'id':'sha256:'+'c'*64,'refs':[],'os':'linux','arch':'amd64'},
                      {'id':'sha256:'+'c'*64,'refs':list(self.images.values()),'os':'linux','arch':'arm64'}):
            def probe(command, **kwargs):
                return json.dumps('unix:///var/run/docker.sock') if 'context' in command and 'inspect' in command else json.dumps(value)
            with self.subTest(value=value), patch.dict(os.environ, {'DOCKER_HOST':''}), \
                    patch.object(updater.install_recovery,'run_readonly',side_effect=probe):
                with self.assertRaisesRegex(ValueError,'not available locally'):
                    updater.verify_offline_images(self.cfg,(self.old,self.new))


if __name__ == '__main__':
    unittest.main()
