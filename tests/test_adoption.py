import argparse
import base64
import contextlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import install, adopt_installation, adopt_managed, managed_smoke
from scripts.bundle import build
import uterctl


class AdoptionTests(unittest.TestCase):
    def test_compose_containerd_descriptor_must_match_signed_digest(self):
        ref='registry.example/guardrail@sha256:'+'a'*64
        digest=ref.split('@')[1]
        manifest={'images':{'guardrail':ref},'image_config_ids':{'guardrail':'sha256:'+'b'*64}}
        cfg={'backend':'compose','context':'default','name':'uter-test'}
        running={'running':True,'config_image':ref,'project':'uter-test','service':'guardrail','image':digest}
        image={'Id':digest,'Descriptor':{'digest':digest}}
        commands=[]
        def responses(command,env=None):
            commands.append(command)
            if 'context' in command and 'inspect' in command:return json.dumps('unix:///var/run/docker.sock').encode()
            if 'ps' in command:return b'a'*64
            if 'image' in command and '.Descriptor.Digest' in ' '.join(command):return json.dumps(image['Descriptor']['digest']).encode()
            if 'image' in command:return json.dumps(image['Id']).encode()
            return json.dumps(running).encode()
        with patch.dict('os.environ',{},clear=True),patch.object(adopt_installation.installer,'commands',return_value=(['compose'],{})),patch.object(adopt_installation,'output',side_effect=responses):
            adopt_installation.verify_live(Path('.'),cfg,manifest)
            image['Descriptor']['digest']='sha256:'+'c'*64
            with self.assertRaisesRegex(ValueError,'configuration ID mismatch'):
                adopt_installation.verify_live(Path('.'),cfg,manifest)
        for command in commands:
            if 'inspect' in command:
                self.assertIn('--format',command)
                self.assertNotIn('Config.Env',' '.join(command))

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.images={s:f'registry.example/{s}@sha256:'+'a'*64 for s in ('guardrail','agent','redis')}
        for name, data in [('images',json.dumps(self.images)),('policy','[policy]\nenabled=true\n'),('profiles','[profile]\nenabled=true\n')]:
            (self.root/name).write_text(data)
        self.key=Ed25519PrivateKey.generate();self.private=self.root/'private';self.pub=self.root/'public'
        self.private.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.pub.write_bytes(self.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        self.manifest={'schema':1,'config_schema':1,'status':'released','version':'1.0.0','source_commit':'b'*40,'data_epoch':1,'upgrade_from':[],'images':self.images}
        self.manifest_file=self.root/'manifest.json';self.manifest_file.write_text(json.dumps(self.manifest))
        self.bundle=self.root/'bundle';build(self.manifest_file,self.bundle,self.private)

    def prepare(self, backend='compose'):
        home=self.root/'installation'
        args=argparse.Namespace(home=home,backend=backend,name='uter-test',context='my-context' if backend=='kubernetes' else None,
            images=self.root/'images',policy=self.root/'policy',profiles=self.root/'profiles',llm_url='https://llm.example/v1',llm_model='test',
            allow_http_llm=False,port=18001,guardrail_cpus=2,storage_class='',registry_config=None)
        install.prepare(args,'')
        (home/'install-state.json').write_text('{"status":"ready"}')
        return home

    def test_adopt_preserves_runtime_and_does_not_deploy(self):
        for backend in ('compose','kubernetes'):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as temp:
                original=self.root; self.root=Path(temp)
                try:
                    for name,data in [('images',json.dumps(self.images)),('policy','[policy]\nenabled=true\n'),('profiles','[profile]\nenabled=true\n')]: (self.root/name).write_text(data)
                    home=self.prepare(backend); before=(home/'runtime/guardrail.env').read_bytes()
                    with patch.object(adopt_installation,'verify_live') as live, patch.object(adopt_installation.subprocess,'run',return_value=subprocess.CompletedProcess([],0)):
                        adopt_installation.adopt(home,self.bundle,self.pub,['smoke'])
                    self.assertEqual(uterctl.read(home/'state.json')['current'],self.manifest)
                    self.assertEqual((home/'runtime/guardrail.env').read_bytes(),before)
                    site=uterctl.site_config(home);self.assertEqual(site['port'],18001);self.assertEqual(site['guardrail_cpus'],2)
                    self.assertEqual(site['context'],'my-context' if backend=='kubernetes' else 'default');live.assert_called_once()
                    if backend=='kubernetes':self.assertEqual((home/'runtime/values.yaml').read_bytes(),(home/'values.yaml').read_bytes())
                finally:self.root=original

    def test_failed_smoke_does_not_adopt(self):
        home=self.prepare()
        with patch.object(adopt_installation,'verify_live'), patch.object(adopt_installation.subprocess,'run',return_value=subprocess.CompletedProcess([],1)):
            with self.assertRaisesRegex(ValueError,'smoke failed'):adopt_installation.adopt(home,self.bundle,self.pub,['smoke'])
        self.assertFalse((home/'state.json').exists());self.assertFalse((home/'runtime/site.json').exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX fence and locking')
    def test_adoption_refuses_fence_created_before_lock_without_smoke_or_writes(self):
        for managed in (False, True):
            with self.subTest(managed=managed), tempfile.TemporaryDirectory() as folder:
                original=self.root; self.root=Path(folder)
                try:
                    for name,data in [('images',json.dumps(self.images)),('policy','[policy]\nenabled=true\n'),
                                      ('profiles','[profile]\nenabled=true\n')]: (self.root/name).write_text(data)
                    home=self.prepare(); before=sorted(p.name for p in (home/'runtime').iterdir())
                    marker=home/'redis-fence-operation.json'; real_lock=uterctl.locked
                    @contextlib.contextmanager
                    def inject(path):
                        with real_lock(path):
                            marker.symlink_to(home/'missing')
                            yield
                    with patch.object(uterctl,'locked',side_effect=inject), \
                            patch.object(adopt_installation,'verify_live') as live, \
                            patch.object(adopt_installation.subprocess,'run') as smoke, \
                            patch.object(managed_smoke,'prepare') as prepare:
                        with self.assertRaisesRegex(ValueError,'^REDIS_FENCE_REQUIRES_INSPECTION$'):
                            if managed: adopt_managed.adopt(home,self.bundle,self.pub)
                            else: adopt_installation.adopt(home,self.bundle,self.pub,['smoke'])
                        live.assert_not_called();smoke.assert_not_called();prepare.assert_not_called()
                    self.assertEqual(before,sorted(p.name for p in (home/'runtime').iterdir()))
                    self.assertFalse((home/'state.json').exists())
                    self.assertTrue(marker.is_symlink())
                finally:self.root=original

    @unittest.skipUnless(os.name == 'posix', 'POSIX locking')
    def test_managed_smoke_files_are_prepared_under_adoption_lock(self):
        home=self.prepare(); real_prepare=managed_smoke.prepare
        def prepare(path):
            self.assertTrue((path/'operation.lock').is_file())
            return real_prepare(path)
        with patch.object(managed_smoke,'prepare',side_effect=prepare), \
                patch.object(adopt_installation,'verify_live'), \
                patch.object(adopt_installation.subprocess,'run',return_value=subprocess.CompletedProcess([],0)):
            adopt_managed.adopt(home,self.bundle,self.pub)
        self.assertTrue((home/'runtime/uter_managed_smoke.py').is_file())
        self.assertFalse((home/'operation.lock').exists())

    def test_signed_bundle_includes_and_protects_runtime_tooling(self):
        manifest=dict(self.manifest,tooling_schema=1)
        source=self.root/'tooling-manifest.json';source.write_text(json.dumps(manifest))
        bundle=self.root/'tooling-bundle';build(source,bundle,self.private)
        self.assertEqual(uterctl.verify(bundle,self.pub),manifest)
        self.assertTrue((bundle/'scripts/recovery_preflight.py').is_file())
        with (bundle/'scripts/recovery_preflight.py').open('a') as f:f.write('\n# changed\n')
        with self.assertRaisesRegex(ValueError,'inventory mismatch'):
            uterctl.verify(bundle,self.pub)

    def test_signed_tooling_cannot_omit_required_file(self):
        manifest=dict(self.manifest,tooling_schema=1)
        source=self.root/'tooling-manifest.json';source.write_text(json.dumps(manifest))
        bundle=self.root/'tooling-bundle';build(source,bundle,self.private)
        (bundle/'scripts/recovery_preflight.py').unlink()
        raw=json.dumps(uterctl.inventory(bundle),sort_keys=True,indent=2).encode()
        (bundle/'checksums.json').write_bytes(raw)
        (bundle/'checksums.sig').write_bytes(base64.b64encode(self.key.sign(raw)))
        with self.assertRaisesRegex(ValueError,'Missing scripts/recovery_preflight.py'):
            uterctl.verify(bundle,self.pub)

    def test_rejects_mismatch_and_modified_assets(self):
        home=self.prepare();cfg=uterctl.read(home/'install.json');cfg['images']['agent']='registry.example/agent@sha256:'+'c'*64;uterctl.write(home/'install.json',cfg)
        with self.assertRaisesRegex(ValueError,'image references'):adopt_installation.adopt(home,self.bundle,self.pub,['smoke'])
        cfg['images']=self.images;uterctl.write(home/'install.json',cfg)
        (home/'compose/compose.yaml').write_text('changed')
        with self.assertRaisesRegex(ValueError,'deployment assets'):adopt_installation.adopt(home,self.bundle,self.pub,['smoke'])

    def test_preserves_explicit_context_and_port(self):
        site={'context':'isolated','port':18001,'guardrail_cpus':2}
        env=uterctl.render_env(self.root,self.bundle,self.manifest,site)
        self.assertEqual(env['GUARDRAIL_PORT'],'18001');self.assertEqual(env['GUARDRAIL_CPUS'],'2')
        home=self.root/'helmhome';(home/'runtime').mkdir(parents=True);(home/'runtime/values.yaml').write_text('{}')
        site.update(backend='helm',name='uter-test',namespace='uter-test')
        with patch.object(uterctl,'run') as run:uterctl.deploy(home,self.bundle,self.manifest,site)
        self.assertTrue(all(c.args[0][:3]==['helm','--kube-context','isolated'] for c in run.call_args_list))
