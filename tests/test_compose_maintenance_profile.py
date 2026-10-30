import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import yaml
import uterctl
from scripts import bundle, compose_maintenance_profile as subject


@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW') and os.geteuid()==0,
                     'requires root Linux POSIX file ownership')
class SignedComposeMaintenanceProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.home=self.root/'home';self.home.mkdir(mode=0o700)
        self.runtime=self.home/'runtime';self.runtime.mkdir(mode=0o700)
        key=self.runtime/'maintenance-key';key.write_bytes(b'K'*64);os.chown(key,10001,10001);key.chmod(0o400)
        self.signing=Ed25519PrivateKey.generate()
        self.private=self.root/'private.pem';self.publisher=self.root/'publisher.pem'
        self.private.write_bytes(self.signing.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.publisher.write_bytes(self.signing.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        images={name:'registry.example/'+name+'@sha256:'+'a'*64 for name in ('agent','guardrail','redis')}
        self.manifest={'schema':1,'config_schema':1,'tooling_schema':1,'status':'released','version':'1.0.0',
                       'source_commit':'a'*40,'data_epoch':1,'upgrade_from':[], 'images':images,
                       'maintenance_protocol':{'version':1,'services':['agent','guardrail']}}
        path=self.root/'manifest.json';path.write_text(json.dumps(self.manifest))
        self.bundle=self.root/'bundle';bundle.build(path,self.bundle,self.private)
        # The repository may be mounted from Windows; model a Linux release
        # with owner-controlled signed assets, not DrvFS's permissive modes.
        (self.bundle/'compose').chmod(0o755)
        for asset in (self.bundle/'compose').iterdir():asset.chmod(0o644)
        shutil.copytree(self.bundle/'compose',self.home/'compose')
        self.cfg={'backend':'compose','maintenance_enabled':True,'images':images.copy()}

    def verify(self):
        return subject.verify(self.bundle,self.publisher,self.home,self.cfg)

    def resign(self):
        raw=json.dumps(uterctl.inventory(self.bundle),sort_keys=True,indent=2).encode()
        (self.bundle/'checksums.json').write_bytes(raw)
        (self.bundle/'checksums.sig').write_bytes(base64.b64encode(self.signing.sign(raw)))

    def test_signed_overlay_and_private_mirrors(self):
        with patch('subprocess.Popen',side_effect=AssertionError('must not start a process')):
            result=self.verify()
        self.assertTrue(result['web_concurrency_env_requested'])
        for key in ('installation_state_verified','runtime_verified','redis_isolated','safe_to_backup','safe_to_update'):
            self.assertFalse(result[key])
        self.cfg['images']={name:'nexus.corp:5000/project/'+name+'@'+ref.split('@')[1]
                            for name,ref in self.cfg['images'].items()}
        self.assertEqual(self.verify(),result)

    def test_overlay_declares_exact_mount_and_one_worker_only(self):
        data=yaml.safe_load((self.bundle/'compose'/subject.OVERLAY).read_text())
        env={'UTER_MAINTENANCE_ENABLED':'true','UTER_MAINTENANCE_KEY_FILE':'/run/uter-maintenance/key',
             'WEB_CONCURRENCY':'1'}
        mount={'type':'bind','source':'${RUNTIME_DIR:?}/maintenance-key','target':'/run/uter-maintenance/key',
               'read_only':True,'bind':{'create_host_path':False}}
        self.assertEqual(data,{'services':{name:{'environment':env,'volumes':[mount]} for name in ('agent','guardrail')}})
        self.assertEqual(hashlib.sha256((self.bundle/'compose'/subject.OVERLAY).read_bytes()).hexdigest(),subject.OVERLAY_SHA256)

    def test_missing_capability_or_changed_images_refused(self):
        manifest_path=self.bundle/'manifest.json'
        value=json.loads(manifest_path.read_text());del value['maintenance_protocol']
        manifest_path.write_text(json.dumps(value));self.resign()
        with self.assertRaisesRegex(ValueError,'COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED'):self.verify()
        manifest_path.write_text(json.dumps(self.manifest));self.resign()
        self.cfg['images']['agent']='nexus.corp/agent@sha256:'+'b'*64
        with self.assertRaisesRegex(ValueError,'COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED'):self.verify()

    def test_overlay_tampering_and_resigned_wrong_profile_refused(self):
        overlay=self.bundle/'compose'/subject.OVERLAY
        overlay.write_bytes(overlay.read_bytes().replace(b"WEB_CONCURRENCY: '1'",b"WEB_CONCURRENCY: '2'"))
        (self.home/'compose'/subject.OVERLAY).write_bytes(overlay.read_bytes())
        with self.assertRaisesRegex(ValueError,'COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED'):self.verify()
        self.resign()
        with self.assertRaisesRegex(ValueError,'COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED'):self.verify()

    def test_missing_replaced_or_unprivate_key_refused_without_disclosure(self):
        key=self.runtime/'maintenance-key';key.chmod(0o444)
        with self.assertRaisesRegex(ValueError,'COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED') as error:self.verify()
        self.assertNotIn('KKKK',str(error.exception))
        key.unlink();key.symlink_to(self.root/'missing')
        with self.assertRaisesRegex(ValueError,'COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED'):self.verify()

    def test_disabled_or_missing_overlay_or_changed_base_refused(self):
        self.cfg['maintenance_enabled']=False
        with self.assertRaisesRegex(ValueError,'COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED'):self.verify()
        self.cfg['maintenance_enabled']=True
        local=self.home/'compose'/subject.OVERLAY;local.unlink()
        with self.assertRaisesRegex(ValueError,'COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED'):self.verify()
        shutil.copyfile(self.bundle/'compose'/subject.OVERLAY,local)
        with (self.home/'compose/compose.yaml').open('ab') as stream:stream.write(b'\n# changed')
        with self.assertRaisesRegex(ValueError,'COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED'):self.verify()

    def test_changed_both_compose_files_after_signature_verification_are_refused(self):
        original=subject.maintenance_protocol.verify_capability
        def mutate_after_verify(bundle_path,key_path):
            signed=original(bundle_path,key_path)
            for path in (self.bundle/'compose/compose.yaml',self.home/'compose/compose.yaml'):
                with path.open('ab') as stream:stream.write(b'\n# changed')
            return signed
        with patch.object(subject.maintenance_protocol,'verify_capability',side_effect=mutate_after_verify):
            with self.assertRaisesRegex(ValueError,'COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED'):self.verify()

    def test_untrusted_file_or_ancestor_refused(self):
        path=self.home/'compose/compose.yaml'; original=path.stat().st_mode & 0o777
        path.chmod(original | 0o020)
        with self.assertRaisesRegex(ValueError,'COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED'):self.verify()
        path.chmod(original)
        directory=self.home/'compose';directory.chmod(0o777)
        with self.assertRaisesRegex(ValueError,'COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED'):self.verify()
