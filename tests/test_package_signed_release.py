import hashlib
import json
from pathlib import Path
import tempfile
import tarfile
import subprocess
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.extract_signed_bundle import extract
from scripts.package_signed_release import package


class SignedReleasePackagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.inputs=self.root/'inputs';self.inputs.mkdir()
        images={s:'registry.example/'+s+'@sha256:'+'b'*64 for s in ('guardrail','agent','redis')}
        records={s:{'image_id':'sha256:'+'c'*64} for s in images}
        for s in ('guardrail','agent'):records[s]['source_commit']='a'*40
        (self.inputs/'images.json').write_text(json.dumps(images));(self.inputs/'publication.json').write_text(json.dumps({'images':records}))
        key=Ed25519PrivateKey.generate();self.private=self.root/'private';self.public=self.root/'public'
        self.private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));self.private.chmod(0o600)
        self.public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        self.fingerprint=hashlib.sha256(self.public.read_bytes()).hexdigest()

    def test_packaged_archive_verifies_and_excludes_private_key(self):
        out=self.root/'release';result=package(self.inputs,'1.0.0',1,[],self.private,self.public,self.fingerprint,out)
        self.assertEqual(result['version'],'1.0.0');self.assertFalse((out/'INCOMPLETE').exists())
        extracted=self.root/'extracted';extract(out/'signed-bundle.tar.gz',self.public,extracted)
        self.assertFalse(any(p.name=='private' for p in extracted.rglob('*')))
        self.assertTrue((extracted/'scripts/update_installation.py').is_file())
        commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
        expected=subprocess.check_output(['git','show',commit+':compose/compose.yaml'])
        self.assertEqual((extracted/'compose/compose.yaml').read_bytes(),expected)
        self.assertEqual(result['deployment_commit'],commit)
        with tarfile.open(out/'signed-bundle.tar.gz','r:gz') as archive:
            self.assertTrue(all(m.uid==0 and m.gid==0 and not m.uname and not m.gname for m in archive))

    def test_signed_archive_hash_is_verified_end_to_end(self):
        from scripts.extract_release_inputs import extract as extract_inputs
        archive=self.root/'installation-inputs.tar.gz'
        for name in ('policy.toml','model_profiles.toml'):
            (self.inputs/name).write_text('policy')
        with tarfile.open(archive,'w:gz') as tar:
            for name in ('images.json','publication.json','policy.toml','model_profiles.toml'):
                tar.add(self.inputs/name,arcname=name)
        checksum=self.root/'checksum';checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
        out=self.root/'release'
        package(self.inputs,'1.0.0',1,[],self.private,self.public,self.fingerprint,out,archive)
        signed=self.root/'verified';extract(out/'signed-bundle.tar.gz',self.public,signed)
        extract_inputs(archive,checksum,self.root/'verified-inputs',bundle=signed,key=self.public)
        self.assertEqual((self.root/'verified-inputs'/'policy.toml').read_text(),'policy')
        archive.write_bytes(archive.read_bytes()+b'changed')
        checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
        with self.assertRaisesRegex(ValueError,'signed manifest'):
            extract_inputs(archive,checksum,self.root/'bad',bundle=signed,key=self.public)
        self.assertFalse((self.root/'bad').exists())

    def test_rejects_archive_that_does_not_match_inputs(self):
        archive=self.root/'inputs.tar.gz'
        with tarfile.open(archive,'w:gz') as tar:
            for name in ('images.json','publication.json'):
                tar.add(self.inputs/name,arcname=name)
            for name in ('policy.toml','model_profiles.toml'):
                (self.inputs/name).write_text('expected')
                tar.add(self.inputs/name,arcname=name)
        (self.inputs/'policy.toml').write_text('changed')
        with self.assertRaisesRegex(ValueError,'differs from release inputs'):
            package(self.inputs,'1.0.0',1,[],self.private,self.public,self.fingerprint,
                    self.root/'release',archive)

    def test_rejects_wrong_fingerprint_before_creating_output(self):
        out=self.root/'release'
        with self.assertRaisesRegex(ValueError,'fingerprint'):
            package(self.inputs,'1.0.0',1,[],self.private,self.public,'0'*64,out)
        self.assertFalse(out.exists())
