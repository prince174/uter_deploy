import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.bundle import build
from scripts.extract_signed_bundle import extract


class SignedBundleExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        key=Ed25519PrivateKey.generate();self.private=self.root/'private';self.public=self.root/'public'
        self.private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        manifest={'schema':1,'config_schema':1,'tooling_schema':1,'status':'released','version':'1.0.0',
                  'source_commit':'a'*40,'data_epoch':1,'upgrade_from':[],
                  'images':{s:'registry.example/'+s+'@sha256:'+'b'*64 for s in ('guardrail','agent','redis')}}
        source=self.root/'manifest.json';source.write_text(json.dumps(manifest));self.bundle=self.root/'bundle'
        build(source,self.bundle,self.private)

    def archive(self,name='bundle.tar.gz'):
        path=self.root/name
        with tarfile.open(path,'w:gz') as tar:tar.add(self.bundle,arcname='bundle')
        return path

    def test_verified_bundle_and_no_overwrite(self):
        archive=self.archive();output=self.root/'output'
        self.assertEqual(extract(archive,self.public,output)['version'],'1.0.0')
        self.assertTrue((output/'scripts/recover_compose.py').is_file())
        self.assertFalse((output/'INCOMPLETE').exists())
        with self.assertRaisesRegex(ValueError,'already exists'):extract(archive,self.public,output)

    def test_tampered_content_never_creates_destination(self):
        (self.bundle/'compose/compose.yaml').write_text('tampered')
        with self.assertRaisesRegex(ValueError,'inventory mismatch'):
            extract(self.archive(),self.public,self.root/'output')
        self.assertFalse((self.root/'output').exists())

    def test_rejects_parent_path_and_links(self):
        for index,name in enumerate(('bundle/../../escape','/absolute')):
            path=self.root/f'bad-{index}.tar'
            with tarfile.open(path,'w') as tar:
                info=tarfile.TarInfo(name);info.size=1;tar.addfile(info,io.BytesIO(b'x'))
            with self.assertRaisesRegex(ValueError,'Unsafe bundle path'):
                extract(path,self.public,self.root/f'out-{index}')
        path=self.root/'link.tar'
        with tarfile.open(path,'w') as tar:
            info=tarfile.TarInfo('bundle/link');info.type=tarfile.SYMTYPE;info.linkname='/tmp';tar.addfile(info)
        with self.assertRaisesRegex(ValueError,'Links'):
            extract(path,self.public,self.root/'out-link')
