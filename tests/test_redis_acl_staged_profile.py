import base64
import json
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import uterctl
from scripts import bundle, redis_acl_staged


@unittest.skipUnless(os.name=='posix','POSIX trusted-file checks required')
class StagedSignedProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.signing=Ed25519PrivateKey.generate()
        self.private=self.root/'private.pem';self.publisher=self.root/'publisher.pem'
        self.private.write_bytes(self.signing.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.publisher.write_bytes(self.signing.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        self.manifest={'schema':1,'config_schema':1,'tooling_schema':1,'status':'released','version':'1.0.0',
          'source_commit':'a'*40,'data_epoch':1,'upgrade_from':[],
          'images':{name:'example/'+name+'@sha256:'+'b'*64 for name in ('guardrail','agent','redis')},
          'maintenance_protocol':{'version':1,'services':['agent','guardrail']}}
        source=self.root/'manifest.json';source.write_text(json.dumps(self.manifest))
        self.bundle=self.root/'bundle';bundle.build(source,self.bundle,self.private)
        (self.bundle/'compose').chmod(0o755)
        for asset in (self.bundle/'compose').iterdir():asset.chmod(0o644)

    def test_signed_profile_verified_and_wrong_profile_refused_even_when_resigned(self):
        self.assertEqual(redis_acl_staged.verify_profile(self.bundle,self.publisher),self.manifest)
        target=self.bundle/redis_acl_staged.PROFILE
        target.write_bytes(target.read_bytes().replace(b'uter-writer',b'fake-writer'))
        raw=json.dumps(uterctl.inventory(self.bundle),sort_keys=True,indent=2).encode()
        (self.bundle/'checksums.json').write_bytes(raw)
        (self.bundle/'checksums.sig').write_bytes(base64.b64encode(self.signing.sign(raw)))
        with self.assertRaisesRegex(redis_acl_staged.StagedError,'REDIS_STAGED_PROFILE_UNVERIFIED'):
            redis_acl_staged.verify_profile(self.bundle,self.publisher)

    def test_missing_signed_maintenance_capability_fails(self):
        manifest=self.bundle/'manifest.json';value=dict(self.manifest);del value['maintenance_protocol']
        manifest.write_text(json.dumps(value))
        raw=json.dumps(uterctl.inventory(self.bundle),sort_keys=True,indent=2).encode()
        (self.bundle/'checksums.json').write_bytes(raw)
        (self.bundle/'checksums.sig').write_bytes(base64.b64encode(self.signing.sign(raw)))
        with self.assertRaisesRegex(redis_acl_staged.StagedError,'REDIS_STAGED_PROFILE_UNVERIFIED'):
            redis_acl_staged.verify_profile(self.bundle,self.publisher)
