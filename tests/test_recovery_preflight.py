import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import uterctl
from scripts import backup_crypto, backup_store, recovery_preflight
from scripts.bundle import build


class RecoveryPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.home=self.root/'home';(self.home/'runtime').mkdir(parents=True)
        self.site={'backend':'compose','name':'uter-test','namespace':'uter-test','context':'default','smoke_command':['true']}
        uterctl.write(self.home/'runtime/site.json',self.site)
        self.keyfile=self.root/'backup-key';backup_crypto.create_key(self.keyfile)
        key=Ed25519PrivateKey.generate();private=self.root/'private';self.public=self.root/'public'
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        m={'schema':1,'config_schema':1,'status':'released','version':'1.0.0','source_commit':'a'*40,
           'data_epoch':1,'upgrade_from':[], 'images':{s:'registry.example/'+s+'@sha256:'+'b'*64 for s in ('guardrail','agent','redis')}}
        manifest=self.root/'manifest';manifest.write_text(json.dumps(m))
        (self.home/'releases').mkdir();build(manifest,self.home/'releases/1.0.0',private)
        uterctl.write(self.home/'state.json',{'current':m,'previous':None,'pending':None,'adopted_installer':True})
        uterctl.write(self.home/'install.json',{'backend':'compose','name':'uter-test','context':'default'})
        self.backup=self.root/'backup';writer=backup_store.BackupWriter(self.backup,backup_crypto.read_key(self.keyfile),self.home,self.site,'1.0.0')
        with tempfile.TemporaryFile() as stream:
            with tarfile.open(fileobj=stream,mode='w') as tar:
                for name in ('runtime','state.json','install.json','releases'):tar.add(self.home/name,arcname=name)
            stream.seek(0);writer.put('runtime',stream)
        writer.put('redis',io.BytesIO(b'REDIS0011data'))
        with tempfile.TemporaryFile() as stream:
            with tarfile.open(fileobj=stream,mode='w') as tar:
                data=b'audit';info=tarfile.TarInfo('audit.jsonl');info.size=len(data);tar.addfile(info,io.BytesIO(data))
            stream.seek(0);writer.put('audit',stream)
        writer.finish()

    def test_authenticated_and_signed_backup_is_staged(self):
        out=self.root/'stage';result=recovery_preflight.preflight(self.home,self.backup,self.keyfile,self.public,out)
        self.assertEqual(result['version'],'1.0.0');self.assertFalse((out/'INCOMPLETE').exists())
        self.assertTrue((out/'runtime-staged/runtime/site.json').exists())

    def test_wrong_publisher_key_marks_incomplete(self):
        wrong=self.root/'wrong';wrong.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        out=self.root/'stage'
        with self.assertRaises(Exception):recovery_preflight.preflight(self.home,self.backup,self.keyfile,wrong,out)
        self.assertTrue((out/'INCOMPLETE').exists())

    def test_rejects_backup_for_other_installation_before_export(self):
        other=self.root/'other';(other/'runtime').mkdir(parents=True);uterctl.write(other/'runtime/site.json',self.site)
        out=self.root/'stage'
        with self.assertRaisesRegex(ValueError,'different installation'):
            recovery_preflight.preflight(other,self.backup,self.keyfile,self.public,out)
        self.assertFalse(out.exists())

    def test_can_verify_backup_when_original_installation_is_missing(self):
        self.home.rename(self.root/'disconnected-original')
        out=self.root/'stage'
        result=recovery_preflight.preflight(self.home,self.backup,self.keyfile,self.public,out)
        self.assertEqual(result['version'],'1.0.0')
        self.assertFalse((out/'INCOMPLETE').exists())
