from pathlib import Path
import hashlib
import io
import tempfile
import tarfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from extract_release_inputs import extract, REQUIRED


class ReleaseExtractionTests(unittest.TestCase):
    def test_checksum_and_member_validation(self):
        for entries, tamper, expected in [
            (sorted(REQUIRED), False, True),
            (sorted(REQUIRED) + ['../escape'], False, False),
            (sorted(REQUIRED) + ['images.json'], False, False),
            (sorted(REQUIRED), True, False),
        ]:
            with self.subTest(entries=entries, tamper=tamper), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); archive = root / 'installation-inputs.tar.gz'
                with tarfile.open(archive, 'w:gz') as tar:
                    for name in entries:
                        info = tarfile.TarInfo(name); data = b'{}'; info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
                sha = '0'*64 if tamper else hashlib.sha256(archive.read_bytes()).hexdigest()
                checksum = root / 'installation-inputs.tar.gz.sha256'
                checksum.write_text(sha + '  ' + archive.name + '\n')
                if expected:
                    extract(archive, checksum, root / 'inputs', legacy_unverified=True)
                    self.assertEqual({p.name for p in (root / 'inputs').iterdir()}, REQUIRED)
                else:
                    with self.assertRaises(ValueError):
                        extract(archive, checksum, root / 'inputs', legacy_unverified=True)
                    self.assertFalse((root / 'escape').exists())

    def test_signed_digest_rejects_modified_archive_even_with_new_checksum(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); archive=root/'installation-inputs.tar.gz'; checksum=root/'checksum'
            def create(payload):
                with tarfile.open(archive,'w:gz') as tar:
                    for name in sorted(REQUIRED):
                        data=payload if name=='images.json' else b'{}'
                        member=tarfile.TarInfo(name);member.size=len(data);tar.addfile(member,io.BytesIO(data))
                checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
            create(b'original')
            signed_hash=hashlib.sha256(archive.read_bytes()).hexdigest()
            with patch('uterctl.verify', return_value={'installation_archive_sha256':signed_hash}):
                extract(archive,checksum,root/'good',bundle=root/'bundle',key=root/'key')
                create(b'tampered')
                with self.assertRaisesRegex(ValueError,'signed manifest'):
                    extract(archive,checksum,root/'bad',bundle=root/'bundle',key=root/'key')
                self.assertFalse((root/'bad').exists())

    def test_key_and_bundle_must_be_supplied_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); archive=root/'archive'; archive.write_bytes(b'x')
            checksum=root/'checksum';checksum.write_text(hashlib.sha256(b'x').hexdigest()+'  archive\n')
            with self.assertRaisesRegex(ValueError,'Both signed bundle'):
                extract(archive,checksum,root/'out',bundle=root/'bundle')

    def test_unsigned_archive_requires_explicit_legacy_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = root / 'archive'; archive.write_bytes(b'x')
            checksum = root / 'checksum'; checksum.write_text(hashlib.sha256(b'x').hexdigest() + '  archive\n')
            with self.assertRaisesRegex(ValueError, 'signed bundle'):
                extract(archive, checksum, root / 'out')
            self.assertFalse((root / 'out').exists())

    def test_missing_signed_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = root / 'archive'; archive.write_bytes(b'x')
            checksum = root / 'checksum'; checksum.write_text(hashlib.sha256(b'x').hexdigest() + '  archive\n')
            with patch('uterctl.verify', return_value={}):
                with self.assertRaisesRegex(ValueError, 'signed manifest'):
                    extract(archive, checksum, root / 'out', bundle=root / 'bundle', key=root / 'key')
            self.assertFalse((root / 'out').exists())

    def test_actual_signed_bundle_extracts_and_detects_manifest_tampering(self):
        import json
        import subprocess
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from scripts.bundle import build
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = root / 'installation-inputs.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                for name in sorted(REQUIRED):
                    item=tarfile.TarInfo(name);item.size=2;tar.addfile(item,io.BytesIO(b'{}'))
            digest=hashlib.sha256(archive.read_bytes()).hexdigest()
            checksum=root/'checksum';checksum.write_text(digest+'  '+archive.name+'\n')
            key=Ed25519PrivateKey.generate(); private=root/'private';public=root/'public'
            private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
            manifest={'schema':1,'config_schema':1,'tooling_schema':1,'status':'released','version':'1.0.0',
                      'source_commit':'a'*40,'data_epoch':1,'upgrade_from':[],
                      'images':{s:'registry.example/'+s+'@sha256:'+'b'*64 for s in ('guardrail','agent','redis')},
                      'installation_archive_sha256':digest}
            mf=root/'manifest.json';mf.write_text(json.dumps(manifest));bundle=root/'bundle';build(mf,bundle,private)
            subprocess.run([sys.executable,str(bundle/'scripts/extract_release_inputs.py'),str(archive),str(checksum),
                            str(root/'good'),'--bundle',str(bundle),'--key',str(public)],check=True)
            self.assertFalse(list(bundle.rglob('__pycache__')))
            (bundle/'manifest.json').write_text('{}')
            result=subprocess.run([sys.executable,str(bundle/'scripts/extract_release_inputs.py'),str(archive),str(checksum),
                                   str(root/'bad'),'--bundle',str(bundle),'--key',str(public)],capture_output=True)
            self.assertNotEqual(result.returncode,0);self.assertFalse((root/'bad').exists())
