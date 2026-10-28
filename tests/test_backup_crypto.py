import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
from scripts import backup_crypto as backup


class BackupCryptoTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.key=b'x'*32;self.aad=b'test-backup:redis';self.data=b'REDIS0009'+b'test-data'*100000

    def encrypted(self):
        path=self.root/'artifact.enc'
        with path.open('wb') as out:meta=backup.encrypt_stream(io.BytesIO(self.data),out,self.key,self.aad)
        return path,meta

    def test_roundtrip_and_authenticated_manifest(self):
        path,meta=self.encrypted();output=io.BytesIO()
        backup.decrypt_verify(path,self.key,self.aad,meta,output)
        self.assertEqual(output.getvalue(),self.data)
        manifest={'version':'1.0.0','files':{'redis':meta}}
        signature=backup.sign_manifest(manifest,self.key);backup.verify_manifest(manifest,signature,self.key)
        manifest['version']='2.0.0'
        with self.assertRaises(ValueError):backup.verify_manifest(manifest,signature,self.key)

    def test_corruption_wrong_key_and_context_fail(self):
        path,meta=self.encrypted()
        for key,aad in ((b'y'*32,self.aad),(self.key,b'other')):
            with self.assertRaises(InvalidTag):backup.decrypt_verify(path,key,aad,meta)
        data=bytearray(path.read_bytes());data[25]^=1;path.write_bytes(data)
        with self.assertRaises(InvalidTag):backup.decrypt_verify(path,self.key,self.aad,meta)

    def test_restore_never_overwrites_and_failed_verify_leaves_no_output(self):
        path,meta=self.encrypted();target=self.root/'restored'
        with self.assertRaises(InvalidTag):backup.decrypt_to_new_file(path,target,b'z'*32,self.aad,meta)
        self.assertFalse(target.exists());self.assertEqual(list(self.root.glob('.uter-restore-*')),[])
        backup.decrypt_to_new_file(path,target,self.key,self.aad,meta);self.assertEqual(target.read_bytes(),self.data)
        with self.assertRaises(ValueError):backup.decrypt_to_new_file(path,target,self.key,self.aad,meta)

    def test_key_file_is_exclusive_and_private(self):
        path=self.root/'key';backup.create_key(path);self.assertEqual(len(backup.read_key(path)),32)
        with self.assertRaises(FileExistsError):backup.create_key(path)
        if os.name=='posix':
            path.chmod(0o644)
            with self.assertRaises(ValueError):backup.read_key(path)

    def test_key_is_not_kept_when_fsync_fails(self):
        path=self.root/'key'
        with patch.object(backup.os,'fsync',side_effect=OSError('sync failed')):
            with self.assertRaisesRegex(OSError,'sync failed'):backup.create_key(path)
        self.assertFalse(path.exists())
