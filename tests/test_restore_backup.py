import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from scripts import backup_crypto,backup_store,restore_backup


def archive(name='runtime/file',content=b'secret'):
    target=io.BytesIO()
    with tarfile.open(fileobj=target,mode='w') as tar:
        info=tarfile.TarInfo(name);info.size=len(content);tar.addfile(info,io.BytesIO(content))
    return target.getvalue()


class RestoreExportTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name)
        self.home=self.root/'home';self.home.mkdir();self.keyfile=self.root/'key';backup_crypto.create_key(self.keyfile)
        self.key=backup_crypto.read_key(self.keyfile)
        self.site={'backend':'compose','name':'uter-test','namespace':'uter-test','context':'default'}

    def build(self,audit=None):
        writer=backup_store.BackupWriter(self.root/'backup',self.key,self.home,self.site,'1.0.0')
        writer.put('runtime',io.BytesIO(archive()));writer.put('redis',io.BytesIO(b'REDIS0011data'))
        writer.put('audit',io.BytesIO(audit or archive('audit/audit.jsonl')));writer.finish();return writer

    def test_verified_export_and_no_overwrite(self):
        w=self.build();dest=self.root/'output';restore_backup.export(w.path,self.keyfile,dest)
        self.assertTrue((dest/'runtime.tar').exists());self.assertEqual((dest/'redis.rdb').read_bytes(),b'REDIS0011data')
        self.assertFalse((dest/'INCOMPLETE').exists())
        with self.assertRaisesRegex(ValueError,'already exists'):restore_backup.export(w.path,self.keyfile,dest)

    def test_traversal_is_rejected_without_extracting(self):
        w=self.build(archive('../outside'));dest=self.root/'output'
        with self.assertRaisesRegex(ValueError,'Unsafe path'):restore_backup.export(w.path,self.keyfile,dest)
        self.assertTrue((dest/'INCOMPLETE').exists());self.assertFalse((self.root/'outside').exists())

    def test_corrupted_backup_no_export_directory(self):
        w=self.build();path=w.path/'redis.enc';data=bytearray(path.read_bytes());data[22]^=1;path.write_bytes(data)
        with self.assertRaises(Exception):restore_backup.export(w.path,self.keyfile,self.root/'output')
        self.assertFalse((self.root/'output').exists())

    def test_stage_validated_archive_without_overwriting(self):
        path=self.root/'data.tar';path.write_bytes(archive('audit/audit.jsonl',b'audit'))
        stage=self.root/'stage';restore_backup.stage_archive(path,stage)
        self.assertEqual((stage/'audit/audit.jsonl').read_bytes(),b'audit')
        with self.assertRaisesRegex(ValueError,'already exists'):
            restore_backup.stage_archive(path,stage)

    def test_stage_rejects_traversal_before_creating_directory(self):
        path=self.root/'bad.tar';path.write_bytes(archive('../outside'))
        with self.assertRaisesRegex(ValueError,'Unsafe path'):
            restore_backup.stage_archive(path,self.root/'stage')
        self.assertFalse((self.root/'stage').exists())
