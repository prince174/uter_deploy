import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from scripts import recovery_volume


def audit_archive(path, name):
    with tarfile.open(path, 'w') as archive:
        data=b'valid audit record\n'
        item=tarfile.TarInfo(name);item.size=len(data)
        archive.addfile(item,io.BytesIO(data))


class RecoveryVolumeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.volume=self.root/'volume';self.volume.mkdir()

    def test_redis_restores_only_to_empty_volume(self):
        source=self.root/'redis.rdb';source.write_bytes(b'REDIS0011snapshot')
        recovery_volume.populate_redis(source,self.volume)
        self.assertEqual((self.volume/'dump.rdb').read_bytes(),source.read_bytes())
        with self.assertRaisesRegex(ValueError,'not empty'):
            recovery_volume.populate_redis(source,self.volume)

    def test_existing_aof_is_never_overwritten(self):
        source=self.root/'redis.rdb';source.write_bytes(b'REDIS0011snapshot')
        (self.volume/'appendonlydir').mkdir()
        with self.assertRaisesRegex(ValueError,'not empty'):
            recovery_volume.populate_redis(source,self.volume)
        self.assertFalse((self.volume/'dump.rdb').exists())

    def test_both_audit_snapshot_layouts(self):
        for index,name in enumerate(('./audit.jsonl','audit/audit.jsonl')):
            with self.subTest(name=name):
                volume=self.root/f'audit-{index}';volume.mkdir()
                source=self.root/f'audit-{index}.tar';audit_archive(source,name)
                recovery_volume.populate_audit(source,volume)
                self.assertEqual((volume/'audit.jsonl').read_bytes(),b'valid audit record\n')

    def test_audit_traversal_never_writes(self):
        source=self.root/'bad.tar';audit_archive(source,'../audit.jsonl')
        with self.assertRaises(ValueError):recovery_volume.populate_audit(source,self.volume)
        self.assertEqual(list(self.volume.iterdir()),[])

    def test_rejects_invalid_rdb_before_writing(self):
        source=self.root/'invalid';source.write_bytes(b'not an rdb')
        with self.assertRaisesRegex(ValueError,'Invalid Redis'):
            recovery_volume.populate_redis(source,self.volume)
        self.assertEqual(list(self.volume.iterdir()),[])
