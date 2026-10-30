import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts import compose_nsfirewall_checkpoint as checkpoint


@unittest.skipUnless(os.name=='posix','POSIX secure filesystem required')
class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name);self.key=b'k'*32
        self.record={'operation':'a'*32,'site':'uter','resource':'b'*64,'plan_sha256':'c'*64}
        self.data={'schema':1,**self.record,'boot_id':'12345678-1234-1234-1234-123456789abc',
                   'pid':42,'pid_start':55,'net_dev':7,'net_ino':8,'firewall_sha256':'d'*64}

    def test_round_trip_tampering_wrong_key_and_binding_are_rejected(self):
        checkpoint.create(self.home,self.record,self.data,self.key)
        self.assertEqual(checkpoint.read(self.home,self.record,self.key),self.data)
        for key,record in ((b'x'*32,self.record),(self.key,{**self.record,'operation':'e'*32})):
            with self.subTest(record=record):
                with self.assertRaises(checkpoint.CheckpointError):checkpoint.read(self.home,record,key)
        path=self.home/checkpoint.NAME
        envelope=json.loads(path.read_text());envelope['data']['net_ino']+=1;path.write_text(json.dumps(envelope))
        with self.assertRaises(checkpoint.CheckpointError):checkpoint.read(self.home,self.record,self.key)

    def test_write_once_symlink_and_insecure_permissions_are_rejected(self):
        checkpoint.create(self.home,self.record,self.data,self.key)
        with self.assertRaises(checkpoint.CheckpointError):checkpoint.create(self.home,self.record,self.data,self.key)
        path=self.home/checkpoint.NAME;path.chmod(0o644)
        with self.assertRaises(checkpoint.CheckpointError):checkpoint.read(self.home,self.record,self.key)
        path.unlink();path.symlink_to(self.home/'missing')
        with self.assertRaises(checkpoint.CheckpointError):checkpoint.read(self.home,self.record,self.key)
        with self.assertRaises(checkpoint.CheckpointError):checkpoint.create(self.home,self.record,self.data,self.key)

    def test_process_and_boot_identity_have_valid_shapes(self):
        self.assertGreater(checkpoint.process_start(os.getpid()),0)
        self.assertRegex(checkpoint.boot_id(),r'^[0-9a-f-]{36}$')


if __name__=='__main__':unittest.main()
