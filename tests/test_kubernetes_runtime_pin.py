import os
from pathlib import Path
import tempfile
import unittest

from scripts import backup_snapshot, backup_store, kubernetes_runtime_pin as pin


@unittest.skipUnless(os.name=='posix','private runtime requires POSIX')
class RuntimePinTests(unittest.TestCase):
    def test_decrypted_archive_must_equal_exact_runtime_pin(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);home=root/'home';home.mkdir(mode=0o700)
            runtime=home/'runtime';runtime.mkdir(mode=0o700)
            (runtime/'site.json').write_text('{"name":"test"}')
            (home/'state.json').write_text('{"version":"1"}')
            key=b'k'*32;digest=pin._inventory(home,key)
            site={'backend':'helm','name':'test','namespace':'test','context':'test'}
            writer=backup_store.BackupWriter(root/'backup',key,home,site,'0.1.6')
            backup_snapshot.archive_runtime(home,writer)
            pin.verify_archive(writer,key,digest)
            (runtime/'site.json').write_text('{"name":"changed"}')
            self.assertNotEqual(pin._inventory(home,key),digest)
            with self.assertRaises(pin.RuntimePinError):pin.verify_archive(writer,key,pin._inventory(home,key))
            encrypted=writer.path/'runtime.enc';data=bytearray(encrypted.read_bytes());data[32]^=1;encrypted.write_bytes(data)
            with self.assertRaises(pin.RuntimePinError):pin.verify_archive(writer,key,digest)

    def test_runtime_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder);(home/'runtime').symlink_to('/tmp')
            with self.assertRaises(ValueError):pin._inventory(home,b'k'*32)
