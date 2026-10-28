import os
from pathlib import Path
import tempfile
import unittest

from scripts.publisher_key import create


@unittest.skipUnless(os.name == 'posix', 'POSIX permission checks')
class PublisherKeyTests(unittest.TestCase):
    def test_new_keys_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); private=root/'private.pem'; public=root/'public.pem'
            fingerprint=create(private,public)
            self.assertEqual(len(fingerprint),64)
            self.assertEqual(private.stat().st_mode & 0o777,0o600)
            old=private.read_bytes()
            with self.assertRaises(ValueError):create(private,public)
            self.assertEqual(private.read_bytes(),old)

    def test_refuse_shared_private_directory(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o755)
            with self.assertRaisesRegex(ValueError,'inaccessible'):
                create(root/'private.pem',root/'public.pem')
