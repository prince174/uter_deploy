import hashlib
import unittest
from unittest.mock import patch
from pathlib import Path
import tempfile

from scripts.verify_release_pair import verify_pair

class ReleasePairTests(unittest.TestCase):
    def test_accepts_only_explicit_compatible_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            key=Path(tmp)/'key';key.write_bytes(b'public-key')
            fingerprint=hashlib.sha256(b'public-key').hexdigest()
            old={'version':'0.1.2','data_epoch':1}
            new={'version':'0.1.3','data_epoch':1,'upgrade_from':['0.1.2'],'installation_archive_sha256':'a'*64}
            with patch('uterctl.verify', side_effect=[old,new]):
                self.assertEqual(verify_pair('old','new',key,fingerprint,'0.1.2','0.1.3'),(old,new))
            for bad in (dict(new,data_epoch=2),dict(new,upgrade_from=[]),dict(new,installation_archive_sha256='')):
                with self.subTest(bad=bad), patch('uterctl.verify', side_effect=[old,bad]):
                    with self.assertRaises(ValueError):
                        verify_pair('old','new',key,fingerprint,'0.1.2','0.1.3')
            with self.assertRaisesRegex(ValueError,'fingerprint'):
                verify_pair('old','new',key,'0'*64,'0.1.2','0.1.3')
