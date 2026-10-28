from pathlib import Path
import hashlib
import io
import tempfile
import tarfile
import unittest
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
                    extract(archive, checksum, root / 'inputs')
                    self.assertEqual({p.name for p in (root / 'inputs').iterdir()}, REQUIRED)
                else:
                    with self.assertRaises(ValueError):
                        extract(archive, checksum, root / 'inputs')
                    self.assertFalse((root / 'escape').exists())
