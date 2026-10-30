import base64
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import snapshot_source, source_provenance


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        def git(*args):
            return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.DEVNULL)
        self.git = git
        git('init', '-q'); git('config', 'user.name', 'test'); git('config', 'user.email', 'test@example.invalid')
        (self.root/'tracked.txt').write_text('before\n', encoding='utf-8')
        git('add', 'tracked.txt'); git('commit', '-qm', 'baseline')
        self.sha = git('rev-parse', 'HEAD').decode().strip()
        (self.root/'tracked.txt').write_text('after\n', encoding='utf-8')
        self.patch = git('diff', '--binary', '--no-ext-diff')
        git('checkout', '--', 'tracked.txt')
        self.digest = hashlib.sha256(self.patch).hexdigest()
        self.encoded = base64.b64encode(self.patch).decode('ascii')

    def test_exact_patch_applies_to_clean_baseline(self):
        state = snapshot_source.apply(self.root, self.sha, self.digest, self.encoded)
        self.assertEqual(state, {'kind':'uncommitted_patch', 'baseline_commit':self.sha, 'patch_sha256':self.digest})
        self.assertEqual((self.root/'tracked.txt').read_text().strip(), 'after')

    def test_wrong_fingerprint_and_dirty_checkout_rejected(self):
        with self.assertRaises(ValueError): snapshot_source.apply(self.root, self.sha, '0'*64, self.encoded)
        (self.root/'other').write_text('x')
        with self.assertRaises(ValueError): snapshot_source.apply(self.root, self.sha, self.digest, self.encoded)

    def test_wrong_baseline_and_invalid_secret_rejected(self):
        with self.assertRaises(ValueError): snapshot_source.apply(self.root, 'a'*40, self.digest, self.encoded)
        with self.assertRaises(ValueError): snapshot_source.apply(self.root, self.sha, self.digest, '!secret!')

    def test_extra_or_mismatched_provenance_rejected(self):
        valid = {'kind':'uncommitted_patch', 'baseline_commit':self.sha, 'patch_sha256':self.digest}
        self.assertEqual(source_provenance.validate(valid, self.sha), valid)
        with self.assertRaises(ValueError): source_provenance.validate(dict(valid, extra='x'))
        with self.assertRaises(ValueError): source_provenance.validate(valid, 'f'*40)

    def test_secret_name_rejects_unrelated_or_injected_names(self):
        self.assertEqual(source_provenance.validate_secret_name('SOURCE_SNAPSHOT_'+'A'*32), 'SOURCE_SNAPSHOT_'+'A'*32)
        for name in ('SOURCE_READ_TOKEN', 'SOURCE_SNAPSHOT_PATCH_B64', '../bad', 'SOURCE_SNAPSHOT_'+'G'*32):
            with self.assertRaises(ValueError): source_provenance.validate_secret_name(name)


if __name__ == '__main__': unittest.main()
