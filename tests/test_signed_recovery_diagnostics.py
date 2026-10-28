import json
from pathlib import Path
import tempfile
import unittest

from scripts.signed_recovery_diagnostics import recovery_category, recovery_phase

class RecoveryDiagnosticTests(unittest.TestCase):
    def test_only_whitelisted_categories_are_exposed(self):
        samples = {
            b'compose recovery: ValueError: Bundle inventory mismatch (changed, extra or missing file) secret=xyz': 'signed-bundle-inventory',
            b'kubernetes recovery: FileNotFoundError: confidential-path token=abc': 'file-not-found',
            b'compose recovery: RuntimeError: docker recovery operation failed; output withheld to protect data: token=abc': 'recovery-external-operation-failed',
            b'kubernetes recovery: InvalidTag: secret data': 'backup-authentication-failed',
            b'compose recovery: ValueError: do not expose this secret xyz': 'unclassified',
            b'\xff': 'unclassified',
        }
        for raw, expected in samples.items():
            with self.subTest(raw=raw): self.assertEqual(recovery_category(raw), expected)

    def test_phase_is_allowlisted_and_malformed_data_is_not_exposed(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp);self.assertEqual(recovery_phase(target),'unavailable')
            path=target/'recovery-operation.json';path.write_text(json.dumps({'phase':'restoring-volumes','id':'secret'}))
            self.assertEqual(recovery_phase(target),'restoring-volumes')
            path.write_text(json.dumps({'phase':'some secret'}));self.assertEqual(recovery_phase(target),'unknown')
            path.write_text('x'*4097);self.assertEqual(recovery_phase(target),'unknown')
            path.write_text('{bad');self.assertEqual(recovery_phase(target),'unavailable')
