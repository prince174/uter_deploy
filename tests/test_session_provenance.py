import contextlib
import io
import os
import unittest
from unittest.mock import patch

from scripts import session_migration_guard as guard
from scripts import session_provenance as provenance


class UnavailableProvenanceTests(unittest.TestCase):
    def test_no_input_is_accepted_or_disclosed(self):
        # Treat even convincing-looking or malicious values as unverified.
        candidates = [
            ('signed-snapshot', 0, b'sess:alice'),
            ('', -1, b''),
            ({'verified': True, 'owner': 'secret-owner'}, 0, b'sess:secret-key'),
            (None, None, None),
        ]
        for snapshot, database, key in candidates:
            with self.subTest(database=database):
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    with self.assertRaises(provenance.ProvenanceUnavailable) as error:
                        provenance.require_owner_proof(snapshot_id=snapshot, database=database, session_key=key)
                self.assertEqual(str(error.exception), 'SESSION_PROVENANCE_UNAVAILABLE')
                self.assertEqual(stdout.getvalue(), '')
                self.assertEqual(stderr.getvalue(), '')

    def test_environment_cannot_enable_source(self):
        fake_config = {'UTER_SESSION_PROVENANCE': 'trusted', 'UTER_SESSION_OWNER': 'alice'}
        with patch.dict(os.environ, fake_config):
            with self.assertRaises(provenance.ProvenanceUnavailable):
                provenance.require_owner_proof(snapshot_id='signed', database=0, session_key=b'sess:alice')

    def test_gate_remains_blocked_even_if_placeholder_is_patched(self):
        # The placeholder is not consulted by the existing fail-closed gate.
        with patch.object(provenance, 'require_owner_proof', return_value={'owner': 'alice'}), \
             patch.object(guard, '_query', side_effect=[b'databases\n1\n', b'0\n0\n']):
            with self.assertRaisesRegex(guard.SessionMigrationBlocked, '^SESSION_MIGRATION_FENCE_UNVERIFIED$'):
                guard.classify('/unused', {}, {}, {})

    def test_ambiguous_session_still_blocks_with_forged_configuration(self):
        with patch.dict(os.environ, {'UTER_SESSION_PROVENANCE': 'trusted'}), \
             patch.object(guard, '_query', side_effect=[b'databases\n1\n', b'0\n1\n']):
            with self.assertRaisesRegex(guard.SessionMigrationBlocked, '^SESSION_MIGRATION_AMBIGUOUS$'):
                guard.classify('/unused', {}, {}, {})
