import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import uterctl
from scripts import redis_fence_journal as journal


@unittest.skipUnless(os.name == 'posix', 'secure journal requires POSIX')
class FenceStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / 'home'
        self.home.mkdir(mode=0o700)

    def status(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            uterctl.main(['fence-status', '--home', str(self.home)])
        return json.loads(out.getvalue().splitlines()[0])

    def test_no_journal_is_only_an_observation(self):
        self.assertEqual(self.status(), {'journal': 'absent', 'finalize_anchor':'absent', 'update_intent':'absent','target_start':'absent','target_result':'absent','cleanup_intent':'absent','live_fence_verified': False})
        self.assertEqual(list(self.home.iterdir()), [])

    def test_existing_valid_journal_reports_phase_without_claiming_fence(self):
        record = journal.create(self.home, backend='compose', site='uter', resource='a'*64,
                                plan_sha256='b'*64)
        result = self.status()
        self.assertEqual(result, {'journal': 'present', 'backend': 'compose', 'phase': 'prepared',
                                  'operation': record['operation'], 'finalize_anchor':'absent','update_intent':'absent','target_start':'absent','target_result':'absent','cleanup_intent':'absent','live_fence_verified': False})
        self.assertEqual(journal.read(self.home), record)

    def test_invalid_or_dangling_journal_is_never_reported_absent(self):
        marker = self.home / journal.NAME
        marker.symlink_to(self.home / 'missing')
        with self.assertRaises(journal.FenceJournalError):
            self.status()
        marker.unlink()
        marker.write_text('{invalid', encoding='utf-8')
        marker.chmod(0o600)
        with self.assertRaises(journal.FenceJournalError):
            self.status()

    def test_missing_home_is_not_created(self):
        self.home.rmdir()
        with self.assertRaisesRegex(ValueError, 'Installation directory not found'):
            self.status()
        self.assertFalse(self.home.exists())

    def test_dangling_anchor_is_never_reported_as_unconditionally_absent(self):
        anchor=self.home/journal.FINALIZE_ANCHOR;anchor.symlink_to(self.home/'missing')
        self.assertEqual(self.status(),{'journal':'absent','finalize_anchor':'present','update_intent':'absent','target_start':'absent','target_result':'absent','cleanup_intent':'absent','live_fence_verified':False})
        self.assertTrue(anchor.is_symlink())

    def test_linked_anchor_reports_both_without_reading_two_link_journal(self):
        journal.create(self.home,backend='compose',site='uter',resource='a'*64,plan_sha256='b'*64)
        os.link(self.home/journal.NAME,self.home/journal.FINALIZE_ANCHOR)
        self.assertEqual(self.status(),{'journal':'present','finalize_anchor':'present','update_intent':'absent','target_start':'absent','target_result':'absent','cleanup_intent':'absent','live_fence_verified':False})

    def test_dangling_update_intent_is_reported(self):
        (self.home/journal.UPDATE_INTENT).symlink_to(self.home/'missing')
        self.assertEqual(self.status(),{'journal':'absent','finalize_anchor':'absent','update_intent':'present','target_start':'absent','target_result':'absent','cleanup_intent':'absent','live_fence_verified':False})

    def test_dangling_target_evidence_is_reported(self):
        for name,field in ((journal.UPDATE_START,'target_start'),(journal.UPDATE_RESULT,'target_result'),(journal.CLEANUP_INTENT,'cleanup_intent')):
            path=self.home/name;path.symlink_to(self.home/'missing')
            self.assertEqual(self.status()[field],'present');path.unlink()
