import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import redis_fence_journal as journal


@unittest.skipUnless(os.name == 'posix', 'journal requires POSIX dirfd and fsync')
class FenceJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.fields = {'backend': 'compose', 'site': 'uter-test', 'resource': 'a'*64, 'plan_sha256': 'b'*64}

    def make(self):
        return journal.create(self.home, **self.fields)

    def test_durable_ordered_stages_and_kubernetes_identity(self):
        self.fields.update(backend='kubernetes', resource='7a1ae129-82a8-490f-86e3-84dfd735d330')
        initial = self.make()
        path = self.home/journal.NAME
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(journal.read(self.home), initial)
        record = initial
        success = ('prepared', 'isolating', 'isolated', 'capturing', 'captured', 'releasing', 'restored')
        for old, new in zip(success, success[1:]):
            record = journal.advance(self.home, operation=initial['operation'], expected=old, next_phase=new)
            self.assertEqual(journal.read(self.home), record)
        self.assertEqual(record['phase'], 'restored')
        self.assertEqual({key: value for key, value in record.items() if key != 'phase'},
                         {key: value for key, value in initial.items() if key != 'phase'})
        self.assertEqual(list(self.home.iterdir()), [path])

    def test_failed_operation_records_abort_before_restoration_from_every_stage(self):
        success = ('prepared', 'isolating', 'isolated', 'capturing', 'captured', 'releasing')
        for stop in success:
            with self.subTest(stop=stop), tempfile.TemporaryDirectory() as folder:
                initial = journal.create(folder, **self.fields)
                for old, new in zip(success, success[1:]):
                    if old == stop: break
                    journal.advance(folder, operation=initial['operation'], expected=old, next_phase=new)
                invalid = 'restored' if stop != 'releasing' else 'capturing'
                with self.assertRaises(journal.FenceJournalError):
                    journal.advance(folder, operation=initial['operation'], expected=stop, next_phase=invalid)
                abort = journal.advance(folder, operation=initial['operation'], expected=stop, next_phase='aborting')
                self.assertEqual(journal.read(folder), abort)
                final = journal.advance(folder, operation=initial['operation'], expected='aborting', next_phase='restored')
                self.assertEqual(final['phase'], 'restored')

    def test_refuses_existing_journal_skipped_or_stale_phase(self):
        initial = self.make()
        for kwargs in (dict(operation=initial['operation'], expected='prepared', next_phase='isolated'),
                       dict(operation='0'*32, expected='prepared', next_phase='isolating'),
                       dict(operation=initial['operation'], expected='isolated', next_phase='capturing')):
            with self.subTest(kwargs=kwargs), self.assertRaises(journal.FenceJournalError):
                journal.advance(self.home, **kwargs)
        with self.assertRaises(journal.FenceJournalError):
            self.make()
        self.assertEqual(journal.read(self.home), initial)

    def test_caller_operation_is_strict_and_existing_operation_cannot_be_reused_in_home(self):
        value = '1'*32
        record = journal.create(self.home, **self.fields, operation=value)
        self.assertEqual(record['operation'], value)
        with self.assertRaises(journal.FenceJournalError):
            journal.create(self.home, **self.fields, operation=value)
        self.assertEqual(journal.read(self.home),record)
        with tempfile.TemporaryDirectory() as other:
            for invalid in ('x'*32, '1'*31, 1, True):
                with self.subTest(invalid=invalid), self.assertRaises(journal.FenceJournalError):
                    journal.create(other, **self.fields, operation=invalid)

    def test_rejects_bad_fields_and_unexpected_data(self):
        for field, bad in (('site', '../secret'), ('resource', 'x'*64), ('plan_sha256', 'b'*63),
                           ('backend', 'other')):
            with self.subTest(field=field), self.assertRaises(journal.FenceJournalError):
                journal.create(self.home, **dict(self.fields, **{field: bad}))
        initial = self.make()
        path = self.home/journal.NAME
        path.write_text(json.dumps(dict(initial, password='do-not-store')))
        with self.assertRaises(journal.FenceJournalError):
            journal.read(self.home)

    def test_symlink_hardlink_permissions_and_large_journal_are_refused(self):
        initial = self.make()
        path = self.home/journal.NAME
        copy = self.home/'extra'
        os.link(path, copy)
        with self.assertRaises(journal.FenceJournalError): journal.read(self.home)
        copy.unlink()
        path.chmod(0o644)
        with self.assertRaises(journal.FenceJournalError): journal.read(self.home)
        path.chmod(0o600)
        path.unlink()
        path.symlink_to(copy)
        with self.assertRaises(journal.FenceJournalError): journal.read(self.home)
        path.unlink()
        path.write_text('x'*(journal.MAX_BYTES+1)); path.chmod(0o600)
        with self.assertRaises(journal.FenceJournalError): journal.read(self.home)
        path.unlink()
        self.assertEqual(initial['phase'], 'prepared')

    def test_untrusted_directory_is_refused(self):
        self.home.chmod(0o755)
        with self.assertRaisesRegex(journal.FenceJournalError, 'DIRECTORY_UNSAFE'):
            self.make()

    def test_failed_replace_keeps_prior_journal_and_removes_temporary_file(self):
        initial = self.make()
        with patch.object(journal.os, 'replace', side_effect=OSError('synthetic')):
            with self.assertRaisesRegex(journal.FenceJournalError, 'WRITE_FAILED'):
                journal.advance(self.home, operation=initial['operation'], expected='prepared', next_phase='isolating')
        self.assertEqual(journal.read(self.home), initial)
        self.assertEqual([p.name for p in self.home.iterdir()], [journal.NAME])

    def test_fsync_failure_is_reported_as_uncertain(self):
        initial = self.make()
        original = os.fsync
        calls = []
        def fail_directory(fd):
            calls.append(fd)
            if len(calls) == 2: raise OSError('synthetic fsync failure')
            return original(fd)
        with patch.object(journal.os, 'fsync', side_effect=fail_directory):
            with self.assertRaisesRegex(journal.FenceJournalError, 'WRITE_FAILED'):
                journal.advance(self.home, operation=initial['operation'], expected='prepared', next_phase='isolating')
        # A rename may already have happened; caller must inspect and never infer success.
        self.assertEqual(journal.read(self.home)['phase'], 'isolating')


if __name__ == '__main__':
    unittest.main()
