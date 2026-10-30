import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import backup_store, update_wizard as wizard


@unittest.skipUnless(os.name == 'posix', 'Protected paths require Linux')
class SessionBlockWizardTests(unittest.TestCase):
    def setUp(self):
        # Retain unit coverage of the dormant result-classification branch.
        gate=patch.object(wizard.uterctl,'require_live_update_support',lambda: None)
        gate.start();self.addCleanup(gate.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.home, self.backups, self.keydir = root/'home', root/'backups', root/'key'
        for path in (self.home, self.backups, self.keydir):
            path.mkdir(mode=0o700)
        self.key = self.keydir/'backup.key'
        self.key.write_bytes(b'X'*32); self.key.chmod(0o600)
        self.old = {'version': '0.1.6', 'data_epoch': 1}
        self.new = {'version': '0.1.7', 'data_epoch': 2,
                    'session_identity_gate': {'schema': 1, 'from_epoch': 1, 'to_epoch': 2,
                                              'policy': 'block_unverified_sessions'}}
        self.site = {'backend': 'compose', 'name': 'uter-test', 'namespace': 'uter-test',
                     'context': 'default', 'port': 18000, 'guardrail_cpus': 4,
                     'smoke_command': ['check']}
        self.write_private(self.home/'install.json', {'backend': 'compose', 'name': 'uter-test',
            'context': 'default', 'port': 18000, 'guardrail_cpus': 4})
        self.write_private(self.home/'install-state.json', {'status': 'ready'})
        self.write_private(self.home/'state.json', {'adopted_installer': True, 'current': self.old, 'pending': None})
        (self.home/'runtime').mkdir(mode=0o700)
        self.write_private(self.home/'runtime/site.json', self.site)
        self.backup = self.backups/'uter-ci'
        writer = backup_store.BackupWriter(self.backup, b'X'*32, self.home, self.site, self.old['version'])
        for label in ('runtime', 'redis', 'audit'):
            writer.put(label, io.BytesIO(('synthetic-'+label).encode()))
        self.backup_id = writer.finish()['id']
        self.marker = self.home/'session-migration-block.json'
        self.marker_data = {'schema': 1, 'reason': 'SESSION_MIGRATION_AMBIGUOUS',
                            'old_version': '0.1.6', 'new_version': '0.1.7',
                            'backup_id': self.backup_id, 'backup_path': str(self.backup)}
        self.plan = {'home': self.home, 'old': self.old, 'new': self.new,
                     'backup_root': self.backups, 'backup_key': self.key}

    def write_private(self, path, value):
        path.write_text(json.dumps(value), encoding='utf-8'); path.chmod(0o600)

    def write_marker(self, **changes):
        self.write_private(self.marker, {**self.marker_data, **changes})

    def test_new_protected_marker_verifies_backup_without_exposing_key(self):
        self.write_marker()
        # Existing 0.1.6 controller writes this non-secret state with the
        # caller's umask; 0644 is protected by the owner-only home directory.
        (self.home/'state.json').chmod(0o644)
        blocked = wizard.fresh_session_block(self.plan, absent_before=True)
        self.assertIsInstance(blocked, wizard.SessionMigrationBlocked)
        self.assertTrue(blocked.backup_verified)
        self.assertEqual(str(blocked), 'SESSION_MIGRATION_AMBIGUOUS')
        human = io.StringIO(); machine = io.StringIO()
        with contextlib.redirect_stderr(human), contextlib.redirect_stdout(machine):
            wizard.report_error(blocked)
            wizard.report_error(blocked, machine=True)
        result = json.loads(machine.getvalue())
        self.assertEqual(result['result'], 'blocked')
        self.assertTrue(result['backup_independently_verified'])
        self.assertEqual(result['backup_id'], self.backup_id)
        self.assertNotIn('X'*32, human.getvalue()+machine.getvalue())
        self.assertNotIn(str(self.key), human.getvalue()+machine.getvalue())

    def test_tampered_backup_is_reported_as_unverified(self):
        self.write_marker()
        with (self.backup/'redis.enc').open('ab') as stream: stream.write(b'tamper')
        blocked = wizard.fresh_session_block(self.plan, absent_before=True)
        self.assertIsInstance(blocked, wizard.SessionMigrationBlocked)
        self.assertFalse(blocked.backup_verified)
        output = io.StringIO()
        with contextlib.redirect_stdout(output): wizard.report_error(blocked, machine=True)
        self.assertFalse(json.loads(output.getvalue())['backup_independently_verified'])

    def test_stale_marker_or_unsigned_policy_not_accepted(self):
        self.write_marker()
        self.assertIsNone(wizard.fresh_session_block(self.plan, absent_before=False))
        other = {**self.plan, 'new': {'version': '0.1.7', 'data_epoch': 2}}
        self.assertIsNone(wizard.fresh_session_block(other, absent_before=True))
        altered = {**self.new, 'session_identity_gate': {**self.new['session_identity_gate'], 'policy': 'other'}}
        self.assertIsNone(wizard.fresh_session_block({**self.plan, 'new': altered}, absent_before=True))

    def test_unsafe_or_forged_marker_is_not_accepted(self):
        cases = ({'reason': 'ATTACKER_CONTROLLED'}, {'old_version': '1.2.3'},
                 {'new_version': '9.9.9'}, {'backup_id': 'z'*32},
                 {'backup_path': str(self.home)}, {'backup_path': str(self.backups/'..'/'home')},
                 {'backup_path': str(self.backups/'fake\nsecret')})
        for case in cases:
            with self.subTest(case=case):
                self.write_marker(**case)
                self.assertIsNone(wizard.fresh_session_block(self.plan, absent_before=True))
        self.write_marker(); self.marker.chmod(0o644)
        self.assertIsNone(wizard.fresh_session_block(self.plan, absent_before=True))
        self.marker.unlink(); self.marker.symlink_to(self.backup/'manifest.json')
        self.assertIsNone(wizard.fresh_session_block(self.plan, absent_before=True))

    def test_hardlinked_marker_and_incomplete_state_refused(self):
        self.write_marker()
        os.link(self.marker, self.home/'linked-marker')
        self.assertIsNone(wizard.fresh_session_block(self.plan, absent_before=True))
        (self.home/'linked-marker').unlink()
        self.write_private(self.home/'state.json', {'adopted_installer': True, 'current': self.old, 'pending': {'secret': 'do-not-print'}})
        self.assertIsNone(wizard.fresh_session_block(self.plan, absent_before=True))

    def test_other_untrusted_exceptions_do_not_expose_detail(self):
        human = io.StringIO(); machine = io.StringIO()
        with contextlib.redirect_stderr(human), contextlib.redirect_stdout(machine):
            wizard.report_error(ValueError('secret-canary'))
            wizard.report_error(ValueError('secret-canary'), machine=True)
        self.assertNotIn('secret-canary', human.getvalue()+machine.getvalue())
        self.assertEqual(json.loads(machine.getvalue())['code'], 'INPUT_OR_VERIFICATION_FAILED')

    def fake_execute_plan(self):
        return {**self.plan, 'bundle': self.home/'target', 'current_bundle': self.home/'current',
                'publisher_key': self.home/'public.pem', 'fingerprint': 'a'*64,
                'tool': self.home/'target/scripts/update_installation.py', 'offline': False,
                'make_backups': False, 'make_keydir': False, 'create_key': False, 'adopted': True}

    def run_fake_execute(self, action):
        plan = self.fake_execute_plan()
        def verified(folder, key):
            return self.old if folder == plan['current_bundle'] else self.new
        with patch.object(wizard, 'prepare_plan', return_value=plan), \
             patch.object(wizard, 'verify_publisher', return_value=plan['publisher_key']), \
             patch.object(wizard, 'secure_bundle', side_effect=lambda path: path), \
             patch.object(wizard.uterctl, 'verify', side_effect=verified), \
             patch.object(wizard, 'run_updater', side_effect=action):
            return wizard.execute(plan)

    def test_execute_reports_only_new_marker_after_signed_updater_failure(self):
        def fail(argv):
            self.write_marker()
            raise wizard.WizardError('SIGNED_UPDATE_FAILED_INSPECT_STATE')
        with self.assertRaises(wizard.SessionMigrationBlocked) as caught:
            self.run_fake_execute(fail)
        self.assertEqual(str(caught.exception), 'SESSION_MIGRATION_AMBIGUOUS')
        self.assertTrue(caught.exception.backup_verified)

    def test_execute_never_interprets_stale_marker_or_timeout(self):
        self.write_marker()
        def fail(argv): raise wizard.WizardError('SIGNED_UPDATE_FAILED_INSPECT_STATE')
        with self.assertRaisesRegex(wizard.WizardError, '^SIGNED_UPDATE_FAILED_INSPECT_STATE$'):
            self.run_fake_execute(fail)
        self.marker.unlink()
        def timeout(argv):
            self.write_marker()
            raise wizard.WizardError('UPDATER_TIMEOUT_INSPECT_STATE')
        with self.assertRaisesRegex(wizard.WizardError, '^UPDATER_TIMEOUT_INSPECT_STATE$'):
            self.run_fake_execute(timeout)

    def test_check_only_does_not_claim_runtime_or_writer_fence_verified(self):
        result = wizard.check_only_result(self.plan)
        self.assertEqual(result['session_runtime_check'], 'not_run')
        self.assertEqual(result['external_writer_fence'], 'not_verified')
        self.assertEqual(result['result'], 'checked')
        ordinary = {**self.plan, 'new': {'version': '0.1.6', 'data_epoch': 1}}
        self.assertEqual(set(wizard.check_only_result(ordinary)), {'result', 'old_version', 'new_version'})

    def test_human_plan_describes_runtime_check_and_gate(self):
        plan = {**self.plan, 'name': 'uter-test', 'backend': 'compose', 'context': 'default',
                'create_key': False, 'offline': False}
        output = io.StringIO()
        with contextlib.redirect_stdout(output): wizard.display_plan(plan)
        self.assertIn('проверка плана её не проводит', output.getvalue())
        self.assertIn('обновление будет заблокировано', output.getvalue())
        self.assertNotIn('X'*32, output.getvalue())


if __name__ == '__main__':
    unittest.main()
