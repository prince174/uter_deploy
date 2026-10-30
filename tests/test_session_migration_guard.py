import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import uterctl
from scripts import session_migration_guard as guard
from tests import test_controller as fixtures

ROOT = Path(__file__).resolve().parents[1]
GATE = {'schema': 1, 'from_epoch': 1, 'to_epoch': 2, 'policy': 'block_unverified_sessions'}
OLD_CONTROLLER_COMMIT = '7d2c38450776df9a479e5e2b0933ec1c23204e96'


class RedisGuardTests(unittest.TestCase):
    def test_internal_empty_scan_is_not_update_authorization(self):
        with patch.object(guard, '_query', side_effect=[b'databases\n1\n', b'0\n0\n']):
            self.assertIsNone(guard._scan_for_legacy_sessions('/x', {}, {}, {}))
        with patch.object(guard, '_scan_for_legacy_sessions', return_value=None):
            with self.assertRaisesRegex(guard.SessionMigrationBlocked, '^SESSION_MIGRATION_FENCE_UNVERIFIED$'):
                guard.classify('/x', {}, {}, {})

    def test_internal_scan_always_refuses_legacy_session(self):
        with patch.object(guard, '_query', side_effect=[b'databases\n2\n', b'0\n0\n', b'0\n1\n']):
            with self.assertRaisesRegex(guard.SessionMigrationBlocked, '^SESSION_MIGRATION_AMBIGUOUS$'):
                guard._scan_for_legacy_sessions('/x', {}, {}, {})

    def test_scanner_targets_only_the_selected_local_redis_and_no_password_argument(self):
        cfg={'backend':'compose','context':'default','name':'uter-ci','images':{}}
        site={'backend':'compose','context':'default','name':'uter-ci','namespace':'uter-ci'}
        current={'version':'0.1.0','images':{}}
        with patch.object(guard.install, 'commands', return_value=(['docker','-f','original'], {})):
            argv, env = guard._redis_command('/private-home', cfg, site, current, ['-n','3','EVAL_RO',guard._SCRIPT,'0'])
        self.assertEqual(argv[:3], ['docker','-f','/private-home/releases/0.1.0/compose/compose.yaml'])
        self.assertIn('redis', argv); self.assertIn('/run/secrets/redis_password', argv[-1])
        self.assertNotIn('secret-canary', ' '.join(argv)); self.assertEqual(env, {})
        kube=dict(cfg,backend='kubernetes',context='kind-test')
        kube_site=dict(site,backend='helm',context='kind-test')
        argv, env = guard._redis_command('/private-home', kube, kube_site, current, ['CONFIG','GET','databases'])
        self.assertEqual(argv[:4], ['kubectl','--context','kind-test','-n'])
        self.assertIn('deployment/uter-ci-redis', argv); self.assertIsNone(env)
        with self.assertRaises(guard.SessionMigrationBlocked):
            guard._redis_command('/private-home', kube, dict(kube_site,namespace='other'), current, [])

    def test_scan_all_databases_and_block_when_fence_is_unverified(self):
        with patch.object(guard, '_query', side_effect=[b'databases\n3\n', b'0\n0\n', b'12\n0\n', b'0\n0\n', b'0\n0\n']) as query:
            with self.assertRaisesRegex(guard.SessionMigrationBlocked, '^SESSION_MIGRATION_FENCE_UNVERIFIED$'):
                guard.classify('/x', {}, {}, {})
        self.assertEqual([call.args[4][:2] for call in query.call_args_list[1:]],
                         [['-n', '0'], ['-n', '1'], ['-n', '1'], ['-n', '2']])
        self.assertEqual(query.call_args_list[3].args[4][-1], '12')
        self.assertIn("'sess:*'", guard._SCRIPT)

    def test_any_existing_session_fails_closed_without_key_disclosure(self):
        with patch.object(guard, '_query', side_effect=[b'databases\n2\n', b'0\n0\n', b'0\n1\n']):
            with self.assertRaisesRegex(guard.SessionMigrationBlocked, '^SESSION_MIGRATION_AMBIGUOUS$') as error:
                guard.classify('/x', {}, {}, {})
        self.assertNotIn('sess:', str(error.exception))

    def test_invalid_or_incomplete_scans_fail_closed(self):
        for responses in ([b'ERR permission denied\n'], [b'databases\n0\n'],
                          [b'databases\n257\n'], [b'databases\n1\n', b'-1\n0\n'],
                          [b'databases\n1\n', b'ERR\n'],
                          [b'databases\n1\n', b'13\n0\n', b'13\n0\n']):
            with self.subTest(responses=responses), patch.object(guard, '_query', side_effect=responses):
                with self.assertRaisesRegex(guard.SessionMigrationBlocked, '^SESSION_MIGRATION_SCAN_FAILED$'):
                    guard.classify('/x', {}, {}, {})

    def test_failed_process_and_timeout_are_not_exposed(self):
        cases = ('import sys;print("secret-canary");sys.exit(1)',
                 'import time;time.sleep(5)', 'print("secret-canary"*10000)')
        for code in cases:
            with self.subTest(code=code), patch.object(guard, '_redis_command',
                    return_value=([sys.executable, '-c', code], None)):
                with self.assertRaisesRegex(guard.SessionMigrationBlocked, '^SESSION_MIGRATION_SCAN_FAILED$') as error:
                    guard._query('/x', {}, {}, {}, [], 1)
                self.assertNotIn('secret-canary', str(error.exception))


class ControllerSessionGateTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.ControllerTests(methodName='runTest')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.key = self.fx.prepare_adopted()
        self.target = fixtures.manifest('1.1.0', ['1.0.0'])
        self.target['data_epoch'] = 2
        self.target['session_identity_gate'] = dict(GATE)
        self.bundle = self.fx.bundle(self.target, 'new')
        helper = self.bundle/'scripts/session_migration_guard.py'
        helper.parent.mkdir(exist_ok=True)
        helper.write_text('# test fixture\n')
        self.fx.sign(self.bundle)

    def execute(self):
        return self.fx.call('apply', self.bundle,
            ['--backup-dir', str(self.fx.root/'backup'), '--backup-key', str(self.key)])

    def capture(self, home, cfg, site, current, destination, key, *, leave_stopped):
        self.assertTrue(leave_stopped)
        Path(destination).mkdir()
        uterctl.write(Path(home)/'backup-operation.json', {'phase':'quiesced'})
        return {'id':'d'*32, 'version':'1.0.0'}

    def test_signed_gate_required_for_cross_epoch(self):
        self.assertEqual(uterctl.verify(self.bundle, self.fx.pub)['session_identity_gate'], GATE)
        uterctl.transition(fixtures.manifest(), self.target)
        for bad in ({}, {'schema':True,'from_epoch':1,'to_epoch':2,'policy':'block_unverified_sessions'},
                    {'schema':1,'from_epoch':1,'to_epoch':2,'policy':'allow'}):
            invalid = copy.deepcopy(self.target); invalid['session_identity_gate'] = bad
            with self.subTest(bad=bad), self.assertRaises(ValueError): uterctl.validate(invalid)
        missing = copy.deepcopy(self.target); missing.pop('session_identity_gate')
        with self.assertRaisesRegex(ValueError, 'Data migration required'): uterctl.transition(fixtures.manifest(), missing)
        unchanged_version = copy.deepcopy(self.target); unchanged_version['version'] = '1.0.0'
        with self.assertRaisesRegex(ValueError, 'Data migration required'):
            uterctl.transition(fixtures.manifest(), unchanged_version)

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX symlink handling')
    def test_existing_fence_journal_blocks_controller_before_backup_or_deploy(self):
        marker = self.fx.home/'redis-fence-operation.json'
        before = (self.fx.home/'state.json').read_bytes()
        for dangling in (False, True):
            with self.subTest(dangling=dangling):
                if dangling:
                    marker.symlink_to(self.fx.home/'missing-target')
                else:
                    marker.write_text('{}')
                try:
                    with patch.object(uterctl, 'deploy') as deploy, patch('scripts.backup_snapshot.capture') as capture:
                        with self.assertRaisesRegex(ValueError, '^REDIS_FENCE_REQUIRES_INSPECTION$'):
                            self.execute()
                    deploy.assert_not_called(); capture.assert_not_called()
                    self.assertEqual((self.fx.home/'state.json').read_bytes(), before)
                finally:
                    marker.unlink()

    def test_historical_old_controller_refuses_epoch_change(self):
        # This exact Git commit is the public signed 0.1.6 tooling snapshot.
        # Shallow checkout may omit it; the isolated integration test exercises
        # the actual downloaded, signature-verified 0.1.6 controller as well.
        result = subprocess.run(['git','-C',str(ROOT),'show',OLD_CONTROLLER_COMMIT+':uterctl.py'],
                                capture_output=True)
        if result.returncode:
            self.skipTest('Historical Git commit unavailable in this checkout')
        raw = result.stdout
        old = self.fx.root/'old-controller.py'; old.write_bytes(raw)
        before = (self.fx.home/'state.json').read_bytes()
        process = subprocess.run([sys.executable, str(old), 'apply', '--home', str(self.fx.home),
                                  '--bundle', str(self.bundle), '--key', str(self.fx.pub)],
                                 capture_output=True, timeout=30)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn(b'Data migration required', process.stderr)
        self.assertEqual((self.fx.home/'state.json').read_bytes(), before)

    def test_ambiguous_sessions_backup_resume_and_block_without_rollout(self):
        before = (self.fx.home/'state.json').read_bytes()
        with patch.object(uterctl, 'deploy') as deploy, patch('scripts.backup_snapshot.capture', side_effect=self.capture), \
             patch('scripts.backup_snapshot.resume_writers') as resume, \
             patch.object(guard, 'classify', side_effect=guard.SessionMigrationBlocked(guard.AMBIGUOUS)):
            with self.assertRaisesRegex(ValueError, '^SESSION_MIGRATION_AMBIGUOUS$'): self.execute()
        deploy.assert_not_called(); resume.assert_called_once()
        self.assertEqual((self.fx.home/'state.json').read_bytes(), before)
        self.assertFalse((self.fx.home/'backup-operation.json').exists())
        self.assertFalse((self.fx.home/'releases'/'1.1.0').exists())
        marker = self.fx.home/'session-migration-block.json'
        data = json.loads(marker.read_text())
        self.assertEqual(data, {'schema':1, 'reason':guard.AMBIGUOUS, 'old_version':'1.0.0',
                                'new_version':'1.1.0', 'backup_id':'d'*32,
                                'backup_path':str((self.fx.root/'backup').resolve())})
        if os.name == 'posix': self.assertEqual(marker.stat().st_mode & 0o777, 0o600)

    def test_empty_or_unexpected_guard_success_still_refuses_without_fence(self):
        with patch.object(uterctl, 'deploy') as deploy, patch('scripts.backup_snapshot.capture', side_effect=self.capture), \
             patch('scripts.backup_snapshot.resume_writers') as resume, patch.object(guard, 'classify', return_value=None):
            with self.assertRaisesRegex(ValueError, '^SESSION_MIGRATION_FENCE_UNVERIFIED$'): self.execute()
        deploy.assert_not_called(); resume.assert_called_once()
        self.assertIsNone(uterctl.read(self.fx.home/'state.json')['pending'])

    def test_interrupt_or_unexpected_scanner_failure_resumes_old_writers(self):
        for failure in (RuntimeError('secret-canary'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                # Each test uses a fresh install, preserving exclusive marker semantics.
                original = self.fx
                fresh = fixtures.ControllerTests(methodName='runTest'); fresh.setUp(); self.fx=fresh
                try:
                    self.key=fresh.prepare_adopted(); self.bundle=fresh.bundle(self.target, 'new')
                    helper=self.bundle/'scripts/session_migration_guard.py';helper.parent.mkdir(exist_ok=True);helper.write_text('# fixture\n');fresh.sign(self.bundle)
                    with patch.object(uterctl, 'deploy') as deploy, patch('scripts.backup_snapshot.capture', side_effect=self.capture), \
                         patch('scripts.backup_snapshot.resume_writers') as resume, patch.object(guard, 'classify', side_effect=failure):
                        with self.assertRaisesRegex(ValueError, '^SESSION_MIGRATION_SCAN_FAILED$'): self.execute()
                    deploy.assert_not_called(); resume.assert_called_once()
                finally:
                    fresh.doCleanups(); self.fx=original

    def test_failed_resume_keeps_journal_and_does_not_claim_safe_block(self):
        with patch.object(uterctl, 'deploy') as deploy, patch('scripts.backup_snapshot.capture', side_effect=self.capture), \
             patch('scripts.backup_snapshot.resume_writers', side_effect=RuntimeError('failure')), \
             patch.object(guard, 'classify', side_effect=guard.SessionMigrationBlocked(guard.AMBIGUOUS)):
            with self.assertRaisesRegex(RuntimeError, '^SESSION_MIGRATION_RESUME_FAILED$'): self.execute()
        deploy.assert_not_called()
        self.assertTrue((self.fx.home/'backup-operation.json').is_file())
        self.assertFalse((self.fx.home/'session-migration-block.json').exists())
        self.assertIsNone(uterctl.read(self.fx.home/'state.json')['pending'])

    def test_marker_prevents_repeat_without_overwrite(self):
        marker=self.fx.home/'session-migration-block.json'; marker.write_text('existing')
        with patch.object(uterctl, 'deploy') as deploy, patch('scripts.backup_snapshot.capture') as capture:
            with self.assertRaisesRegex(ValueError, '^SESSION_MIGRATION_BLOCK_MARKER_EXISTS$'): self.execute()
        deploy.assert_not_called(); capture.assert_not_called(); self.assertEqual(marker.read_text(), 'existing')

    def test_check_only_does_not_modify_helm_values_or_claim_session_check(self):
        before=(self.fx.home/'state.json').read_bytes()
        with patch.object(uterctl, 'deploy') as deploy, patch('scripts.backup_snapshot.capture') as capture:
            self.fx.call('check', self.bundle)
        deploy.assert_not_called();capture.assert_not_called()
        self.assertEqual((self.fx.home/'state.json').read_bytes(), before)
        self.assertFalse((self.fx.home/'session-migration-block.json').exists())

    def test_direct_resume_and_nonadopted_apply_are_refused(self):
        state=uterctl.read(self.fx.home/'state.json'); state['pending']=self.target
        uterctl.write(self.fx.home/'state.json', state)
        with patch.object(uterctl, 'deploy') as deploy:
            with self.assertRaisesRegex(ValueError, '^SESSION_MIGRATION_REQUIRES_ADOPTED_IDLE_INSTALLATION$'):
                self.fx.call('resume', self.bundle)
        deploy.assert_not_called()
        state['pending']=None;state['adopted_installer']=False;uterctl.write(self.fx.home/'state.json', state)
        with patch.object(uterctl, 'deploy') as deploy:
            with self.assertRaisesRegex(ValueError, '^SESSION_MIGRATION_REQUIRES_ADOPTED_IDLE_INSTALLATION$'):
                self.execute()
        deploy.assert_not_called()

    def test_cross_epoch_rollback_requires_restoration_and_cannot_bypass_guard(self):
        state=uterctl.read(self.fx.home/'state.json')
        state.update(current=self.target, previous=fixtures.manifest(), pending=None)
        uterctl.write(self.fx.home/'state.json', state)
        before=(self.fx.home/'state.json').read_bytes()
        with patch.object(uterctl, 'deploy') as deploy:
            with self.assertRaisesRegex(ValueError, 'Rollback requires data restoration'):
                uterctl.main(['rollback','--home',str(self.fx.home),'--key',str(self.fx.pub)])
        deploy.assert_not_called()
        self.assertEqual((self.fx.home/'state.json').read_bytes(), before)


if __name__ == '__main__': unittest.main()
