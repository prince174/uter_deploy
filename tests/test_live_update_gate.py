"""Unmocked gate coverage: existing installations never enter update logic."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml
import uterctl
from scripts import backup_installation, backup_snapshot, install, update_installation, update_wizard
from tests import test_controller as fixtures


class ControllerLiveUpdateGateTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.ControllerTests(methodName='runTest')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def test_existing_adopted_and_legacy_apply_block_before_staging_or_capture(self):
        key = self.fx.prepare_adopted()
        target = self.fx.bundle(fixtures.manifest('1.1.0', ['1.0.0']), 'new')
        receipt = self.fx.root/'receipt.json'
        uterctl.write(receipt, {'version': '1.0.0', 'backup_id': 'unverified'})
        for backend in ('compose', 'helm'):
            site = uterctl.read(self.fx.home/'runtime/site.json')
            site.update(backend=backend, context='default')
            uterctl.write(self.fx.home/'runtime/site.json', site)
            for adopted in (False, True):
                state = uterctl.read(self.fx.home/'state.json')
                state['adopted_installer'] = adopted
                uterctl.write(self.fx.home/'state.json', state)
                before = (self.fx.home/'state.json').read_bytes()
                with self.subTest(backend=backend, adopted=adopted), \
                     patch.object(uterctl, 'deploy') as deploy, \
                     patch.object(uterctl, 'run') as run, \
                     patch('scripts.backup_snapshot.capture') as capture:
                    with self.assertRaisesRegex(ValueError, '^LIVE_UPDATE_MAINTENANCE_ISOLATION_UNAVAILABLE$'):
                        self.fx.call('apply', target, ['--backup-receipt', str(receipt),
                                                      '--backup-dir', str(self.fx.root/'backup'), '--backup-key', str(key)])
                deploy.assert_not_called(); run.assert_not_called(); capture.assert_not_called()
                self.assertEqual((self.fx.home/'state.json').read_bytes(), before)
                self.assertFalse((self.fx.home/'releases/1.1.0').exists())
                self.assertFalse((self.fx.root/'backup').exists())
                self.assertFalse((self.fx.home/'operation.lock').exists())

    def test_fresh_legacy_controller_apply_refuses_before_staging(self):
        bundle = self.fx.bundle()
        with patch.object(uterctl, 'deploy') as deploy, patch.object(uterctl, 'run') as run:
            with self.assertRaisesRegex(ValueError, '^FRESH_CONTROLLER_INSTALL_UNAVAILABLE_USE_INSTALL_PY$'):
                self.fx.call('apply', bundle)
        deploy.assert_not_called(); run.assert_not_called()
        self.assertFalse((self.fx.home/'state.json').exists())
        self.assertFalse((self.fx.home/'releases').exists())

    def test_unadopted_install_state_blocks_apply_without_controller_state(self):
        bundle = self.fx.bundle()
        marker = self.fx.home/'install-state.json'
        for kind in ('ready', 'pending', 'dangling'):
            with self.subTest(kind=kind):
                if kind == 'dangling':
                    if not hasattr(os, 'symlink') or os.name != 'posix':
                        continue
                    marker.symlink_to(self.fx.home/'missing')
                else:
                    uterctl.write(marker, {'status': kind})
                with patch.object(uterctl, 'deploy') as deploy, patch.object(uterctl, 'run') as run:
                    with self.assertRaisesRegex(ValueError, '^LIVE_UPDATE_MAINTENANCE_ISOLATION_UNAVAILABLE$'):
                        self.fx.call('apply', bundle)
                deploy.assert_not_called(); run.assert_not_called()
                self.assertFalse((self.fx.home/'state.json').exists())
                self.assertFalse((self.fx.home/'releases').exists())
                marker.unlink()

    def test_adopted_pending_resume_is_not_blocked_by_new_apply_gate(self):
        key = self.fx.prepare_adopted()
        new = fixtures.manifest('1.1.0', ['1.0.0'])
        target = self.fx.bundle(new, 'new')
        backup = self.fx.root/'backup'
        state = uterctl.read(self.fx.home/'state.json')
        state.update(pending=new, last_backup={'id': 'd'*32, 'path': str(backup.resolve()), 'version': '1.0.0'})
        uterctl.write(self.fx.home/'state.json', state)
        with patch.object(uterctl, 'deploy') as deploy, patch.object(uterctl, 'run'), \
             patch('scripts.backup_store.verify_set', return_value={'id': 'd'*32}):
            self.fx.call('resume', target, ['--backup-dir', str(backup), '--backup-key', str(key)])
        self.assertEqual(uterctl.read(self.fx.home/'state.json')['current']['version'], '1.1.0')
        self.assertEqual(deploy.call_count, 2)

    def test_new_rollback_is_blocked_for_legacy_and_adopted_state(self):
        key = self.fx.prepare_adopted()
        previous = fixtures.manifest('1.0.0')
        active = fixtures.manifest('1.1.0', ['1.0.0'])
        receipt = self.fx.root/'receipt.json'
        uterctl.write(receipt, {'version': '1.1.0', 'backup_id': 'unverified'})
        for adopted in (False, True):
            with self.subTest(adopted=adopted):
                state = {'current': active, 'previous': previous, 'pending': None, 'adopted_installer': adopted}
                uterctl.write(self.fx.home/'state.json', state)
                before = (self.fx.home/'state.json').read_bytes()
                with patch.object(uterctl, 'deploy') as deploy, patch.object(uterctl, 'run') as run, \
                     patch('scripts.backup_snapshot.capture') as capture:
                    with self.assertRaisesRegex(ValueError, '^LIVE_UPDATE_MAINTENANCE_ISOLATION_UNAVAILABLE$'):
                        self.fx.call('rollback', self.fx.home/'releases/1.0.0',
                                     ['--backup-receipt', str(receipt), '--backup-dir', str(self.fx.root/'backup'),
                                      '--backup-key', str(key)])
                deploy.assert_not_called(); run.assert_not_called(); capture.assert_not_called()
                self.assertEqual((self.fx.home/'state.json').read_bytes(), before)
                self.assertFalse((self.fx.root/'backup').exists())

    def test_legacy_pending_rollback_path_is_preserved(self):
        self.fx.prepare_adopted()
        old, pending = fixtures.manifest('1.0.0'), fixtures.manifest('1.1.0', ['1.0.0'])
        uterctl.write(self.fx.home/'state.json', {'current': old, 'previous': None, 'pending': pending})
        receipt = self.fx.root/'receipt.json'
        uterctl.write(receipt, {'version': '1.1.0', 'backup_id': 'legacy-recovery-receipt'})
        with patch.object(uterctl, 'deploy') as deploy, patch.object(uterctl, 'run'):
            self.fx.call('rollback', self.fx.home/'releases/1.0.0', ['--backup-receipt', str(receipt)])
        self.assertEqual(deploy.call_count, 2)
        self.assertIsNone(uterctl.read(self.fx.home/'state.json')['pending'])


@unittest.skipUnless(os.name == 'posix', 'Managed update requires Linux')
class UpdateEntryPointGateTests(unittest.TestCase):
    def test_supported_initial_install_paths_remain_available(self):
        for backend in ('compose', 'kubernetes'):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as temp:
                home = Path(temp); runtime = home/'runtime'
                for folder in ('policies', 'profiles', 'models'):
                    (runtime/folder).mkdir(parents=True)
                for name in ('policies/runtime.toml', 'profiles/model_profiles.toml', 'audit-hmac-key',
                             'redis.conf', 'redis-password'):
                    (runtime/name).write_text('fixture')
                calls = []
                def run(command, env=None):
                    calls.append(command)
                    if command[:3] == ['docker', 'context', 'inspect']:
                        return '[{"Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}}}]'
                    return ''
                cfg = {'backend': backend, 'name': 'uter-test', 'context': 'default',
                       'images': {x:'registry/'+x+'@sha256:'+'a'*64 for x in ('agent','guardrail','redis')}}
                with patch.object(install, 'check'), patch.object(install, 'run', side_effect=run), \
                     patch.object(install, 'commands', return_value=(['fixture-deployer'], {})), \
                     patch.object(install, 'reject_reserved_compose_names'), \
                     patch.object(install, 'prepare_ca_permissions'), patch.object(install.os, 'geteuid', return_value=0), \
                     patch.object(install.os, 'chown'):
                    install.install(home, cfg)
                self.assertEqual(uterctl.read(home/'install-state.json')['status'], 'ready')
                self.assertTrue(any('up' in command or 'install' in command for command in calls))

    def test_standalone_and_low_level_live_backup_refuse_before_mutation(self):
        for backend in ('compose', 'kubernetes'):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as temp:
                home = Path(temp)/'home'; home.mkdir()
                destination = Path(temp)/'backup'
                with patch.object(backup_installation, 'private_directory') as private, \
                     patch.object(backup_snapshot, 'capture') as capture:
                    with self.assertRaisesRegex(backup_installation.BackupError,
                                                '^LIVE_BACKUP_MAINTENANCE_ISOLATION_UNAVAILABLE$'):
                        backup_installation.backup(home, destination, 'key', 'publisher', 'identity',
                                                   backend, 'uter-test', 'default')
                private.assert_not_called(); capture.assert_not_called()
                with patch.object(backup_snapshot.adopt_installation, 'verify_live') as live, \
                     patch.object(backup_snapshot.backup_store, 'BackupWriter') as writer, \
                     patch.object(backup_snapshot, 'checked') as workload:
                    with self.assertRaisesRegex(ValueError, '^LIVE_BACKUP_MAINTENANCE_ISOLATION_UNAVAILABLE$'):
                        backup_snapshot.capture(home, {}, {'backend': backend}, {}, destination, b'k'*32)
                live.assert_not_called(); writer.assert_not_called(); workload.assert_not_called()
                self.assertEqual(list(home.iterdir()), []); self.assertFalse(destination.exists())

    def test_update_wrapper_blocks_before_backup_key_and_adoption(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); home = root/'home'; bundle = root/'signed'; home.mkdir(); bundle.mkdir()
            backup_key = root/'new-key'
            with patch.object(update_installation.adopt_managed, 'adopt') as adopt, \
                 patch.object(update_installation.backup_crypto, 'create_key') as create, \
                 patch.object(uterctl, 'main') as controller:
                with self.assertRaisesRegex(ValueError, '^LIVE_UPDATE_MAINTENANCE_ISOLATION_UNAVAILABLE$'):
                    update_installation.update(home, bundle, root/'pub', root/'backup', backup_key,
                                               create_backup_key=True)
            adopt.assert_not_called(); create.assert_not_called(); controller.assert_not_called()
            self.assertEqual(list(home.iterdir()), []); self.assertFalse(backup_key.exists())

    def test_wizard_blocks_before_target_bundle_updater_or_directory_creation(self):
        # Even a valid older signed updater must never be invoked through this wizard.
        with patch.object(update_wizard, 'prepare_plan') as prepare, \
             patch.object(update_wizard, 'ensure_new_private_dir') as mkdir, \
             patch.object(update_wizard, 'run_updater') as updater:
            with self.assertRaisesRegex(update_wizard.WizardError, '^LIVE_UPDATE_MAINTENANCE_ISOLATION_UNAVAILABLE$'):
                update_wizard.execute({'tool': 'old-signed-updater'})
        prepare.assert_not_called(); mkdir.assert_not_called(); updater.assert_not_called()

    def test_historical_unsafe_workflow_fails_before_checkout_or_download(self):
        workflows = Path(__file__).resolve().parents[1]/'.github/workflows'
        for filename, job, name in (
                ('real-llm-upgrade.yml', 'real-llm-upgrade', 'Refuse historical unsafe live-update experiment'),
                ('scheduled-backup.yml', 'scheduled-backup', 'Refuse historical unsafe live-backup experiment')):
            with self.subTest(filename=filename):
                workflow = yaml.safe_load((workflows/filename).read_text())
                first = workflow['jobs'][job]['steps'][0]
                self.assertEqual(first['name'], name)
                self.assertIn('exit 1', first['run'])
                self.assertNotIn('uses', first)


if __name__ == '__main__':
    unittest.main()
