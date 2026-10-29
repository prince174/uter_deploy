import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import bundle, update_wizard as wizard


@unittest.skipUnless(os.name == 'posix', 'Wizard requires Linux')
class SignedUpdateWizardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'installation'
        self.home.mkdir(mode=0o700)
        self.images = {role: 'registry.example/' + role + '@sha256:' + 'a' * 64
                       for role in ('guardrail', 'agent', 'redis')}
        self.old = {'schema': 1, 'config_schema': 1, 'tooling_schema': 1,
                    'status': 'released', 'version': '1.0.0', 'source_commit': 'b' * 40,
                    'data_epoch': 1, 'upgrade_from': [], 'images': self.images}
        self.new = dict(self.old, version='1.1.0', upgrade_from=['1.0.0'])
        signer = Ed25519PrivateKey.generate()
        private = self.root / 'private.pem'
        private.write_bytes(signer.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.public = self.root / 'publisher.pem'
        self.public.write_bytes(signer.public_key().public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo))
        self.fingerprint = hashlib.sha256(self.public.read_bytes()).hexdigest()
        self.current, self.target = self.root / 'current', self.root / 'target'
        for label, manifest, out in [('old', self.old, self.current), ('new', self.new, self.target)]:
            source = self.root / (label + '.json')
            source.write_text(json.dumps(manifest), encoding='utf-8')
            bundle.build(source, out, private)
            # build copies source modes: this workspace is on Windows/DrvFS,
            # whereas distributed archives extract to protected Unix modes.
            for item in out.rglob('*'):
                item.chmod(0o755 if item.is_dir() else 0o644)
        self.config = {'backend': 'compose', 'name': 'uter-test', 'context': 'default',
                       'port': 18000, 'images': self.images}
        (self.home / 'install.json').write_text(json.dumps(self.config), encoding='utf-8')
        (self.home / 'install-state.json').write_text('{"status":"ready"}', encoding='utf-8')
        self.backups = self.root / 'backup-dir'
        self.keydir = self.root / 'key-dir'
        self.keyfile = self.keydir / 'backup.key'

    def plan(self, **kwargs):
        return wizard.prepare_plan(self.home, self.target, self.public, self.fingerprint,
                                   current_bundle=self.current, backup_root=self.backups,
                                   backup_key=self.keyfile, **kwargs)

    def test_new_paths_are_only_created_after_confirmation_and_key_is_new(self):
        plan = self.plan()
        self.assertTrue(plan['create_key'])
        self.assertFalse(self.backups.exists())
        self.assertFalse(self.keydir.exists())
        response = 'Helm progress\n' + json.dumps({'version': '1.1.0', 'backup_id': 'a'*32,
                               'backup': str(self.backups / 'copy'), 'backup_key': str(self.keyfile)})
        with patch.object(wizard, 'run_updater', return_value=response) as run:
            result = wizard.execute(plan)
        self.assertEqual(result['version'], '1.1.0')
        self.assertEqual(self.backups.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.keydir.stat().st_mode & 0o777, 0o700)
        args = run.call_args.args[0]
        self.assertEqual(args[1:4], ['-I', '-B', str(self.target / 'scripts/update_installation.py')])
        self.assertIn('--create-backup-key', args)
        self.assertIn('--current-bundle', args)

    def test_existing_key_is_never_recreated_or_printed(self):
        self.backups.mkdir(mode=0o700)
        self.keydir.mkdir(mode=0o700)
        secret = b'X' * 32
        self.keyfile.write_bytes(secret)
        self.keyfile.chmod(0o600)
        plan = self.plan()
        self.assertFalse(plan['create_key'])
        output = io.StringIO()
        response = json.dumps({'version': '1.1.0', 'backup_id': 'a'*32,
                               'backup': str(self.backups / 'copy'), 'backup_key': str(self.keyfile)})
        with contextlib.redirect_stdout(output), \
             patch.object(wizard, 'run_updater', return_value=response) as run:
            wizard.display_plan(plan)
            wizard.execute(plan)
        self.assertNotIn('--create-backup-key', run.call_args.args[0])
        self.assertNotIn(secret.decode(), output.getvalue())
        self.assertEqual(self.keyfile.read_bytes(), secret)

    def test_fingerprint_and_changed_bundle_fail_without_writes(self):
        with self.assertRaises(wizard.WizardError):
            wizard.prepare_plan(self.home, self.target, self.public, '0' * 64,
                                current_bundle=self.current, backup_root=self.backups, backup_key=self.keyfile)
        self.assertFalse(self.backups.exists())
        plan = self.plan()
        (self.target / 'compose' / 'compose.yaml').write_text('modified', encoding='utf-8')
        with patch.object(wizard, 'run_updater') as run:
            with self.assertRaises(Exception):
                wizard.execute(plan)
            run.assert_not_called()
        self.assertFalse(self.backups.exists())
        self.assertFalse(self.keydir.exists())

    def test_key_created_after_plan_refuses_without_replacement(self):
        self.backups.mkdir(mode=0o700)
        self.keydir.mkdir(mode=0o700)
        plan = self.plan()
        original = b'Z' * 32
        self.keyfile.write_bytes(original)
        self.keyfile.chmod(0o600)
        with patch.object(wizard, 'run_updater') as run:
            with self.assertRaisesRegex(wizard.WizardError, 'PLAN_CHANGED'):
                wizard.execute(plan)
            run.assert_not_called()
        self.assertEqual(self.keyfile.read_bytes(), original)

    def test_changed_installation_or_pending_state_refuses(self):
        plan = self.plan()
        (self.home / 'install-state.json').write_text('{"status":"pending"}', encoding='utf-8')
        with patch.object(wizard, 'run_updater') as run:
            with self.assertRaisesRegex(wizard.WizardError, 'INSTALLATION_NOT_READY'):
                wizard.execute(plan)
            run.assert_not_called()
        self.assertFalse(self.backups.exists())

    def test_existing_key_changed_after_plan_refuses_before_mutation(self):
        self.backups.mkdir(mode=0o700)
        self.keydir.mkdir(mode=0o700)
        self.keyfile.write_bytes(b'X'*32); self.keyfile.chmod(0o600)
        plan = self.plan()
        self.keyfile.write_bytes(b'Y'*32)
        with patch.object(wizard, 'run_updater') as run:
            with self.assertRaisesRegex(wizard.WizardError, 'PLAN_CHANGED'):
                wizard.execute(plan)
            run.assert_not_called()

    def test_untrusted_bundle_and_unrelated_paths_rejected(self):
        (self.target / 'compose').chmod(0o777)
        with self.assertRaisesRegex(wizard.WizardError, 'BUNDLE_NOT_PROTECTED'):
            self.plan()
        (self.target / 'compose').chmod(0o755)
        with self.assertRaisesRegex(wizard.WizardError, 'BACKUP_PATHS_NOT_SEPARATE'):
            wizard.prepare_plan(self.home, self.target, self.public, self.fingerprint,
                                current_bundle=self.current, backup_root=self.home / 'backup',
                                backup_key=self.keyfile)

    def test_explicit_check_only_never_creates_directories_or_runs_update(self):
        argv = ['--home', str(self.home), '--current-bundle', str(self.current), '--bundle', str(self.target),
                '--publisher-key', str(self.public), '--fingerprint', self.fingerprint,
                '--backup-root', str(self.backups), '--backup-key', str(self.keyfile), '--check-only']
        with patch.object(wizard, 'run_updater') as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(wizard.main(argv), 0)
            run.assert_not_called()
        self.assertFalse(self.backups.exists())
        self.assertFalse(self.keydir.exists())

    def test_noninteractive_without_confirmation_does_not_start(self):
        argv = ['--home', str(self.home), '--current-bundle', str(self.current), '--bundle', str(self.target),
                '--publisher-key', str(self.public), '--fingerprint', self.fingerprint,
                '--backup-root', str(self.backups), '--backup-key', str(self.keyfile)]
        with patch.object(wizard.sys.stdin, 'isatty', return_value=False), \
             patch.object(wizard, 'run_updater') as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(wizard.main(argv), 2)
            run.assert_not_called()
        self.assertFalse(self.backups.exists())

    def test_failed_update_hides_raw_output_and_does_not_fake_rollback(self):
        plan = self.plan()
        with patch.object(wizard, 'run_updater', side_effect=wizard.WizardError('SIGNED_UPDATE_FAILED_INSPECT_STATE')):
            with self.assertRaisesRegex(wizard.WizardError, 'SIGNED_UPDATE_FAILED_INSPECT_STATE') as error:
                wizard.execute(plan)
        self.assertNotIn('secret', str(error.exception))

    def test_adopted_uses_current_signed_bundle_automatically(self):
        releases = self.home / 'releases'
        releases.mkdir()
        installed = releases / self.old['version']
        shutil.copytree(self.current, installed)
        runtime = self.home / 'runtime'
        runtime.mkdir()
        site = {'backend': 'compose', 'name': 'uter-test', 'namespace': 'uter-test',
                'context': 'default', 'port': 18000, 'guardrail_cpus': 4,
                'smoke_command': ['smoke']}
        (runtime / 'site.json').write_text(json.dumps(site), encoding='utf-8')
        (self.home / 'state.json').write_text(json.dumps({'current': self.old, 'pending': None,
                                                         'adopted_installer': True}), encoding='utf-8')
        plan = wizard.prepare_plan(self.home, self.target, self.public, self.fingerprint,
                                   backup_root=self.backups, backup_key=self.keyfile)
        self.assertTrue(plan['adopted'])
        self.assertEqual(plan['current_bundle'], installed)

    def test_download_uses_expected_version_and_independent_fingerprint(self):
        destination = self.root / 'downloaded-release'
        argv = ['--home', str(self.home), '--current-bundle', str(self.current),
                '--release', 'test-tag', '--version', '1.1.0', '--download-to', str(destination),
                '--fingerprint', self.fingerprint, '--backup-root', str(self.backups),
                '--backup-key', str(self.keyfile), '--check-only', '--json']
        def fetch(tag, fingerprint, expected_version, output):
            self.assertEqual((tag, fingerprint, expected_version, output),
                             ('test-tag', self.fingerprint, '1.1.0', destination))
            destination.mkdir(mode=0o700)
            shutil.copytree(self.target, destination / 'bundle')
            downloads = destination / 'downloads'; downloads.mkdir(mode=0o700)
            shutil.copyfile(self.public, downloads / 'publisher-public.pem')
        captured = io.StringIO()
        with patch.object(wizard.fetch_release, 'fetch_with_deadline', side_effect=fetch) as mocked, \
             patch.object(wizard, 'run_updater') as run, contextlib.redirect_stdout(captured):
            self.assertEqual(wizard.main(argv), 0)
        mocked.assert_called_once()
        run.assert_not_called()
        self.assertEqual(json.loads(captured.getvalue())['new_version'], '1.1.0')
        self.assertFalse(self.backups.exists())
        self.assertFalse(self.keydir.exists())

    def test_json_success_is_machine_readable_and_contains_no_secret(self):
        argv = ['--home', str(self.home), '--current-bundle', str(self.current), '--bundle', str(self.target),
                '--publisher-key', str(self.public), '--fingerprint', self.fingerprint,
                '--backup-root', str(self.backups), '--backup-key', str(self.keyfile), '--confirm', '--json']
        response = json.dumps({'version': '1.1.0', 'backup_id': 'a'*32,
                               'backup': str(self.backups / 'copy'), 'backup_key': str(self.keyfile)})
        captured = io.StringIO()
        with patch.object(wizard, 'run_updater', return_value=response), \
             contextlib.redirect_stdout(captured):
            self.assertEqual(wizard.main(argv), 0)
        self.assertEqual(json.loads(captured.getvalue())['version'], '1.1.0')

    def test_kubernetes_rejects_offline_before_mutation(self):
        config = dict(self.config, backend='kubernetes', context='test-context')
        (self.home / 'install.json').write_text(json.dumps(config), encoding='utf-8')
        with self.assertRaisesRegex(wizard.WizardError, 'OFFLINE_REQUIRES_COMPOSE'):
            self.plan(offline=True)
        self.assertFalse(self.backups.exists())

    def test_kubernetes_runs_signed_updater_with_explicit_context(self):
        config = dict(self.config, backend='kubernetes', context='isolated-context')
        (self.home / 'install.json').write_text(json.dumps(config), encoding='utf-8')
        plan = self.plan()
        self.assertEqual((plan['backend'], plan['context']), ('kubernetes', 'isolated-context'))
        response = json.dumps({'version': '1.1.0', 'backup_id': 'b'*32,
                               'backup': str(self.backups / 'copy'), 'backup_key': str(self.keyfile)})
        with patch.object(wizard, 'run_updater', return_value=response) as run:
            wizard.execute(plan)
        self.assertNotIn('--offline', run.call_args.args[0])

    def test_changed_release_version_rejected_before_writes(self):
        argv = ['--home', str(self.home), '--current-bundle', str(self.current), '--bundle', str(self.target),
                '--version', '1.2.0', '--publisher-key', str(self.public), '--fingerprint', self.fingerprint,
                '--backup-root', str(self.backups), '--backup-key', str(self.keyfile), '--check-only']
        with self.assertRaisesRegex(wizard.WizardError, 'EXPECTED_VERSION_MISMATCH'):
            wizard.main(argv)
        self.assertFalse(self.backups.exists())

    def test_old_key_symlink_and_bad_permissions_are_rejected(self):
        self.backups.mkdir(mode=0o700)
        self.keydir.mkdir(mode=0o700)
        underlying = self.root / 'secret-file'
        underlying.write_bytes(b'Q' * 32); underlying.chmod(0o600)
        self.keyfile.symlink_to(underlying)
        with self.assertRaises(Exception):
            self.plan()
        self.keyfile.unlink()
        self.keyfile.write_bytes(b'Q' * 32); self.keyfile.chmod(0o640)
        with self.assertRaises(Exception):
            self.plan()

    def test_signed_updater_ignores_injected_pythonpath_and_writes_no_bytecode(self):
        rogue = self.root / 'rogue-pythonpath'
        rogue.mkdir(mode=0o700)
        marker = self.root / 'rogue-code-ran'
        (rogue / 'sitecustomize.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n',
                                               encoding='utf-8')
        updater = self.target / 'scripts' / 'update_installation.py'
        with patch.dict(os.environ, {'PYTHONPATH': str(rogue)}):
            result = wizard.run_updater([sys.executable, '-I', '-B', str(updater), '--help'], timeout=10)
        self.assertIn('--backup-root', result)
        self.assertFalse(marker.exists())
        self.assertFalse(any(self.target.rglob('__pycache__')))


@unittest.skipUnless(os.name == 'posix', 'POSIX process groups required')
class BoundedUpdaterTests(unittest.TestCase):
    def test_reads_stdout_and_discards_stderr_without_leaking_it(self):
        script = 'import sys; sys.stderr.write("secret-in-stderr"); print("normal-result")'
        self.assertEqual(wizard.run_updater([sys.executable, '-c', script], timeout=5), 'normal-result\n')

    def test_large_stdout_is_drained_without_stopping_update(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'completed'
            script = ('import os,pathlib,sys; os.write(1,b"secret-canary"*10000); '
                      'pathlib.Path(sys.argv[1]).write_text("completed")')
            with self.assertRaisesRegex(wizard.WizardError, 'UPDATER_OUTPUT_LIMIT_INSPECT_STATE') as error:
                wizard.run_updater([sys.executable, '-c', script, str(marker)], timeout=5, max_output=1024)
            self.assertTrue(marker.exists(), 'Updater must finish before reporting truncated output')
            self.assertNotIn('secret-canary', str(error.exception))

    def test_large_stderr_is_drained_and_never_retained(self):
        script = 'import os; os.write(2,b"secret-canary"*10000); print("completed")'
        result = wizard.run_updater([sys.executable, '-c', script], timeout=5, max_output=1024)
        self.assertEqual(result, 'completed\n')

    def test_timeout_terminates_own_child_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / 'child.pid'
            child = ('import os,pathlib,signal,sys,time; signal.signal(signal.SIGINT,signal.default_int_handler); '
                     'pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)')
            parent = ('import signal,subprocess,sys,time; signal.signal(signal.SIGINT,signal.default_int_handler); '
                      'subprocess.Popen([sys.executable,"-c",sys.argv[1],sys.argv[2]]); time.sleep(30)')
            with self.assertRaisesRegex(wizard.WizardError, 'UPDATER_TIMEOUT_INSPECT_STATE'):
                wizard.run_updater([sys.executable, '-c', parent, child, str(pid_file)], timeout=1)
            self.assertTrue(pid_file.exists())
            pid = int(pid_file.read_text())
            for _ in range(30):
                status = Path('/proc') / str(pid) / 'stat'
                if not status.exists() or status.read_text().split()[2] == 'Z':
                    break
                time.sleep(.1)
            else:
                self.fail('Updater descendant survived process group termination')

    def test_json_error_uses_fixed_code_and_suppresses_raw_exception(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            wizard.report_error(ValueError('secret-canary'), machine=True)
        self.assertEqual(json.loads(output.getvalue()), {'result': 'error', 'code': 'INPUT_OR_VERIFICATION_FAILED'})
        self.assertNotIn('secret-canary', output.getvalue())

    def test_json_cli_missing_input_is_one_structured_error(self):
        path = Path(wizard.__file__).resolve()
        result = subprocess.run([sys.executable, str(path), '--json', '--confirm'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=10, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), {'result': 'error', 'code': 'REQUIRED_ARGUMENT_MISSING'})
        self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
