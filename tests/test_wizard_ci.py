import os
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from scripts import wizard_ci as ci


class WizardCiTests(unittest.TestCase):
    def test_max_tokens_checked_in_old_and_restored_compose_without_secret_output(self):
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp)
            for folder in ('managed', 'restored-compose-api'):
                runtime = stage/'work'/folder/'runtime'; runtime.mkdir(parents=True)
                (runtime/'guardrail.env').write_text('PRIVATE=secret-canary\nUPSTREAM_OPENAI_MAX_TOKENS=64\n')
            for phase in ('before_update', 'restored', 'after_update'):
                ci.check_ci_max_tokens(stage, 'compose', phase)
            env = stage/'work/restored-compose-api/runtime/guardrail.env'
            env.write_text('PRIVATE=secret-canary\nUPSTREAM_OPENAI_MAX_TOKENS=63\n')
            with self.assertRaisesRegex(ci.CheckFailure, '^MAX_TOKENS_SETTING_NOT_PRESERVED$') as caught:
                ci.check_ci_max_tokens(stage, 'compose', 'restored')
            self.assertNotIn('secret-canary', str(caught.exception))
            env.write_text('UPSTREAM_OPENAI_MAX_TOKENS=64\nUPSTREAM_OPENAI_MAX_TOKENS=64\n')
            with self.assertRaises(ci.CheckFailure):
                ci.check_ci_max_tokens(stage, 'compose', 'restored')

    def test_max_tokens_checked_in_only_fixed_kubernetes_secret_field(self):
        with mock.patch.object(ci, 'command', return_value=subprocess.CompletedProcess([], 0, b'NjQ=', b'')) as run:
            ci.check_ci_max_tokens(Path('/unused'), 'kubernetes', 'before_update')
            ci.check_ci_max_tokens(Path('/unused'), 'kubernetes', 'restored')
        commands = [item.args[0] for item in run.call_args_list]
        self.assertIn('uter-upgrade-ci-guardrail-env', commands[0])
        self.assertIn('uter-restored-api-ci-guardrail-env', commands[1])
        self.assertTrue(all(args[-1] == 'jsonpath={.data.UPSTREAM_OPENAI_MAX_TOKENS}' for args in commands))
        with mock.patch.object(ci, 'command', return_value=subprocess.CompletedProcess([], 0, b'', b'')):
            with self.assertRaisesRegex(ci.CheckFailure, '^MAX_TOKENS_SETTING_NOT_PRESERVED$'):
                ci.check_ci_max_tokens(Path('/unused'), 'kubernetes', 'restored')
        with self.assertRaisesRegex(ci.CheckFailure, '^MAX_TOKENS_PHASE_INVALID$'):
            ci.check_ci_max_tokens(Path('/unused'), 'kubernetes', 'invalid')

    def test_signed_update_verifies_each_setting_phase_and_restores_hook(self):
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp); work = stage/'work/adopt-backup-evidence'; work.mkdir(parents=True)
            (work/'result.json').write_text(json.dumps({'upgrade':'pass', 'real_inference':'pass',
                'full_restore_to_workloads':'production recovery command and isolated installation passed',
                'product_image_digests_unchanged': True}))
            checkout = stage/'checkout'
            staged = {'old':stage/'old', 'new':stage/'new', 'public':stage/'publisher'}
            def simulate_upgrade():
                ci.upgrade.call(['/python', '-I', str(checkout/'scripts/bootstrap_wizard.py'),
                                 '--home', str(stage/'home'), '--backup-root', str(stage/'backup'),
                                 '--backup-key', str(stage/'key')])
                for action in ('write', 'read', 'check'):
                    ci.upgrade.audit_and_redis([], None, action)
            original_audit = ci.upgrade.audit_and_redis
            with mock.patch.object(ci.upgrade, 'assert_compose_project_absent'), \
                    mock.patch.object(ci, 'command', return_value=subprocess.CompletedProcess([], 1, b'', b'')), \
                    mock.patch.object(ci, 'check_disallowed_transition'), \
                    mock.patch.object(ci, 'check_ci_max_tokens') as setting, \
                    mock.patch.object(ci.upgrade, 'call', return_value=b''), \
                    mock.patch.object(ci.upgrade, 'audit_and_redis', return_value={}) as original, \
                    mock.patch.object(ci.upgrade, 'main', side_effect=simulate_upgrade):
                self.assertTrue(ci.update_upgrade(stage, staged, checkout, stage/'venv', 'old', 'new', 'compose'))
                self.assertEqual([call.args[2] for call in setting.call_args_list],
                                 ['before_update', 'restored', 'after_update'])
                self.assertIs(ci.upgrade.audit_and_redis, original)
            self.assertIs(ci.upgrade.audit_and_redis, original_audit)

    def env(self, root):
        return {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux',
                'GITHUB_REPOSITORY': 'prince174/uter_deploy', 'GITHUB_WORKSPACE': str(root),
                'BACKEND': 'compose'}

    def test_live_driver_requires_disposable_hosted_linux_root_and_workspace(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            env = self.env(root)
            ci.runner_guard(env, root, uid=0, platform='linux')
            for key, value in [('GITHUB_ACTIONS', 'false'), ('GITHUB_EVENT_NAME', 'push'),
                               ('RUNNER_ENVIRONMENT', 'self-hosted'), ('RUNNER_OS', 'Windows'),
                               ('GITHUB_REPOSITORY', 'other/repo'), ('GITHUB_WORKSPACE', str(root/'elsewhere')),
                               ('BACKEND', 'elsewhere')]:
                with self.subTest(key=key):
                    invalid = dict(env, **{key: value})
                    with self.assertRaises(ci.CheckFailure): ci.runner_guard(invalid, root, uid=0, platform='linux')
            with self.assertRaises(ci.CheckFailure): ci.runner_guard(env, root, uid=1000, platform='linux')
            with self.assertRaises(ci.CheckFailure): ci.runner_guard(env, root, uid=0, platform='win32')

    def test_install_command_uses_signed_wizard_and_never_skips_preflight(self):
        argv = ci.install_command('/python', Path('/signed/scripts/install_wizard.py'), 'test-tag',
                                  '/private/home', '/private/release', 'kubernetes', 'uter-install-ci',
                                  'http://127.0.0.1:8080/v1', '/private/key')
        self.assertIn(str(Path('/signed/scripts/install_wizard.py')), argv)
        self.assertIn('--non-interactive', argv)
        self.assertIn('--context', argv)
        self.assertIn('kind-uter-ci', argv)
        self.assertIn('--llm-key-file', argv)
        self.assertNotIn('--skip-llm-preflight', argv)
        self.assertNotIn('secret-key-content', argv)

    def test_bootstrap_dispatches_without_passing_secret_values(self):
        checkout = Path('/checkout')
        direct = ci.install_command('/python', checkout/'scripts/install_wizard.py', 'release',
                                    '/home', '/release', 'compose', 'uter-install-ci',
                                    'http://127.0.0.1:8000/v1', '/key')
        argv = ci.bootstrap_command('/python', checkout, '/venv', 'install', direct)
        self.assertEqual(argv[1:3], ['-I', str(checkout/'scripts/bootstrap_wizard.py')])
        self.assertIn('install', argv)
        self.assertNotIn('--skip-llm-preflight', argv)
        self.assertNotIn('secret-key-content', argv)
        with self.assertRaisesRegex(ci.CheckFailure, 'BOOTSTRAP_WIZARD_MISMATCH'):
            ci.bootstrap_command('/python', checkout, '/venv', 'update', direct)

    def test_fresh_harness_routes_real_sequence_through_bootstrap(self):
        """Unit-only orchestration check; the hosted job runs the actual processes."""
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp)
            new = stage/'signed'; (new/'scripts').mkdir(parents=True)
            (new/'scripts/install_wizard.py').write_text('signed placeholder')
            (new/'scripts/install.py').write_text('installer placeholder')
            public = stage/'publisher-public.pem'; public.write_text('public')
            inputs = stage/'work/input/published-new'; inputs.mkdir(parents=True)
            (inputs/'images.json').write_text('{}')
            pair = stage/'work/pair/new'; pair.mkdir(parents=True)
            for name in ('publisher-public.pem', 'installation-inputs.tar.gz', 'installation-inputs.tar.gz.sha256'):
                (pair/name).write_text('public')
            checkout = stage/'checkout'; (checkout/'scripts').mkdir(parents=True)
            environment = stage/'private-venv'
            staged = {'new': new, 'public': public}
            observed = []

            def execute(argv, **kwargs):
                observed.append(argv)
                self.assertEqual(argv[1:3], ['-I', str(checkout/'scripts/bootstrap_wizard.py')])
                self.assertIn('install', argv)
                self.assertNotIn('--skip-llm-preflight', argv)
                if ci.option(argv, '--fingerprint') == '0'*64:
                    self.assertIn('--reuse-release', argv)
                    return subprocess.CompletedProcess(argv, 1, b'', b'RELEASE_VERIFICATION_FAILED')
                home = Path(ci.option(argv, '--home')); home.mkdir()
                (home/'install-state.json').write_text('{"status":"ready"}')
                return subprocess.CompletedProcess(argv, 0, b'', b'')

            def harness():
                home = ci.installation.ROOT/'work/installation'
                key = ci.installation.ROOT/'work/llm-key'; key.write_text('')
                installer = str(new/'scripts/install.py')
                ci.installation.run(['/python', installer, 'prepare', '--home', home,
                                     '--llm-url', 'http://127.0.0.1:8080/v1', '--llm-key-file', key])
                ci.installation.run(['/python', installer, 'check', '--home', home])
                ci.installation.run(['/python', installer, 'install', '--home', home])

            with mock.patch.object(ci.upgrade, 'assert_compose_project_absent'), \
                    mock.patch.object(ci, 'command', side_effect=execute), \
                    mock.patch.object(ci.installation, 'main', side_effect=harness):
                ci.fresh_install(stage, staged, checkout, environment, 'release', 'compose')
            self.assertEqual(len(observed), 2)
            self.assertEqual(ci.option(observed[1], '--fingerprint'), ci.FINGERPRINT)
            self.assertNotIn('--reuse-release', observed[1])

    def test_update_uses_new_signed_wizard_and_explicit_confirmation(self):
        argv = ci.update_command('/python', Path('/old'), Path('/new'), Path('/home'), Path('/publisher'),
                                 Path('/backups'), Path('/keys/backup.key'))
        self.assertEqual(argv[1], str(Path('/new/scripts/update_wizard.py')))
        self.assertEqual(ci.option(argv, '--current-bundle'), str(Path('/old')))
        self.assertEqual(ci.option(argv, '--bundle'), str(Path('/new')))
        self.assertIn('--confirm', argv)
        self.assertIn('--json', argv)
        self.assertNotIn('--check-only', argv)
        self.assertNotIn('secret-key-content', argv)

    def test_valid_plan_then_disallowed_target_are_read_only(self):
        staged = {'old': Path('/old'), 'new': Path('/new'), 'public': Path('/key'),
                  'disallowed': Path('/disallowed')}
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)/'home'; home.mkdir()
            backup = Path(temp)/'backup'; backup.mkdir()
            key = Path(temp)/'key'
            (home/'install.json').write_text('{}')
            responses = [subprocess.CompletedProcess([], 0, b'', b''),
                         subprocess.CompletedProcess([], 1, b'', b'')]
            with mock.patch.object(ci, 'command', side_effect=responses) as cmd, \
                    mock.patch.object(ci, 'workload_snapshot', return_value=['unchanged']):
                ci.check_disallowed_transition('compose', staged, home, backup, key, Path('/checkout'), Path('/venv'))
            self.assertEqual(len(cmd.call_args_list), 2)
            self.assertEqual(ci.option(cmd.call_args_list[0].args[0], '--bundle'), str(Path('/new')))
            self.assertEqual(ci.option(cmd.call_args_list[1].args[0], '--bundle'), str(Path('/disallowed')))
            self.assertTrue(all('--check-only' in call.args[0] for call in cmd.call_args_list))

    def test_disallowed_plan_cannot_be_accepted_or_mutate_state(self):
        staged = {'old': Path('/old'), 'new': Path('/new'), 'public': Path('/key'),
                  'disallowed': Path('/disallowed')}
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)/'home'; home.mkdir()
            backup = Path(temp)/'backup'; backup.mkdir()
            (home/'install.json').write_text('{}')
            key = Path(temp)/'key'
            with mock.patch.object(ci, 'command', return_value=subprocess.CompletedProcess([], 0, b'', b'')), \
                    mock.patch.object(ci, 'workload_snapshot', return_value=['unchanged']):
                with self.assertRaisesRegex(ci.CheckFailure, 'DISALLOWED_TRANSITION'):
                    ci.check_disallowed_transition('compose', staged, home, backup, key, Path('/checkout'), Path('/venv'))
            def mutate(argv, **kwargs):
                if ci.option(argv, '--bundle') == str(Path('/disallowed')): (backup/'unexpected').write_text('x')
                return subprocess.CompletedProcess(argv, 0 if ci.option(argv, '--bundle') == str(Path('/new')) else 1, b'', b'')
            with mock.patch.object(ci, 'command', side_effect=mutate), \
                    mock.patch.object(ci, 'workload_snapshot', return_value=['unchanged']):
                with self.assertRaisesRegex(ci.CheckFailure, 'DISALLOWED_TRANSITION'):
                    ci.check_disallowed_transition('compose', staged, home, backup, key, Path('/checkout'), Path('/venv'))

    def test_checkout_must_match_signed_bundle_before_bootstrap(self):
        contents = {'uterctl.py': b'controller', 'requirements.txt': b'reqs',
                    'scripts/install_wizard.py': b'install', 'scripts/update_wizard.py': b'update',
                    'scripts/preflight.py': b'preflight', 'scripts/bootstrap_wizard.py': b'bootstrap',
                    'scripts/uter_wizard.py': b'dispatch'}
        def archive_bytes(items):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w:') as tar:
                for name, data in items.items():
                    info = tarfile.TarInfo(name); info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            return output.getvalue()
        def run_with_archive(payload):
            def run(argv, *, stdout, stderr, timeout):
                stdout.write(payload)
                return subprocess.CompletedProcess(argv, 0)
            return run
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); bundle = root/'bundle'; (bundle/'scripts').mkdir(parents=True)
            for name in ('uterctl.py', 'requirements.txt', 'scripts/install_wizard.py',
                         'scripts/update_wizard.py', 'scripts/preflight.py'):
                (bundle/name).write_bytes(contents[name])
            manifest = {'deployment_commit': 'abc'}
            with mock.patch.object(ci, 'tag_commit', return_value='abc'), \
                    mock.patch.object(ci.subprocess, 'run', side_effect=run_with_archive(archive_bytes(contents))):
                ci.trusted_tag_checkout(root, root/'checkout', 'release', bundle, manifest)
            bad = dict(contents); bad['scripts/preflight.py'] = b'tampered'
            with mock.patch.object(ci, 'tag_commit', return_value='abc'), \
                    mock.patch.object(ci.subprocess, 'run', side_effect=run_with_archive(archive_bytes(bad))):
                with self.assertRaisesRegex(ci.CheckFailure, 'CHECKOUT_DIFFERS_FROM_SIGNED_BUNDLE'):
                    ci.trusted_tag_checkout(root, root/'bad-checkout', 'release', bundle, manifest)

    def test_checkout_rejects_symlinks_and_parent_traversal(self):
        for unsafe_name, symlink in (('../outside', False), ('scripts/link', True)):
            with self.subTest(unsafe_name=unsafe_name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); bundle = root/'bundle'; bundle.mkdir()
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode='w:') as tar:
                    item = tarfile.TarInfo(unsafe_name)
                    if symlink:
                        item.type = tarfile.SYMTYPE; item.linkname = '/etc/passwd'
                        tar.addfile(item)
                    else:
                        item.size = 1; tar.addfile(item, io.BytesIO(b'x'))
                def run(argv, *, stdout, stderr, timeout):
                    stdout.write(raw.getvalue())
                    return subprocess.CompletedProcess(argv, 0)
                with mock.patch.object(ci, 'tag_commit', return_value='abc'), \
                        mock.patch.object(ci.subprocess, 'run', side_effect=run):
                    with self.assertRaisesRegex(ci.CheckFailure, 'PUBLIC_CHECKOUT_ARCHIVE_INVALID'):
                        ci.trusted_tag_checkout(root, root/'checkout', 'release', bundle,
                                                {'deployment_commit': 'abc'})
                self.assertFalse((root/'outside').exists())

    def test_tag_resolution_uses_only_process_local_git_config(self):
        with mock.patch.object(ci, 'require_success', return_value=b'a'*40+b'\n') as run:
            self.assertEqual(ci.tag_commit(Path('/workspace'), 'tag-name'), 'a'*40)
        argv = [str(v) for v in run.call_args.args[0]]
        self.assertIn('-c', argv)
        self.assertIn('safe.directory='+str(Path('/workspace')), argv)
        self.assertNotIn('--global', argv)

    def test_failure_diagnostics_never_expose_process_output(self):
        self.assertEqual(ci.install_failure_category(b'secret-canary HOST_PREFLIGHT_FAILED more secret'),
                         'INSTALL_WIZARD_HOST_PREFLIGHT_FAILED')
        self.assertEqual(ci.install_failure_category(b'password=secret-canary'),
                         'SIGNED_INSTALL_WIZARD_FAILED')

    def test_fingerprint_mismatch_fails_before_extracting_untrusted_assets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'workspace'
            source = root/'work/pair/old'; source.mkdir(parents=True)
            for name in ('signed-bundle.tar.gz', 'publisher-public.pem',
                         'installation-inputs.tar.gz', 'installation-inputs.tar.gz.sha256'):
                (source/name).write_bytes(b'not-the-trusted-publisher')
            stage = Path(temp)/'stage'; stage.mkdir()
            with mock.patch.object(ci.extract_signed_bundle, 'extract') as extract:
                with self.assertRaisesRegex(ci.CheckFailure, 'PUBLISHER_FINGERPRINT_MISMATCH'):
                    ci.stage_releases(root, stage, 'old-tag', 'new-tag')
                extract.assert_not_called()

    def test_workflow_requires_public_signed_assets_and_tests_both_backends(self):
        text = (ci.ROOT/'.github/workflows/wizard-e2e.yml').read_text(encoding='utf-8')
        for term in ('workflow_dispatch:', 'backend: [compose, kubernetes]',
                     'release_upgrade_preflight_ci.py', 'scripts/wizard_ci.py',
                     'GIT_TERMINAL_PROMPT', 'credential.helper=', 'installation-inputs.tar.gz'):
            self.assertIn(term, text)
        self.assertNotIn('secrets.', text)


if __name__ == '__main__':
    unittest.main()
