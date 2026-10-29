import os
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from scripts import bootstrap_wizard as bootstrap


@unittest.skipUnless(os.name == 'posix', 'POSIX permission checks')
class BootstrapTests(unittest.TestCase):
    def test_protected_directory_and_private_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / 'protected'
            parent.mkdir(mode=0o700)
            self.assertEqual(bootstrap.trusted_directory(parent, private=True), parent)
            parent.chmod(0o755)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.trusted_directory(parent, private=True)

    def test_symlink_and_shared_writable_parent_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            protected = root / 'owned'
            protected.mkdir(mode=0o700)
            (root / 'link').symlink_to(protected, target_is_directory=True)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.trusted_directory(root / 'link')
            protected.chmod(0o777)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.trusted_directory(protected)

    def test_existing_signed_bundle_is_never_modified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'checksums.sig').write_text('marker')
            with self.assertRaisesRegex(bootstrap.BootstrapError, 'SIGNED_BUNDLE'):
                bootstrap.bootstrap(root, root / '.uter-wizard-venv')
            self.assertFalse((root / '.uter-wizard-venv').exists())

    def test_rejects_venv_inside_another_signed_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'checksums.sig').write_text('marker')
            child = root / 'environment'
            with self.assertRaisesRegex(bootstrap.BootstrapError, 'INSIDE_SIGNED_BUNDLE'):
                bootstrap.reject_signed_ancestor(child)
            self.assertFalse(child.exists())

    def test_writable_module_and_external_environment_link_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = root / 'code'
            code.mkdir(mode=0o700)
            module = code / 'module.py'
            module.write_text('')
            module.chmod(0o666)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.trusted_tree(code)
            module.chmod(0o600)
            (code / 'outside').symlink_to(root, target_is_directory=True)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.trusted_tree(code, allow_internal_links=True)

    def test_operation_help_does_not_prepare_environment(self):
        with patch.object(bootstrap, 'bootstrap') as prepare:
            self.assertEqual(bootstrap.main(['install', '--help']), 0)
        prepare.assert_not_called()

    def test_rechecks_environment_after_dependency_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / 'scripts'
            scripts.mkdir(mode=0o700)
            for file in (root / 'requirements.txt', root / 'uterctl.py',
                         scripts / 'uter_wizard.py', scripts / 'install_wizard.py',
                         scripts / 'update_wizard.py'):
                file.write_text('')
            env = root / '.uter-wizard-venv'
            def create(path):
                binary = Path(path) / 'bin'
                binary.mkdir(mode=0o700)
                (binary / 'python3').write_text('')
                (binary / 'python3').chmod(0o700)
            def install(*args, **kwargs):
                bad = env / 'writable-module.py'
                bad.write_text('')
                bad.chmod(0o666)
                return SimpleNamespace(returncode=0)
            with patch.object(bootstrap.venv, 'EnvBuilder', return_value=SimpleNamespace(create=create)), \
                 patch.object(bootstrap.subprocess, 'run', side_effect=install):
                with self.assertRaisesRegex(bootstrap.BootstrapError, 'TREE_UNTRUSTED'):
                    bootstrap.bootstrap(root, env)

    def test_private_umask_is_used_and_restored_on_failure(self):
        previous = os.umask(0o002)
        try:
            with self.assertRaises(RuntimeError):
                with bootstrap.private_umask():
                    observed = os.umask(0o077)
                    self.assertEqual(observed, 0o077)
                    raise RuntimeError('test')
            self.assertEqual(os.umask(0o002), 0o002)
        finally:
            os.umask(previous)

    def test_fresh_generated_activation_templates_are_restricted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); scripts=root/'scripts';scripts.mkdir(mode=0o700)
            for file in (root/'requirements.txt',root/'uterctl.py',scripts/'uter_wizard.py',
                         scripts/'install_wizard.py',scripts/'update_wizard.py'):
                file.write_text('')
            env=root/'.venv'; names=('activate','activate.csh','activate.fish','Activate.ps1')
            def create(path):
                bindir=Path(path)/'bin';bindir.mkdir(mode=0o700)
                binary=bindir/'python3';binary.write_text('');binary.chmod(0o700)
                for name in names:
                    file=bindir/name;file.write_text('');file.chmod(0o777)
            with patch.object(bootstrap.venv,'EnvBuilder',return_value=SimpleNamespace(create=create)), \
                 patch.object(bootstrap.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
                bootstrap.bootstrap(root,env)
            for name in names:self.assertEqual((env/'bin'/name).stat().st_mode & 0o777,0o755)

    def test_generated_activator_symlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); env=root/'env';env.mkdir(mode=0o700)
            bindir=env/'bin';bindir.mkdir(mode=0o700)
            target=root/'target';target.write_text('');target.chmod(0o777)
            (bindir/'activate').symlink_to(target)
            with self.assertRaisesRegex(bootstrap.BootstrapError,'GENERATED_ENVIRONMENT_UNTRUSTED'):
                bootstrap.protect_generated_activators(env)
            self.assertEqual(target.stat().st_mode & 0o777,0o777)

    def test_generated_activator_hardlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); env=root/'env';env.mkdir(mode=0o700)
            bindir=env/'bin';bindir.mkdir(mode=0o700)
            target=root/'target';target.write_text('');target.chmod(0o777)
            os.link(target,bindir/'activate')
            with self.assertRaisesRegex(bootstrap.BootstrapError,'GENERATED_ENVIRONMENT_UNTRUSTED'):
                bootstrap.protect_generated_activators(env)
            self.assertEqual(target.stat().st_mode & 0o777,0o777)

    def test_existing_unsafe_env_is_rejected_without_normalizing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);scripts=root/'scripts';scripts.mkdir(mode=0o700)
            for file in (root/'requirements.txt',root/'uterctl.py',scripts/'uter_wizard.py',
                         scripts/'install_wizard.py',scripts/'update_wizard.py'):
                file.write_text('')
            env=root/'.venv';env.mkdir(mode=0o700);bindir=env/'bin';bindir.mkdir(mode=0o700)
            binary=bindir/'python3';binary.write_text('');binary.chmod(0o700)
            activate=bindir/'activate';activate.write_text('');activate.chmod(0o777)
            with patch.object(bootstrap.venv,'EnvBuilder') as builder, \
                 patch.object(bootstrap.subprocess,'run') as run:
                with self.assertRaisesRegex(bootstrap.BootstrapError,'TREE_UNTRUSTED'):
                    bootstrap.bootstrap(root,env)
                builder.assert_not_called();run.assert_not_called()
            self.assertEqual(activate.stat().st_mode & 0o777,0o777)

    def test_pip_failure_does_not_launch_assistant(self):
        with patch.object(bootstrap, 'bootstrap', side_effect=bootstrap.BootstrapError('DEPENDENCY_INSTALL_FAILED')), \
             patch.object(bootstrap.subprocess, 'call') as call:
            self.assertEqual(bootstrap.main(['install']), 1)
        call.assert_not_called()

    @unittest.skipUnless(importlib.util.find_spec('ensurepip'), 'Python ensurepip not installed')
    def test_creates_private_venv_and_uses_it_for_dependency_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / 'scripts'
            scripts.mkdir(mode=0o700)
            for file in (root / 'requirements.txt', root / 'uterctl.py',
                         scripts / 'uter_wizard.py', scripts / 'install_wizard.py',
                         scripts / 'update_wizard.py'):
                file.write_text('')
            real_run = bootstrap.subprocess.run
            def intercept(args, *pos, **kwargs):
                if '-m' in args and 'pip' in args and 'install' in args:
                    return SimpleNamespace(returncode=0)
                return real_run(args, *pos, **kwargs)
            with patch.object(bootstrap.subprocess, 'run', side_effect=intercept) as run:
                try:
                    python, wizard = bootstrap.bootstrap(root, root / '.uter-wizard-venv')
                except bootstrap.BootstrapError:
                    environment = root / '.uter-wizard-venv'
                    unsafe = []
                    for item in environment.rglob('*'):
                        info = item.lstat()
                        if not item.is_symlink() and info.st_mode & 0o022:
                            unsafe.append((str(item.relative_to(environment)), oct(info.st_mode & 0o777)))
                    print('Generated venv writable modes:', unsafe[:10])
                    raise
            self.assertTrue(python.is_file())
            self.assertFalse(python.is_symlink())
            self.assertEqual(wizard, scripts / 'uter_wizard.py')
            self.assertEqual((root / '.uter-wizard-venv').stat().st_mode & 0o077, 0)
            self.assertTrue(any(str(root / 'requirements.txt') in item.args[0] for item in run.call_args_list))
