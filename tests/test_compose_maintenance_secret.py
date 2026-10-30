import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import backup_crypto, backup_snapshot, backup_store, compose_maintenance_secret as secret, recover_compose


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and os.geteuid() == 0,
                     'requires root on Linux with POSIX ownership and no-follow')
class ComposeMaintenanceSecretTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'; self.runtime = self.home / 'runtime'
        self.runtime.mkdir(parents=True, mode=0o700)
        self.config = self.home / 'install.json'
        self.config.write_text(json.dumps({'backend':'compose','maintenance_enabled':True}))
        self.key = b'G' * 64
        self.file = self.runtime / secret.KEY_NAME
        self.file.write_bytes(self.key); os.chown(self.file, 10001, 10001); self.file.chmod(0o400)
        self.backup_key = b'z' * 32
        self.site = {'backend':'compose', 'name':'uter-test', 'namespace':'uter-test', 'context':'default'}

    def writer(self):
        return backup_store.BackupWriter(self.root/'backup', self.backup_key, self.home, self.site, '1.0.0')

    def test_encrypted_archive_and_permission_restoration(self):
        writer = self.writer(); backup_snapshot.archive_runtime(self.home, writer)
        encrypted = self.root/'backup/runtime.enc'
        self.assertNotIn(self.key, encrypted.read_bytes())
        out = io.BytesIO()
        backup_crypto.decrypt_verify(encrypted, self.backup_key, backup_store.aad(writer.manifest['id'], 'runtime'),
                                     writer.manifest['files']['runtime'], out)
        out.seek(0)
        with tarfile.open(fileobj=out, mode='r:') as archive:
            self.assertEqual(archive.getnames().count('runtime/maintenance-key'), 1)
            self.assertEqual(archive.extractfile('runtime/maintenance-key').read(), self.key)
        staged = self.root/'staged'; staged.mkdir(mode=0o700)
        path = staged/secret.KEY_NAME; path.write_bytes(self.key); path.chmod(0o600)
        observed = secret.read_key(staged, staged=True)
        secret.prepare_restored_key(staged, observed)
        self.assertEqual((path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode)), (10001, 10001, 0o400))
        self.assertEqual(secret.read_key(staged), self.key)

    def test_missing_bad_mode_bad_owner_and_bad_content_fail_before_snapshot(self):
        self.file.unlink()
        with self.assertRaisesRegex(ValueError, 'MAINTENANCE_KEY_UNVERIFIED'):
            backup_snapshot.archive_runtime(self.home, self.writer())
        self.assertFalse((self.root/'backup/runtime.enc').exists())
        self.file.write_bytes(self.key); os.chown(self.file, 10001, 10001)
        for change in ('mode', 'owner', 'content'):
            os.chown(self.file, 10001, 10001); self.file.chmod(0o400)
            if change == 'mode': self.file.chmod(0o440)
            if change == 'owner': os.chown(self.file, 0, 0)
            if change == 'content': self.file.write_bytes(b'too short')
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'MAINTENANCE_KEY_UNVERIFIED'):
                secret.read_key(self.runtime)
            if change == 'content': self.file.write_bytes(self.key)

    def test_symlink_and_hardlink_refused(self):
        self.file.unlink(); other = self.runtime/'other'; other.write_bytes(self.key)
        os.chown(other, 10001, 10001); other.chmod(0o400)
        self.file.symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'MAINTENANCE_KEY_UNVERIFIED'): secret.read_key(self.runtime)
        self.file.unlink(); os.link(other, self.file)
        with self.assertRaisesRegex(ValueError, 'MAINTENANCE_KEY_UNVERIFIED'): secret.read_key(self.runtime)

    def test_runtime_directory_symlink_or_nonprivate_mode_refused(self):
        alias = self.root/'alias'; alias.symlink_to(self.runtime, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'MAINTENANCE_KEY_UNVERIFIED'): secret.read_key(alias)
        self.runtime.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'MAINTENANCE_KEY_UNVERIFIED'): secret.read_key(self.runtime)

    def test_changed_key_during_archive_removes_encrypted_component(self):
        writer = self.writer()
        original = secret.read_key
        with patch.object(secret, 'read_key', side_effect=[self.key, b'X' * 64]):
            with self.assertRaisesRegex(ValueError, 'MAINTENANCE_KEY_UNVERIFIED'):
                backup_snapshot.archive_runtime(self.home, writer)
        self.assertFalse((self.root/'backup/runtime.enc').exists())
        self.assertEqual(original(self.runtime), self.key)

    def test_legacy_without_marker_still_archives_without_key(self):
        self.file.unlink(); self.config.write_text('{"backend":"compose"}')
        writer = self.writer(); backup_snapshot.archive_runtime(self.home, writer)
        self.assertIn('runtime', writer.manifest['files'])
        self.assertFalse(secret.enabled({'maintenance_enabled':False}))
        with self.assertRaisesRegex(ValueError, 'MAINTENANCE_CONFIG_INVALID'):
            secret.enabled({'maintenance_enabled':'true'})

    def test_legacy_or_disabled_rejects_unexpected_key_before_archiving(self):
        for marker in (None, False):
            cfg = {'backend':'compose'}
            if marker is not None: cfg['maintenance_enabled'] = marker
            self.config.write_text(json.dumps(cfg))
            for dangling in (False, True):
                if dangling:
                    self.file.unlink(); self.file.symlink_to(self.runtime/'missing')
                writer = self.writer()
                with self.subTest(marker=marker,dangling=dangling), \
                     self.assertRaisesRegex(ValueError, 'MAINTENANCE_KEY_UNEXPECTED'):
                    backup_snapshot.archive_runtime(self.home,writer)
                self.assertFalse((self.root/'backup/runtime.enc').exists())
                (self.root/'backup').rmdir()
                if dangling:
                    self.file.unlink(); self.file.write_bytes(self.key)

    def test_orphan_appearing_during_archive_removes_encrypted_component(self):
        self.file.unlink(); self.config.write_text('{"backend":"compose"}')
        writer = self.writer()
        put_generated = writer.put_generated
        def introduce_orphan(label, generate):
            self.file.write_bytes(self.key)
            return put_generated(label, generate)
        with patch.object(writer, 'put_generated', side_effect=introduce_orphan):
            with self.assertRaisesRegex(ValueError, 'MAINTENANCE_KEY_UNEXPECTED'):
                backup_snapshot.archive_runtime(self.home, writer)
        self.assertFalse((self.root/'backup/runtime.enc').exists())
        self.assertNotIn('runtime', writer.manifest['files'])

    def test_marker_change_during_legacy_archive_removes_encrypted_component(self):
        self.file.unlink(); self.config.write_text('{"backend":"compose"}')
        writer = self.writer(); put_generated = writer.put_generated
        def change_marker(label, generate):
            self.config.write_text('{"backend":"compose","maintenance_enabled":true}')
            return put_generated(label, generate)
        with patch.object(writer, 'put_generated', side_effect=change_marker):
            with self.assertRaisesRegex(ValueError, 'MAINTENANCE_KEY_UNEXPECTED'):
                backup_snapshot.archive_runtime(self.home, writer)
        self.assertFalse((self.root/'backup/runtime.enc').exists())

    def test_transient_orphan_during_tar_is_not_archived(self):
        self.file.unlink(); self.config.write_text('{"backend":"compose"}')
        writer = self.writer(); add = tarfile.TarFile.add
        def insert_during_add(tar, name, arcname=None, *args, **kwargs):
            if arcname != 'runtime':
                return add(tar,name,arcname,*args,**kwargs)
            self.file.write_bytes(self.key)
            try:
                return add(tar,name,arcname,*args,**kwargs)
            finally:
                self.file.unlink()
        with patch.object(tarfile.TarFile,'add',new=insert_during_add):
            with self.assertRaisesRegex(ValueError,'MAINTENANCE_KEY_UNEXPECTED'):
                backup_snapshot.archive_runtime(self.home,writer)
        self.assertFalse(self.file.exists())
        self.assertFalse((self.root/'backup/runtime.enc').exists())

    def test_archived_install_config_is_the_validated_bytes(self):
        self.file.unlink()
        initial = b'{"backend":"compose"}'
        self.config.write_bytes(initial)
        writer = self.writer(); add = tarfile.TarFile.add
        def temporary_change(tar, name, arcname=None, *args, **kwargs):
            if arcname != 'runtime':
                return add(tar,name,arcname,*args,**kwargs)
            self.config.write_bytes(b'{"backend":"compose","maintenance_enabled":true}')
            try:
                return add(tar,name,arcname,*args,**kwargs)
            finally:
                self.config.write_bytes(initial)
        with patch.object(tarfile.TarFile,'add',new=temporary_change):
            backup_snapshot.archive_runtime(self.home,writer)
        out=io.BytesIO()
        backup_crypto.decrypt_verify(self.root/'backup/runtime.enc',self.backup_key,
                                     backup_store.aad(writer.manifest['id'],'runtime'),
                                     writer.manifest['files']['runtime'],out)
        out.seek(0)
        with tarfile.open(fileobj=out,mode='r:') as archive:
            self.assertEqual(archive.getnames().count('install.json'),1)
            self.assertEqual(archive.extractfile('install.json').read(),initial)

    def test_temporarily_missing_install_config_still_archives_bound_bytes(self):
        self.file.unlink(); initial=b'{"backend":"compose"}'
        self.config.write_bytes(initial)
        writer=self.writer(); add=tarfile.TarFile.add; addfile=tarfile.TarFile.addfile
        def remove_config(tar,name,arcname=None,*args,**kwargs):
            if arcname=='runtime':
                self.config.unlink()
            return add(tar,name,arcname,*args,**kwargs)
        def restore_config(tar,member,*args,**kwargs):
            if member.name=='install.json':
                self.config.write_bytes(initial)
            return addfile(tar,member,*args,**kwargs)
        with patch.object(tarfile.TarFile,'add',new=remove_config), \
             patch.object(tarfile.TarFile,'addfile',new=restore_config):
            backup_snapshot.archive_runtime(self.home,writer)
        out=io.BytesIO()
        backup_crypto.decrypt_verify(self.root/'backup/runtime.enc',self.backup_key,
                                     backup_store.aad(writer.manifest['id'],'runtime'),
                                     writer.manifest['files']['runtime'],out)
        out.seek(0)
        with tarfile.open(fileobj=out,mode='r:') as archive:
            self.assertEqual(archive.getnames().count('install.json'),1)
            self.assertEqual(archive.extractfile('install.json').read(),initial)

    def test_changed_staged_key_is_not_chowned(self):
        path = self.runtime/secret.KEY_NAME
        os.chown(path, 0, 0); path.chmod(0o600)
        with patch.object(secret.os, 'fchown') as change:
            with self.assertRaisesRegex(ValueError, 'MAINTENANCE_KEY_UNVERIFIED'):
                secret.prepare_restored_key(self.runtime, b'X'*64)
            change.assert_not_called()

    def test_existing_permission_restoration_without_opt_in_is_unchanged(self):
        with patch.object(recover_compose.os, 'chown'), patch.object(recover_compose.os, 'chmod'), \
             patch.object(recover_compose.install, 'prepare_ca_permissions'), \
             patch.object(secret, 'prepare_restored_key') as guarded:
            recover_compose.prepare_runtime_permissions(self.runtime)
            guarded.assert_not_called()

    def test_opt_in_restore_refuses_before_pull_or_target_creation(self):
        current = {'version':'1.0.0'}
        def preflight(_home, _backup, _backup_key, _publisher_key, stage):
            source = stage/'runtime-staged'; source.mkdir(parents=True)
            (source/'state.json').write_text(json.dumps({'current':current}))
            (source/'install.json').write_text(json.dumps({'backend':'compose','maintenance_enabled':True}))
            return {'backend':'compose'}
        def run(args, **_kwargs):
            return b'[{"Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}}}]' if args[3:5] == ['context','inspect'] else b''
        target = self.root/'new-home'
        with patch.object(recover_compose, 'run', side_effect=run) as command, \
             patch.object(recover_compose.socket, 'socket'), \
             patch.object(recover_compose.subprocess, 'run') as subprocess_run, \
             patch.object(recover_compose.recovery_preflight, 'preflight', side_effect=preflight), \
             patch.object(recover_compose.uterctl, 'site_config', return_value={'name':'uter-old'}), \
             patch.object(recover_compose.uterctl, 'verify', return_value=current), \
             patch.object(recover_compose.maintenance_protocol, 'verify_capability', return_value=current), \
             patch.object(secret, 'read_key', return_value=self.key):
            subprocess_run.return_value.returncode = 1
            with self.assertRaisesRegex(ValueError, 'MAINTENANCE_RESTORE_PROFILE_UNSUPPORTED'):
                recover_compose.restore(self.home,'/backup','/backup-key','/pub',target,'uter-new',18001)
            self.assertFalse(target.exists())
            self.assertFalse(any('pull' in c.args[0] or 'up' in c.args[0] for c in command.call_args_list))
