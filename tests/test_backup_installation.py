import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import uterctl
from scripts import backup_installation as m, backup_store
from scripts.bundle import build


@unittest.skipUnless(os.name == 'posix', 'Scheduled backup requires POSIX')
class BackupInstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'installation'
        self.home.mkdir(mode=0o700)
        self.runtime = self.home / 'runtime'
        self.runtime.mkdir(mode=0o700)
        self.backups = self.root / 'backups'
        self.backups.mkdir(mode=0o700)
        self.keys = self.root / 'keys'
        self.keys.mkdir(mode=0o700)
        self.backup_key = self.keys / 'backup.key'
        self.backup_key.write_bytes(b'K' * 32)
        self.backup_key.chmod(0o600)
        signer = Ed25519PrivateKey.generate()
        self.private = self.keys / 'signing.pem'
        self.public = self.keys / 'public.pem'
        self.private.write_bytes(signer.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))
        self.private.chmod(0o600)
        self.public.write_bytes(signer.public_key().public_bytes(serialization.Encoding.PEM,
                                                                serialization.PublicFormat.SubjectPublicKeyInfo))
        self.public.chmod(0o644)
        self.images = {name: 'registry.example/' + name + '@sha256:' + 'a' * 64
                       for name in ('guardrail', 'agent', 'redis')}
        self.manifest = {'schema': 1, 'config_schema': 1, 'status': 'released', 'version': '1.0.0',
                         'source_commit': 'b' * 40, 'data_epoch': 1, 'upgrade_from': [], 'images': self.images}
        source = self.root / 'manifest.json'
        source.write_text(json.dumps(self.manifest))
        (self.home / 'releases').mkdir()
        self.bundle = self.home / 'releases' / '1.0.0'
        build(source, self.bundle, self.private)
        self.site = {'backend': 'compose', 'name': 'uter-test', 'namespace': 'uter-test', 'context': 'default',
                     'port': 18001, 'guardrail_cpus': 2, 'smoke_command': ['python', 'smoke.py']}
        self.config = {'backend': 'compose', 'name': 'uter-test', 'context': 'default', 'port': 18001,
                       'guardrail_cpus': 2, 'images': self.images}
        self.state = {'current': self.manifest, 'previous': None, 'pending': None, 'adopted_installer': True}
        self.write_state()
        (self.home / 'install-state.json').write_text('{"status":"ready","acceptance":"not-run"}')
        (self.home / 'install.json').write_text(json.dumps(self.config))
        (self.runtime / 'site.json').write_text(json.dumps(self.site))
        self.identity = self.keys / 'runtime-identity.json'
        self.observed = {'docker_daemon_id': 'test-engine-id',
                         'container_ids': {'guardrail': 'a' * 64, 'agent': 'b' * 64, 'redis': 'c' * 64},
                         'volumes': {'redis': 'uter-test_redis-data', 'audit': 'uter-test_audit-data'}}
        self.register_identity('compose', 'default')

    def test_incomplete_fence_blocks_scheduled_backup_metadata(self):
        marker=self.home/'redis-fence-operation.json'
        marker.symlink_to(self.home/'missing')
        with self.assertRaisesRegex(m.BackupError, '^REDIS_FENCE_REQUIRES_INSPECTION$'):
            m.installation_metadata(self.home)

    def write_state(self):
        (self.home / 'state.json').write_text(json.dumps(self.state))

    def register_identity(self, backend, context):
        with patch.object(m, 'observe_runtime', return_value=self.observed), \
                patch.object(m.backup_snapshot.adopt_installation, 'verify_live'):
            return m.register(self.home, self.identity, self.public, backend, 'uter-test', context)

    def call(self, observed=None):
        with patch.object(m, 'observe_runtime', return_value=self.observed if observed is None else observed):
            return m.backup(self.home, self.backups, self.backup_key, self.public, self.identity,
                            'compose' if self.site['backend'] == 'compose' else 'kubernetes',
                            'uter-test', self.site['context'])

    def capture_fixture(self, home, cfg, site, current, destination, key, *, leave_stopped):
        self.assertTrue((self.home / 'operation.lock').exists())
        self.assertFalse(leave_stopped)
        writer = backup_store.BackupWriter(destination, key, home, site, current['version'])
        for label in ('runtime', 'redis', 'audit'):
            writer.put(label, io.BytesIO(('secret-fixture-' + label).encode()))
        return writer.finish()

    def test_creates_verified_encrypted_set_under_lock_without_modifying_state(self):
        before = (self.home / 'state.json').read_bytes()
        key_before = self.backup_key.read_bytes()
        with patch.object(m.backup_snapshot, 'capture', side_effect=self.capture_fixture) as capture:
            result = self.call()
        self.assertEqual(capture.call_count, 1)
        self.assertEqual(result['version'], '1.0.0')
        self.assertEqual(result['smoke'], 'not_run')
        dest = Path(result['backup'])
        self.assertTrue(dest.is_dir())
        for name in ('runtime.enc', 'redis.enc', 'audit.enc'):
            self.assertNotIn(b'secret-fixture', (dest / name).read_bytes())
        self.assertEqual((self.home / 'state.json').read_bytes(), before)
        self.assertEqual(self.backup_key.read_bytes(), key_before)
        self.assertFalse((self.home / 'operation.lock').exists())

    def test_sequential_backups_have_new_unique_directories(self):
        with patch.object(m.backup_snapshot, 'capture', side_effect=self.capture_fixture):
            a, b = self.call(), self.call()
        self.assertNotEqual(a['backup'], b['backup'])
        self.assertTrue(Path(a['backup']).is_dir())
        self.assertTrue(Path(b['backup']).is_dir())

    def test_create_key_is_private_once_only_and_never_prints_key(self):
        key = self.keys / 'new-key'
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = m.main(['create-key', '--home', str(self.home), '--backup-root', str(self.backups),
                             '--backup-key', str(key)])
        self.assertEqual(status, 0)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(key.read_bytes()), 32)
        before = key.read_bytes()
        self.assertNotIn(before.hex(), out.getvalue() + err.getvalue())
        with self.assertRaisesRegex(m.BackupError, '^BACKUP_KEY_ALREADY_EXISTS$'):
            m.create_key(self.home, self.backups, key)
        self.assertEqual(key.read_bytes(), before)

    def test_create_key_rejects_symlink_shared_directory_and_overlap(self):
        link = self.keys / 'new-link'
        link.symlink_to(self.backup_key)
        with self.assertRaisesRegex(m.BackupError, '^BACKUP_KEY_ALREADY_EXISTS$'):
            m.create_key(self.home, self.backups, link)
        self.keys.chmod(0o750)
        with self.assertRaisesRegex(m.BackupError, '^PRIVATE_DIRECTORY_REQUIRED$'):
            m.create_key(self.home, self.backups, self.keys / 'new-key')
        self.keys.chmod(0o700)
        with self.assertRaisesRegex(m.BackupError, '^BACKUP_PATHS_NOT_SEPARATE$'):
            m.create_key(self.home, self.backups, self.backups / 'backup.key')
        self.assertFalse((self.backups / 'backup.key').exists())

    @unittest.skipUnless(shutil.which('setfacl'), 'POSIX ACL tool not installed')
    def test_create_key_rejects_directory_with_named_user_acl(self):
        subprocess.run(['setfacl', '-m', 'u:12345:rx', str(self.keys)], check=True, capture_output=True)
        try:
            with self.assertRaisesRegex(m.BackupError, '^PRIVATE_DIRECTORY_REQUIRED$'):
                m.create_key(self.home, self.backups, self.keys / 'acl-key')
            self.assertFalse((self.keys / 'acl-key').exists())
        finally:
            subprocess.run(['setfacl', '-b', str(self.keys)], check=True, capture_output=True)

    def test_pending_and_unadopted_are_rejected_before_capture(self):
        cases = [('pending', {'current': self.manifest, 'pending': {'version': '2.0.0'}, 'adopted_installer': True}),
                 ('missing-pending', {'current': self.manifest, 'adopted_installer': True}),
                 ('unadopted', {'current': self.manifest, 'pending': None, 'adopted_installer': False})]
        for label, state in cases:
            self.state = state
            self.write_state()
            with self.subTest(label=label), patch.object(m.backup_snapshot, 'capture') as capture:
                with self.assertRaises(m.BackupError):
                    self.call()
                capture.assert_not_called()
                self.assertEqual(list(self.backups.iterdir()), [])

    def test_identity_mismatch_fails_before_capture_for_both_backends(self):
        for change in ('backend', 'name', 'context', 'port', 'guardrail_cpus'):
            old = self.config[change]
            self.config[change] = {'backend': 'kubernetes', 'name': 'other', 'context': 'other',
                                   'port': 18002, 'guardrail_cpus': 4}[change]
            (self.home / 'install.json').write_text(json.dumps(self.config))
            with self.subTest(field=change), patch.object(m.backup_snapshot, 'capture') as capture:
                with self.assertRaisesRegex(m.BackupError, '^INSTALLATION_IDENTITY_MISMATCH$'):
                    self.call()
                capture.assert_not_called()
            self.config[change] = old

    def test_kubernetes_identity_is_supported_without_running_cluster(self):
        self.config.update(backend='kubernetes', context='known-context')
        self.site.update(backend='helm', context='known-context')
        (self.home / 'install.json').write_text(json.dumps(self.config))
        (self.runtime / 'site.json').write_text(json.dumps(self.site))
        self.identity.unlink()
        self.observed = self.kube_identity()
        self.register_identity('kubernetes', 'known-context')
        # Runtime capture is mocked: this test only confirms validated dispatch.
        with patch.object(m.backup_snapshot, 'capture', return_value={'id': 'fixture'}) as capture, \
                patch.object(m.backup_store, 'verify_set', return_value={'id': 'fixture'}):
            result = self.call()
        self.assertEqual(capture.call_args.args[2]['backend'], 'helm')
        self.assertEqual(result['version'], '1.0.0')

    def test_registration_is_private_once_only_and_read_only_for_workloads(self):
        saved = self.identity.read_bytes()
        self.assertEqual(self.identity.stat().st_mode & 0o777, 0o600)
        pinned = json.loads(saved)
        self.assertEqual(pinned['runtime'], self.observed)
        self.assertEqual(pinned['installation_fingerprint'], backup_store.installation_fingerprint(self.home, self.site))
        with patch.object(m.backup_snapshot.adopt_installation, 'verify_live') as live, \
                patch.object(m, 'observe_runtime') as observe:
            with self.assertRaisesRegex(m.BackupError, '^IDENTITY_ALREADY_EXISTS$'):
                m.register(self.home, self.identity, self.public, 'compose', 'uter-test', 'default')
            live.assert_not_called()
            observe.assert_not_called()
        self.assertEqual(saved, self.identity.read_bytes())

    def test_registration_mismatch_or_live_failure_does_not_create_identity(self):
        new = self.keys / 'unregistered.json'
        with patch.object(m.backup_snapshot.adopt_installation, 'verify_live') as live, \
                patch.object(m, 'observe_runtime') as observe:
            with self.assertRaisesRegex(m.BackupError, '^EXPECTED_IDENTITY_MISMATCH$'):
                m.register(self.home, new, self.public, 'compose', 'wrong-name', 'default')
            live.assert_not_called()
            observe.assert_not_called()
        self.assertFalse(new.exists())
        with patch.object(m.backup_snapshot.adopt_installation, 'verify_live', side_effect=ValueError('secret-canary')), \
                patch.object(m, 'observe_runtime') as observe:
            with self.assertRaisesRegex(m.BackupError, '^LIVE_INSTALLATION_VERIFICATION_FAILED$'):
                m.register(self.home, new, self.public, 'compose', 'uter-test', 'default')
            observe.assert_called_once()
        self.assertFalse(new.exists())

    def test_registration_api_failure_does_not_create_identity(self):
        new = self.keys / 'not-created.json'
        with patch.object(m.backup_snapshot.adopt_installation, 'verify_live'), \
                patch.object(m, 'observe_runtime', side_effect=m.BackupError('RUNTIME_IDENTITY_QUERY_FAILED')):
            with self.assertRaisesRegex(m.BackupError, '^RUNTIME_IDENTITY_QUERY_FAILED$'):
                m.register(self.home, new, self.public, 'compose', 'uter-test', 'default')
        self.assertFalse(new.exists())

    def test_registration_refuses_runtime_drift_during_live_check(self):
        new = self.keys / 'racing.json'
        changes = [{'docker_daemon_id': 'first-engine'}, {'docker_daemon_id': 'second-engine'}]
        with patch.object(m.backup_snapshot.adopt_installation, 'verify_live'), \
                patch.object(m, 'observe_runtime', side_effect=changes):
            with self.assertRaisesRegex(m.BackupError, '^RUNTIME_IDENTITY_CHANGED_DURING_REGISTRATION$'):
                m.register(self.home, new, self.public, 'compose', 'uter-test', 'default')
        self.assertFalse(new.exists())

    def test_registration_rejects_existing_race_without_overwrite(self):
        before = self.identity.read_bytes()
        with self.assertRaisesRegex(m.BackupError, '^IDENTITY_ALREADY_EXISTS$'):
            m.write_identity_once(self.identity, {'canary': True})
        self.assertEqual(before, self.identity.read_bytes())

    def test_daemon_drift_is_refused_before_capture(self):
        with patch.object(m.backup_snapshot, 'capture') as capture:
            with self.assertRaisesRegex(m.BackupError, '^RUNTIME_IDENTITY_MISMATCH$'):
                self.call(dict(self.observed, docker_daemon_id='other-engine-id'))
            capture.assert_not_called()
        self.assertEqual(list(self.backups.iterdir()), [])

    def test_recreation_during_backup_is_reported_and_copy_retained(self):
        changed = json.loads(json.dumps(self.observed))
        changed['container_ids']['guardrail'] = 'd' * 64
        with patch.object(m, 'observe_runtime', side_effect=[self.observed, changed]), \
                patch.object(m.backup_snapshot, 'capture', side_effect=self.capture_fixture) as capture:
            with self.assertRaisesRegex(m.BackupError, '^RUNTIME_IDENTITY_CHANGED_AFTER_BACKUP$'):
                m.backup(self.home, self.backups, self.backup_key, self.public, self.identity,
                         'compose', 'uter-test', 'default')
            capture.assert_called_once()
        copies = list(self.backups.iterdir())
        self.assertEqual(len(copies), 1)
        self.assertTrue((copies[0] / 'manifest.json').exists())

    def test_compose_container_and_volume_replacement_are_refused(self):
        for group, key, replacement in [('container_ids', 'guardrail', 'd' * 64),
                                        ('container_ids', 'agent', 'd' * 64),
                                        ('container_ids', 'redis', 'd' * 64),
                                        ('volumes', 'redis', 'other-redis'),
                                        ('volumes', 'audit', 'other-audit')]:
            changed = json.loads(json.dumps(self.observed))
            changed[group][key] = replacement
            with self.subTest(group=group, key=key), patch.object(m.backup_snapshot, 'capture') as capture:
                with self.assertRaisesRegex(m.BackupError, '^RUNTIME_IDENTITY_MISMATCH$'):
                    self.call(changed)
                capture.assert_not_called()

    def test_unexpected_operator_identity_stops_before_runtime_query(self):
        with patch.object(m, 'observe_runtime') as observe, patch.object(m.backup_snapshot, 'capture') as capture:
            with self.assertRaisesRegex(m.BackupError, '^EXPECTED_IDENTITY_MISMATCH$'):
                m.backup(self.home, self.backups, self.backup_key, self.public, self.identity,
                         'compose', 'other-name', 'default')
            observe.assert_not_called()
            capture.assert_not_called()

    def test_runtime_identity_api_failure_stops_before_capture(self):
        with patch.object(m, 'observe_runtime', side_effect=m.BackupError('RUNTIME_IDENTITY_QUERY_FAILED')), \
                patch.object(m.backup_snapshot, 'capture') as capture:
            with self.assertRaisesRegex(m.BackupError, '^RUNTIME_IDENTITY_QUERY_FAILED$'):
                m.backup(self.home, self.backups, self.backup_key, self.public, self.identity,
                         'compose', 'uter-test', 'default')
            capture.assert_not_called()

    def test_kubernetes_uid_drift_is_refused_before_capture(self):
        self.config.update(backend='kubernetes', context='known-context')
        self.site.update(backend='helm', context='known-context')
        (self.home / 'install.json').write_text(json.dumps(self.config))
        (self.runtime / 'site.json').write_text(json.dumps(self.site))
        self.identity.unlink()
        self.observed = self.kube_identity()
        self.register_identity('kubernetes', 'known-context')
        variants = []
        for group, key in [('root', 'kube_system_uid'), ('root', 'namespace_uid'),
                           ('deployment_uids', 'guardrail'), ('deployment_uids', 'agent'),
                           ('deployment_uids', 'redis'), ('pvc_uids', 'guardrail'), ('pvc_uids', 'redis')]:
            changed = json.loads(json.dumps(self.observed))
            (changed if group == 'root' else changed[group])[key] = 'different-uid'
            variants.append(changed)
        for changed in variants:
            with self.subTest(observed=changed), patch.object(m.backup_snapshot, 'capture') as capture:
                with self.assertRaisesRegex(m.BackupError, '^RUNTIME_IDENTITY_MISMATCH$'):
                    self.call(changed)
                capture.assert_not_called()

    @staticmethod
    def kube_identity():
        return {'kube_system_uid': 'cluster-uid-a', 'namespace_uid': 'namespace-uid-a',
                'deployment_uids': {'guardrail': 'dep-guard', 'agent': 'dep-agent', 'redis': 'dep-redis'},
                'pvc_uids': {'guardrail': 'pvc-guard', 'redis': 'pvc-redis'}}

    def test_pin_is_bound_to_original_installation_and_cannot_live_in_backup(self):
        pin = json.loads(self.identity.read_text())
        pin['installation_fingerprint'] = 'restored-installation-fingerprint'
        self.identity.write_text(json.dumps(pin))
        with patch.object(m.backup_snapshot, 'capture') as capture:
            with self.assertRaisesRegex(m.BackupError, '^RUNTIME_IDENTITY_MISMATCH$'):
                self.call()
            capture.assert_not_called()
        inside = self.home / 'identity.json'
        with patch.object(m.backup_snapshot.adopt_installation, 'verify_live') as live:
            with self.assertRaisesRegex(m.BackupError, '^IDENTITY_PATH_NOT_SEPARATE$'):
                m.register(self.home, inside, self.public, 'compose', 'uter-test', 'default')
            live.assert_not_called()
        self.assertFalse(inside.exists())

    def test_observe_runtime_uses_bound_context_and_sanitizes_failures(self):
        context = json.dumps('unix:///var/run/docker.sock')
        outputs = [context, 'daemon-id-a\n', 'a' * 12, 'a' * 64, 'b' * 12, 'b' * 64,
                   'c' * 12, 'c' * 64, 'volume:uter-test_redis-data;',
                   json.dumps({'project': 'uter-test', 'volume': 'redis-data'}),
                   'volume:uter-test_audit-data;', json.dumps({'project': 'uter-test', 'volume': 'audit-data'})]
        with patch.dict(os.environ, {}, clear=True), patch.object(m.install_recovery, 'run_readonly', side_effect=outputs) as run:
            result = m.observe_runtime(self.site)
        self.assertEqual(result['docker_daemon_id'], 'daemon-id-a')
        self.assertEqual(result['container_ids'], {'guardrail': 'a' * 64, 'agent': 'b' * 64, 'redis': 'c' * 64})
        self.assertEqual(result['volumes'], {'redis': 'uter-test_redis-data', 'audit': 'uter-test_audit-data'})
        self.assertEqual(run.call_args_list[1].args[0][0:4], ['docker', '--context', 'default', 'info'])
        self.assertTrue(all('Config.Env' not in ' '.join(call.args[0]) for call in run.call_args_list))
        self.site.update(backend='helm', context='bound-context')
        values = ['uid-cluster-a', 'uid-ns-a', 'uid-dep-g', 'uid-dep-a', 'uid-dep-r',
                  'guardrail', 'data', 'uter-test-guardrail', 'redis', 'data', 'uter-test-redis',
                  'uid-pvc-g', 'uid-pvc-r']
        with patch.object(m.install_recovery, 'run_readonly', side_effect=values) as run:
            result = m.observe_runtime(self.site)
        self.assertEqual(result['kube_system_uid'], 'uid-cluster-a')
        self.assertEqual(result['namespace_uid'], 'uid-ns-a')
        self.assertEqual(result['deployment_uids'], {'guardrail': 'uid-dep-g', 'agent': 'uid-dep-a', 'redis': 'uid-dep-r'})
        self.assertEqual(result['pvc_uids'], {'guardrail': 'uid-pvc-g', 'redis': 'uid-pvc-r'})
        self.assertTrue(all(call.args[0][0:3] == ['kubectl', '--context', 'bound-context'] for call in run.call_args_list))
        with patch.object(m.install_recovery, 'run_readonly', side_effect=m.install_recovery.DiagnosticError('secret-canary')):
            with self.assertRaisesRegex(m.BackupError, '^RUNTIME_IDENTITY_QUERY_FAILED$') as exc:
                m.observe_runtime(self.site)
        self.assertNotIn('canary', str(exc.exception))

    def test_pin_rejects_compose_duplicates_and_non_volume_mounts(self):
        context = json.dumps('unix:///var/run/docker.sock')
        valid = [context, 'daemon-id-a', 'a' * 12, 'a' * 64, 'b' * 12, 'b' * 64,
                 'c' * 12, 'c' * 64, 'volume:uter-test_redis-data;',
                 json.dumps({'project': 'uter-test', 'volume': 'redis-data'}),
                 'volume:uter-test_audit-data;', json.dumps({'project': 'uter-test', 'volume': 'audit-data'})]
        for index, value in [(2, 'a' * 12 + '\n' + 'd' * 12), (3, 'd' * 64),
                             (8, 'bind:/private/path;'), (8, 'volume:foreign_redis-data;'),
                             (9, json.dumps({'project': 'foreign', 'volume': 'redis-data'})),
                             (9, json.dumps({'project': 'uter-test', 'volume': 'foreign'})),
                             (10, 'volume:uter-test_redis-data;'),
                             (11, json.dumps({'project': 'foreign', 'volume': 'audit-data'}))]:
            outputs = list(valid)
            outputs[index] = value
            with self.subTest(index=index), patch.dict(os.environ, {}, clear=True), \
                    patch.object(m.install_recovery, 'run_readonly', side_effect=outputs):
                with self.assertRaisesRegex(m.BackupError, '^RUNTIME_IDENTITY_INVALID$') as exc:
                    m.observe_runtime(self.site)
                self.assertNotIn('/private/path', str(exc.exception))

    def test_pin_rejects_duplicate_or_invalid_kubernetes_uids(self):
        self.site.update(backend='helm', context='bound-context')
        valid = ['uid-cluster-a', 'uid-ns-a', 'uid-dep-g', 'uid-dep-a', 'uid-dep-r',
                 'guardrail', 'data', 'uter-test-guardrail', 'redis', 'data', 'uter-test-redis',
                 'uid-pvc-g', 'uid-pvc-r']
        for index, value in [(1, 'uid-cluster-a'), (4, 'uid-dep-g'), (12, 'secret-canary\nextra')]:
            outputs = list(valid)
            outputs[index] = value
            with self.subTest(index=index), patch.object(m.install_recovery, 'run_readonly', side_effect=outputs):
                with self.assertRaisesRegex(m.BackupError, '^RUNTIME_IDENTITY_INVALID$') as exc:
                    m.observe_runtime(self.site)
                self.assertNotIn('canary', str(exc.exception))

    def test_kubernetes_deployment_pvc_mismatch_is_rejected_before_capture(self):
        self.config.update(backend='kubernetes', context='known-context')
        self.site.update(backend='helm', context='known-context')
        (self.home / 'install.json').write_text(json.dumps(self.config))
        (self.runtime / 'site.json').write_text(json.dumps(self.site))
        self.identity.unlink()
        self.observed = self.kube_identity()
        self.register_identity('kubernetes', 'known-context')
        valid = ['uid-cluster-a', 'uid-ns-a', 'uid-dep-g', 'uid-dep-a', 'uid-dep-r',
                 'guardrail', 'data', 'uter-test-guardrail', 'redis', 'data', 'uter-test-redis',
                 'uid-pvc-g', 'uid-pvc-r']
        for index, replacement in [(5, 'wrong-container'), (6, 'different-volume'),
                                   (7, 'other-guardrail-pvc'), (8, 'wrong-container'),
                                   (9, 'different-volume'), (10, 'other-redis-pvc')]:
            values = list(valid)
            values[index] = replacement
            with self.subTest(index=index), patch.object(m.install_recovery, 'run_readonly', side_effect=values), \
                    patch.object(m.backup_snapshot, 'capture') as capture:
                with self.assertRaisesRegex(m.BackupError, '^RUNTIME_IDENTITY_INVALID$'):
                    m.backup(self.home, self.backups, self.backup_key, self.public, self.identity,
                             'kubernetes', 'uter-test', 'known-context')
                capture.assert_not_called()

    def test_incomplete_backup_and_recovery_block_without_mutation(self):
        for filename, contents in [('backup-operation.json', '{}'), ('recovery-operation.json', '{"phase":"creating"}')]:
            path = self.home / filename
            path.write_text(contents)
            with self.subTest(filename=filename), patch.object(m.backup_snapshot, 'capture') as capture:
                with self.assertRaises(m.BackupError):
                    self.call()
                capture.assert_not_called()
                self.assertTrue(path.exists())
            path.unlink()

    def test_state_is_checked_after_lock_acquisition(self):
        @contextlib.contextmanager
        def changed_during_lock(home):
            self.state['pending'] = {'version': '2.0.0'}
            self.write_state()
            yield
        with patch.object(m.uterctl, 'locked', side_effect=changed_during_lock), patch.object(m.backup_snapshot, 'capture') as capture:
            with self.assertRaisesRegex(m.BackupError, '^CONTROLLER_OPERATION_PENDING$'):
                self.call()
            capture.assert_not_called()

    def test_running_operation_lock_is_never_removed(self):
        lock = self.home / 'operation.lock'
        lock.write_text('another-process')
        with patch.object(m.backup_snapshot, 'capture') as capture:
            with self.assertRaises(FileExistsError):
                self.call()
            capture.assert_not_called()
        self.assertEqual(lock.read_text(), 'another-process')

    def test_current_bundle_must_match_signed_state(self):
        self.state['current'] = dict(self.manifest, source_commit='c' * 40)
        self.write_state()
        with patch.object(m.backup_snapshot, 'capture') as capture:
            with self.assertRaisesRegex(m.BackupError, '^CURRENT_BUNDLE_STATE_MISMATCH$'):
                self.call()
            capture.assert_not_called()

    def test_untrusted_publisher_signature_is_rejected(self):
        other = Ed25519PrivateKey.generate()
        self.public.write_bytes(other.public_key().public_bytes(serialization.Encoding.PEM,
                                                               serialization.PublicFormat.SubjectPublicKeyInfo))
        with patch.object(m.backup_snapshot, 'capture') as capture:
            with self.assertRaisesRegex(m.BackupError, '^CURRENT_BUNDLE_VERIFICATION_FAILED$'):
                self.call()
            capture.assert_not_called()

    def test_key_permissions_symlinks_and_hardlinks_are_rejected(self):
        self.backup_key.chmod(0o644)
        with self.assertRaisesRegex(m.BackupError, '^FILE_UNSAFE$'):
            self.call()
        self.backup_key.chmod(0o600)
        link = self.keys / 'linked-key'
        link.symlink_to(self.backup_key)
        with self.assertRaises(m.BackupError):
            m.backup(self.home, self.backups, link, self.public, self.identity, 'compose', 'uter-test', 'default')
        link.unlink()
        os.link(self.backup_key, link)
        with self.assertRaisesRegex(m.BackupError, '^FILE_UNSAFE$'):
            self.call()

    def test_identity_file_links_and_broad_permissions_are_rejected(self):
        self.identity.chmod(0o644)
        with self.assertRaisesRegex(m.BackupError, '^FILE_UNSAFE$'):
            self.call()
        self.identity.chmod(0o600)
        link = self.keys / 'linked-identity'
        link.symlink_to(self.identity)
        with self.assertRaises(m.BackupError):
            m.backup(self.home, self.backups, self.backup_key, self.public, link,
                     'compose', 'uter-test', 'default')
        link.unlink()
        os.link(self.identity, link)
        with self.assertRaisesRegex(m.BackupError, '^FILE_UNSAFE$'):
            self.call()

    def test_insecure_or_overlapping_directories_are_rejected(self):
        self.backups.chmod(0o755)
        with self.assertRaisesRegex(m.BackupError, '^PRIVATE_DIRECTORY_REQUIRED$'):
            self.call()
        self.backups.chmod(0o700)
        inside = self.home / 'backups'
        inside.mkdir(mode=0o700)
        with self.assertRaisesRegex(m.BackupError, '^BACKUP_PATHS_NOT_SEPARATE$'):
            m.backup(self.home, inside, self.backup_key, self.public, self.identity, 'compose', 'uter-test', 'default')

    def test_bundle_hardlinks_or_symlinks_fail_before_signature_check(self):
        link = self.bundle / 'extra'
        os.link(self.bundle / 'manifest.json', link)
        with patch.object(m.backup_snapshot, 'capture') as capture:
            with self.assertRaisesRegex(m.BackupError, '^BUNDLE_INVALID$'):
                self.call()
            capture.assert_not_called()
        link.unlink()
        link.symlink_to(self.bundle / 'manifest.json')
        with self.assertRaisesRegex(m.BackupError, '^BUNDLE_INVALID$'):
            self.call()

    def test_linked_or_special_runtime_data_are_never_snapshotted(self):
        outside = self.root / 'outside'
        outside.write_text('outside-data-canary')
        target = self.runtime / 'injected'
        for kind in ('hardlink', 'symlink', 'fifo'):
            if kind == 'hardlink':
                os.link(outside, target)
            elif kind == 'symlink':
                target.symlink_to(outside)
            else:
                os.mkfifo(target)
            with self.subTest(kind=kind), patch.object(m.backup_snapshot, 'capture') as capture:
                with self.assertRaisesRegex(m.BackupError, '^SNAPSHOT_SOURCE_UNSAFE$'):
                    self.call()
                capture.assert_not_called()
            target.unlink()
        self.assertEqual(outside.read_text(), 'outside-data-canary')

    def test_tampered_backup_fails_and_is_retained(self):
        def tamper(*args, **kwargs):
            metadata = self.capture_fixture(*args, **kwargs)
            destination = args[4]
            (destination / 'redis.enc').write_bytes(b'tampered')
            return metadata
        with patch.object(m.backup_snapshot, 'capture', side_effect=tamper):
            with self.assertRaisesRegex(m.BackupError, '^BACKUP_FAILED_INSPECT_JOURNAL_AND_WORKLOADS$'):
                self.call()
        found = list(self.backups.iterdir())
        self.assertEqual(len(found), 1)
        self.assertTrue((found[0] / 'redis.enc').exists())
        self.assertFalse((self.home / 'operation.lock').exists())

    def test_failure_output_does_not_leak_exception_or_key(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                patch.object(m, 'observe_runtime', return_value=self.observed), \
                patch.object(m.backup_snapshot, 'capture', side_effect=RuntimeError('secret-canary')):
            code = m.main(['backup', '--home', str(self.home), '--backup-root', str(self.backups),
                           '--backup-key', str(self.backup_key), '--publisher-key', str(self.public),
                           '--identity-file', str(self.identity), '--expected-backend', 'compose',
                           '--expected-name', 'uter-test', '--expected-context', 'default'])
        self.assertEqual(code, 1)
        self.assertNotIn('secret-canary', out.getvalue() + err.getvalue())
        self.assertNotIn('KKKKKKKK', out.getvalue() + err.getvalue())
        self.assertEqual(json.loads(err.getvalue())['code'], 'BACKUP_FAILED_INSPECT_JOURNAL_AND_WORKLOADS')


if __name__ == '__main__':
    unittest.main()
