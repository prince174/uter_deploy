import base64
import copy
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import yaml

from scripts import backup_snapshot, recover_kubernetes, restore_backup


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'requires POSIX private files')
class KubernetesMaintenanceBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        (self.home / 'runtime').mkdir()
        self.config = {'backend': 'helm', 'name': 'uter'}
        self.site = {'name': 'uter', 'namespace': 'uter'}
        self.values = {'guardrailSecret': 'uter-guardrail-env', 'agentSecret': 'uter-agent-env',
                       'redisSecret': 'uter-redis-secret', 'policyConfigMap': 'uter-policies',
                       'profileConfigMap': 'uter-profiles', 'imagePullSecrets': [], 'useEmbeddedModels': True}
        self.manifest = {'maintenance_protocol': {'version': 1, 'services': ['agent', 'guardrail']}}
        self.key = b'z' * 40
        self.save()

    def save(self):
        (self.home / 'install.json').write_text(json.dumps(self.config))
        (self.home / 'runtime/values.yaml').write_text(yaml.safe_dump(self.values))

    def enable(self):
        self.config['maintenance_enabled'] = True
        self.values['maintenanceSecret'] = 'uter-maintenance'
        path = self.home / 'runtime/maintenance-key'
        path.write_bytes(self.key)
        path.chmod(0o600)
        self.save()

    def secret(self):
        return {'kind': 'Secret', 'type': 'Opaque', 'metadata': {'name': 'uter-maintenance', 'namespace': 'uter'},
                'data': {'key': base64.b64encode(self.key).decode('ascii')}}

    def test_legacy_unchanged_and_unexpected_reference_refused(self):
        before = backup_snapshot.kube_objects(self.home, self.site)
        self.assertNotIn('secret/uter-maintenance', before)
        self.config['maintenance_enabled'] = False
        self.save()
        self.assertEqual(before, backup_snapshot.kube_objects(self.home, self.site))
        self.values['maintenanceSecret'] = 'uter-maintenance'
        self.save()
        with self.assertRaises(ValueError): backup_snapshot.kube_objects(self.home, self.site)

    def test_signed_capability_opt_in_and_private_key_are_all_required(self):
        self.enable()
        self.assertIn('secret/uter-maintenance', backup_snapshot.kube_objects(self.home, self.site, manifest=self.manifest))
        for manifest in (None, {}, {'maintenance_protocol': {'version': True, 'services': ['agent', 'guardrail']}},
                         {'maintenance_protocol': {'version': 1, 'services': ['guardrail', 'agent']}}):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                backup_snapshot.kube_objects(self.home, self.site, manifest=manifest)
        self.config['maintenance_enabled'] = 1
        self.save()
        with self.assertRaises(ValueError): backup_snapshot.kube_objects(self.home, self.site, manifest=self.manifest)
        self.config['maintenance_enabled'] = True
        self.save()
        (self.home / 'runtime/maintenance-key').chmod(0o644)
        with self.assertRaises(Exception): backup_snapshot.kube_objects(self.home, self.site, manifest=self.manifest)
        (self.home / 'runtime/maintenance-key').unlink()
        with self.assertRaises(Exception): backup_snapshot.kube_objects(self.home, self.site, manifest=self.manifest)

    def test_legacy_rejects_untracked_key_and_contradictory_environment(self):
        for field in ('guardrailEnv', 'agentEnv'):
            for env in ({'UTER_MAINTENANCE_ENABLED': 'true'}, {'UTER_MAINTENANCE_ENABLED': 0},
                        {'UTER_MAINTENANCE_KEY_FILE': '/secret/key'}, ['invalid']):
                self.values[field] = env
                self.save()
                with self.subTest(field=field, env=env), self.assertRaises(ValueError):
                    backup_snapshot.kube_objects(self.home, self.site)
            self.values.pop(field)
        self.save()
        key = self.home / 'runtime/maintenance-key'
        key.write_bytes(self.key)
        with self.assertRaises(ValueError): backup_snapshot.kube_objects(self.home, self.site)
        key.unlink()
        key.symlink_to(self.home / 'missing')
        with self.assertRaises(ValueError): backup_snapshot.kube_objects(self.home, self.site)

    def test_opt_in_restore_refuses_before_cluster_or_target_changes(self):
        self.enable()
        current = dict(self.manifest, version='1.0.0')
        def preflight(_home, _backup, _backup_key, _publisher, stage):
            source = stage / 'runtime-staged'
            shutil.copytree(self.home / 'runtime', source / 'runtime')
            (source / 'state.json').write_text(json.dumps({'current': current}))
            (source / 'install.json').write_text(json.dumps(self.config))
            return {'backend': 'helm'}
        source_home = self.home / 'original'; source_home.mkdir()
        target = self.home / 'target'
        with patch.object(recover_kubernetes.recovery_preflight, 'preflight', side_effect=preflight), \
             patch.object(recover_kubernetes.uterctl, 'site_config', return_value=self.site), \
             patch.object(recover_kubernetes.uterctl, 'verify', return_value=current), \
             patch.object(recover_kubernetes.socket, 'socket'), \
             patch.object(recover_kubernetes, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'MAINTENANCE_RESTORE_PROFILE_UNSUPPORTED'):
                recover_kubernetes.restore(source_home, '/backup', '/key', '/pub', target, 'new', 'test', 18001)
            run.assert_not_called()
            self.assertFalse(target.exists())
    def test_live_secret_requires_identity_shape_and_matching_private_key(self):
        self.enable()
        original = self.secret()
        backup_snapshot.validate_maintenance_secret(original, 'uter-maintenance', 'uter', home=self.home)
        cases = []
        for mutation in (lambda x: x.update(type='kubernetes.io/tls'),
                         lambda x: x['metadata'].update(namespace='other'),
                         lambda x: x['data'].update(extra='eA=='),
                         lambda x: x['data'].update(key='%%%'),
                         lambda x: x['data'].update(key=base64.b64encode(b'x' * 40).decode()),
                         lambda x: x.update(stringData={'key': 'x'})):
            item = copy.deepcopy(original); mutation(item); cases.append(item)
        for item in cases:
            with self.subTest(item=list(item)), self.assertRaisesRegex(ValueError, 'Maintenance Secret invalid'):
                backup_snapshot.validate_maintenance_secret(item, 'uter-maintenance', 'uter', home=self.home)

    def test_runtime_archive_and_private_staging_preserve_key(self):
        self.enable()
        class Writer:
            def put_generated(inner, label, generate):
                output = io.BytesIO(); generate(output); inner.payload = output.getvalue()
        writer = Writer()
        backup_snapshot.archive_runtime(self.home, writer)
        archive = self.home.parent / (self.home.name + '-snapshot.tar')
        archive.write_bytes(writer.payload)
        self.addCleanup(archive.unlink, missing_ok=True)
        destination = self.home.parent / (self.home.name + '-staged')
        self.addCleanup(shutil.rmtree, destination, True)
        restore_backup.stage_archive(archive, destination)
        key = destination / 'runtime/maintenance-key'
        self.assertEqual(key.read_bytes(), self.key)
        self.assertEqual(key.stat().st_mode & 0o077, 0)
        backup_snapshot.validate_maintenance_secret(self.secret(), 'uter-maintenance', 'uter', home=destination)

    def test_restore_renames_secret_and_rejects_missing_or_malformed(self):
        self.enable()
        mapping = recover_kubernetes.resource_mapping(copy.deepcopy(self.values), 'new', maintenance_source='uter-maintenance')
        self.assertEqual(mapping['uter-maintenance'], 'new-maintenance')
        items = []
        for old in mapping:
            if old == 'uter-maintenance': items.append(self.secret()); continue
            kind = 'ConfigMap' if old.endswith(('policies', 'profiles')) else 'Secret'
            items.append({'kind': kind, 'metadata': {'name': old, 'namespace': 'uter'}, 'data': {}})
        for name in ('guardrail', 'redis'):
            items.append({'kind': 'PersistentVolumeClaim', 'metadata': {'name': 'uter-' + name},
                          'spec': {'resources': {'requests': {'storage': '1Gi'}}}})
        objects, _ = recover_kubernetes.prepare_objects(items, mapping, 'uter', 'new', maintenance_source='uter-maintenance', maintenance_home=self.home)
        restored = [x for x in objects if x['metadata']['name'] == 'new-maintenance']
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0]['data'], self.secret()['data'])
        self.assertEqual(restored[0]['metadata']['namespace'], 'new')
        with self.assertRaises(ValueError):
            recover_kubernetes.prepare_objects([x for x in items if x['metadata']['name'] != 'uter-maintenance'],
                                               mapping, 'uter', 'new', maintenance_source='uter-maintenance', maintenance_home=self.home)
        broken = copy.deepcopy(items)
        next(x for x in broken if x['metadata']['name'] == 'uter-maintenance')['data']['key'] = '!'
        with self.assertRaises(ValueError):
            recover_kubernetes.prepare_objects(broken, mapping, 'uter', 'new', maintenance_source='uter-maintenance', maintenance_home=self.home)
