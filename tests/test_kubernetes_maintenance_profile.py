import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import bundle, kubernetes_maintenance_profile as profile
import uterctl

ROOT = Path(__file__).resolve().parents[1]
HELM = os.environ.get('UTER_TEST_HELM') or shutil.which('helm')


@unittest.skipUnless(os.name == 'posix', 'private file checks require POSIX')
class MaintenanceProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name); (self.home / 'runtime').mkdir()
        self.key = b'k' * 64
        key = self.home / 'runtime/maintenance-key'; key.write_bytes(self.key); key.chmod(0o600)
        (self.home / 'install.json').write_text(json.dumps({'maintenance_enabled': True}))
        self.site = {'name': 'uter', 'namespace': 'uter'}
        images = {s: f'ghcr.io/example/{s}@sha256:' + 'a' * 64 for s in ('guardrail', 'agent', 'redis')}
        self.manifest = {'maintenance_protocol': {'version': 1, 'services': ['agent', 'guardrail']}, 'images': images}
        self.values = {'maintenanceEnabled': True, 'maintenanceSecret': 'uter-maintenance', 'images': copy.deepcopy(images),
                       'guardrailSecret': 'uter-guardrail-env', 'agentSecret': 'uter-agent-env',
                       'redisSecret': 'uter-redis-secret', 'guardrailEnv': {}, 'agentEnv': {}}
        def secret(name, entries):
            return {'kind': 'Secret', 'type': 'Opaque', 'metadata': {'name': name, 'namespace': 'uter'},
                    'data': {k: base64.b64encode(v).decode() for k, v in entries.items()}}
        self.maintenance = secret('uter-maintenance', {'key': self.key})
        self.services = {'guardrailSecret': secret('uter-guardrail-env', {'JWT_SECRET': b'j' * 64, 'AUDIT_LOG_HMAC_KEY': b'a' * 64}),
                         'agentSecret': secret('uter-agent-env', {'AGENT_INTERNAL_SHARED_SECRET': b'i' * 64}),
                         'redisSecret': secret('uter-redis-secret', {'password': b'r' * 64})}

    def validate(self):
        with patch.object(profile.maintenance_protocol, 'verify_capability', return_value=self.manifest) as verify, \
             patch.object(profile, '_verify_signed_chart'):
            result = profile.validate('/bundle', '/publisher', self.home, self.site, self.values, self.maintenance, self.services)
            verify.assert_called_once_with('/bundle', '/publisher')
            return result

    def test_verified_profile_allows_nexus_remap_without_authorizing_backup(self):
        self.values['images']['guardrail'] = 'nexus.example.local/repo/guardrail@sha256:' + 'a' * 64
        self.assertEqual(self.validate(), {'candidate_profile_valid': True, 'process_count_verified': False,
                                           'safe_to_backup': False, 'safe_to_update': False, 'safe_to_restore': False})

    def test_wrong_digest_reserved_env_unsafe_secret_and_reused_credentials_fail(self):
        for case in ('digest', 'env', 'identity', 'reused', 'missing', 'disabled', 'stringData', 'type'):
            self.setUp()
            if case == 'digest': self.values['images']['agent'] = 'repo/agent@sha256:' + 'b' * 64
            if case == 'env': self.values['agentEnv']['WEB_CONCURRENCY'] = '2'
            if case == 'identity': self.maintenance['metadata']['namespace'] = 'other'
            if case == 'reused': self.services['redisSecret']['data']['password'] = base64.b64encode(self.key).decode()
            if case == 'missing': self.services['guardrailSecret']['data'].pop('JWT_SECRET')
            if case == 'disabled': self.values['maintenanceEnabled'] = False
            if case == 'stringData': self.services['redisSecret']['stringData'] = {'password': self.key.decode()}
            if case == 'type': self.services['redisSecret']['type'] = 'kubernetes.io/tls'
            with self.subTest(case=case), self.assertRaisesRegex(ValueError, 'KUBERNETES_MAINTENANCE_PROFILE_UNVERIFIED'):
                self.validate()

    def test_signed_capability_failure_is_fatal(self):
        with patch.object(profile.maintenance_protocol, 'verify_capability', side_effect=ValueError('hidden')):
            with self.assertRaisesRegex(ValueError, '^KUBERNETES_MAINTENANCE_PROFILE_UNVERIFIED$'):
                profile.validate('/bundle', '/pub', self.home, self.site, self.values, self.maintenance, self.services)

    def test_authenticates_real_signed_bundle_and_rejects_chart_tampering(self):
        key = Ed25519PrivateKey.generate()
        private = self.home / 'private.pem'; public = self.home / 'public.pem'
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                         serialization.PublicFormat.SubjectPublicKeyInfo))
        manifest = dict(self.manifest, schema=1, config_schema=1, tooling_schema=1, status='released',
                        version='1.0.0', source_commit='a' * 40, data_epoch=1, upgrade_from=[])
        source = self.home / 'manifest.json'; source.write_text(json.dumps(manifest))
        legacy = dict(manifest); legacy.pop('maintenance_protocol')
        source.write_text(json.dumps(legacy))
        legacy_bundle = self.home / 'legacy-bundle'; bundle.build(source, legacy_bundle, private)
        with self.assertRaisesRegex(ValueError, '^KUBERNETES_MAINTENANCE_PROFILE_UNVERIFIED$'):
            profile.validate(legacy_bundle, public, self.home, self.site, self.values, self.maintenance, self.services)
        source.write_text(json.dumps(manifest))
        signed = self.home / 'bundle'; bundle.build(source, signed, private)
        (signed / 'charts').chmod(0o755)
        (signed / 'charts/uter').chmod(0o755)
        for path in (signed / 'charts/uter').rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
        authenticated = profile.maintenance_protocol.verify_capability(signed, public)
        profile._verify_signed_chart(signed, public, authenticated)
        result = profile.validate(signed, public, self.home, self.site, self.values, self.maintenance, self.services)
        self.assertTrue(result['candidate_profile_valid'])
        self.assertFalse(result['process_count_verified'])
        chart = signed / 'charts/uter/templates/workloads.yaml'
        original = chart.read_bytes()
        chart.write_bytes(original + b'\n# modified\n')
        with self.assertRaisesRegex(ValueError, '^KUBERNETES_MAINTENANCE_PROFILE_UNVERIFIED$'):
            profile.validate(signed, public, self.home, self.site, self.values, self.maintenance, self.services)
        # Even a valid signature on a different chart is not the reviewed profile.
        inventory = json.dumps(uterctl.inventory(signed), sort_keys=True, indent=2).encode()
        (signed / 'checksums.json').write_bytes(inventory)
        (signed / 'checksums.sig').write_bytes(base64.b64encode(key.sign(inventory)))
        profile.maintenance_protocol.verify_capability(signed, public)
        with self.assertRaisesRegex(ValueError, '^KUBERNETES_MAINTENANCE_PROFILE_UNVERIFIED$'):
            profile.validate(signed, public, self.home, self.site, self.values, self.maintenance, self.services)
        # Restore reviewed bytes after capability verification: authenticated
        # inventory still binds the other bytes and prevents this ABA mismatch.
        chart.write_bytes(original)
        with patch.object(profile.maintenance_protocol, 'verify_capability', return_value=authenticated):
            with self.assertRaisesRegex(ValueError, '^KUBERNETES_MAINTENANCE_PROFILE_UNVERIFIED$'):
                profile.validate(signed, public, self.home, self.site, self.values, self.maintenance, self.services)


@unittest.skipUnless(HELM, 'Helm executable not provided')
class HelmMaintenanceProfileTests(unittest.TestCase):
    def render(self, extra):
        base = {'images': {s: f'registry.example/{s}@sha256:' + 'a' * 64 for s in ('guardrail', 'agent', 'redis')},
                'guardrailSecret': 'uter-guardrail-env', 'agentSecret': 'uter-agent-env', 'redisSecret': 'uter-redis-secret',
                'policyConfigMap': 'uter-policies', 'profileConfigMap': 'uter-profiles', 'useEmbeddedModels': True}
        base.update(extra)
        with tempfile.TemporaryDirectory() as directory:
            values = Path(directory) / 'values.yaml'; values.write_text(yaml.safe_dump(base))
            result = subprocess.run([HELM, 'template', 'uter', str(ROOT / 'charts/uter'), '-f', str(values)],
                                    capture_output=True, text=True, timeout=30)
        return result

    def test_default_and_explicit_off_match_and_have_no_maintenance_mounts(self):
        default = self.render({}); off = self.render({'maintenanceEnabled': False})
        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertEqual(default.stdout, off.stdout)
        self.assertNotIn('uter-maintenance', default.stdout)

    def test_profile_mounts_read_only_for_both_services_only_and_one_worker(self):
        result = self.render({'maintenanceEnabled': True, 'maintenanceSecret': 'uter-maintenance'})
        self.assertEqual(result.returncode, 0, result.stderr)
        deployments = {x['metadata']['name']: x for x in yaml.safe_load_all(result.stdout)
                       if isinstance(x, dict) and x.get('kind') == 'Deployment'}
        for name in ('guardrail', 'agent', 'redis'):
            spec = deployments['uter-' + name]['spec']['template']['spec']
            container = spec['containers'][0]
            mounts = [x for x in container['volumeMounts'] if x['name'] == 'maintenance']
            volumes = [x for x in spec['volumes'] if x['name'] == 'maintenance']
            if name == 'redis': self.assertFalse(mounts or volumes); continue
            self.assertEqual(mounts, [{'name': 'maintenance', 'mountPath': '/run/secrets/uter-maintenance', 'readOnly': True}])
            self.assertEqual(volumes[0]['secret']['defaultMode'], 0o440)
            self.assertEqual(volumes[0]['secret']['secretName'], 'uter-maintenance')
            self.assertIs(volumes[0]['secret']['optional'], False)
            self.assertEqual(spec['securityContext']['fsGroup'], 10001)
            env = {x['name']: x.get('value') for x in container['env']}
            self.assertEqual(env['WEB_CONCURRENCY'], '1')
            self.assertEqual(env['UTER_MAINTENANCE_ENABLED'], 'true')
            self.assertEqual(env['UTER_MAINTENANCE_KEY_FILE'], '/run/secrets/uter-maintenance/key')

    def test_template_rejects_bad_flags_secret_alias_and_reserved_env(self):
        for extra in ({'maintenanceEnabled': 'true'}, {'maintenanceEnabled': True},
                      {'maintenanceEnabled': True, 'maintenanceSecret': 'uter-guardrail-env'},
                      {'maintenanceEnabled': True, 'maintenanceSecret': 'uter-maintenance', 'agentEnv': {'WEB_CONCURRENCY': '2'}},
                      {'maintenanceEnabled': False, 'maintenanceSecret': 'uter-maintenance'},
                      {'maintenanceEnabled': False, 'guardrailEnv': {'UTER_MAINTENANCE_ENABLED': 'true'}}):
            with self.subTest(extra=extra): self.assertNotEqual(self.render(extra).returncode, 0)
