import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('offline_installer', Path(__file__).resolve().parents[1] / 'scripts/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


@unittest.skipUnless(os.name == 'posix', 'POSIX offline installation')
class OfflineInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        for name in ('policies', 'profiles', 'models'):
            (self.home / 'runtime' / name).mkdir(parents=True)
        self.images = {name: 'registry.example/' + name + '@sha256:' + 'a' * 64
                       for name in ('guardrail', 'agent', 'redis')}
        self.cfg = {'backend': 'compose', 'context': 'default', 'name': 'uter-test',
                    'images': self.images, 'port': 18000}
        self.calls = []

    def run_command(self, command, env=None):
        self.calls.append(command)
        if command[:3] == ['docker', 'context', 'inspect']:
            return json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}])
        if command[:5] == ['docker', '--context', 'default', 'image', 'inspect']:
            return json.dumps([{'RepoDigests': [command[-1]]}])
        return ''

    def execute(self, cfg=None):
        with patch.object(installer, 'check'), patch.object(installer, 'run', side_effect=self.run_command), \
             patch.object(installer.os, 'geteuid', return_value=0), patch.object(installer.os, 'chown'), \
             patch.object(installer.os, 'chmod'), patch.object(installer, 'prepare_ca_permissions'), \
             patch.dict(os.environ, {'DOCKER_HOST': ''}):
            installer.install(self.home, cfg or self.cfg, offline=True)

    def test_verified_local_images_start_without_pull(self):
        self.execute()
        inspections = [c for c in self.calls if c[:5] == ['docker', '--context', 'default', 'image', 'inspect']]
        self.assertEqual({c[-1] for c in inspections}, set(self.images.values()))
        self.assertFalse(any(c[-1:] == ['pull'] for c in self.calls))
        startup = next(c for c in self.calls if 'up' in c)
        self.assertIn('--pull', startup)
        self.assertEqual(startup[startup.index('--pull') + 1], 'never')
        self.assertEqual(json.loads((self.home / 'install-state.json').read_text())['status'], 'ready')

    def test_missing_or_wrong_local_digest_stops_before_writes(self):
        original = self.run_command
        def wrong(command, env=None):
            if command[:5] == ['docker', '--context', 'default', 'image', 'inspect']:
                return json.dumps([{'RepoDigests': ['registry.example/other@sha256:' + 'b' * 64]}])
            return original(command, env)
        self.run_command = wrong
        with self.assertRaisesRegex(ValueError, 'not verified locally'):
            self.execute()
        self.assertFalse((self.home / 'install-state.json').exists())

    def test_containerd_descriptor_representation(self):
        original = self.run_command
        def descriptor(command, env=None):
            if command[:5] == ['docker', '--context', 'default', 'image', 'inspect']:
                digest = command[-1].split('@', 1)[1]
                return json.dumps([{'Id': digest, 'Descriptor': {'digest': digest}}])
            return original(command, env)
        self.run_command = descriptor
        self.execute()

    def test_kubernetes_offline_is_rejected_before_any_commands(self):
        cfg = dict(self.cfg, backend='kubernetes', context='fixture')
        with self.assertRaisesRegex(ValueError, 'Compose only'):
            self.execute(cfg)
        self.assertEqual(self.calls, [])
        self.assertFalse((self.home / 'install-state.json').exists())

    def test_invalid_image_is_rejected(self):
        self.cfg['images']['agent'] = 'registry.example/agent:latest'
        with self.assertRaisesRegex(ValueError, 'immutable'):
            self.execute()
        self.assertFalse((self.home / 'install-state.json').exists())

    def test_missing_or_extra_role_stops_before_check_or_runtime_commands(self):
        for images in ({k: v for k, v in self.images.items() if k != 'redis'},
                       dict(self.images, foreign='registry.example/foreign@sha256:' + 'a' * 64)):
            with self.subTest(images=images), patch.object(installer, 'check') as check, \
                 patch.dict(os.environ, {'REDIS_IMAGE': 'attacker:latest'}):
                with self.assertRaisesRegex(ValueError, 'exactly guardrail'):
                    installer.install(self.home, dict(self.cfg, images=images), offline=True)
                check.assert_not_called()
                self.assertEqual(self.calls, [])
                self.assertFalse((self.home / 'install-state.json').exists())

    def test_unlabelled_reserved_resources_never_reused(self):
        for offline in (False, True):
            for kind, name in (('volume', 'uter-test_redis-data'),
                               ('volume', 'uter-test_audit-data'),
                               ('network', 'uter-test_backend'),
                               ('network', 'uter-test_outbound'),
                               ('container', 'uter-test-guardrail-1')):
                def existing(command, env=None):
                    if command[3:5] == [kind, 'ls'] and '--format' in command:
                        return name + '\n'
                    return self.run_command(command, env)
                with self.subTest(offline=offline, kind=kind, name=name), \
                     patch.object(installer, 'check'), patch.object(installer, 'run', side_effect=existing), \
                     patch.object(installer.os, 'geteuid', return_value=0), \
                     patch.object(installer.os, 'chown') as chown, \
                     patch.object(installer.os, 'chmod') as chmod, \
                     patch.dict(os.environ, {'DOCKER_HOST': ''}):
                    with self.assertRaisesRegex(ValueError, f'Compose {kind} name already exists'):
                        installer.install(self.home, self.cfg, offline=offline)
                    chown.assert_not_called()
                    chmod.assert_not_called()
                    self.assertFalse((self.home / 'install-state.json').exists())


if __name__ == '__main__':
    unittest.main()
