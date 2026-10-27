import argparse
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import bcrypt
import yaml

spec = importlib.util.spec_from_file_location('installer', Path(__file__).resolve().parents[1] / 'scripts/install.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ('policy', 'profiles'):
            (self.root / name).write_text('[test]\nenabled=true\n')
        (self.root / 'images').write_text(json.dumps({k: 'registry.example/' + k + '@sha256:' + 'a' * 64 for k in ('guardrail', 'agent', 'redis')}))
        self.args = argparse.Namespace(home=self.root / 'home', backend='compose', name='uter-test', context=None,
            images=self.root / 'images', policy=self.root / 'policy', profiles=self.root / 'profiles',
            llm_url='https://llm.example/v1', llm_model='test', allow_http_llm=False, port=18000,
            storage_class='', registry_config=None)

    def env(self, name):
        return dict(line.split('=', 1) for line in (self.args.home / 'runtime' / name).read_text().splitlines())

    def test_credentials_and_permissions(self):
        m.prepare(self.args, 'key$literal')
        g, a = self.env('guardrail.env'), self.env('agent.env')
        credentials = json.loads((self.args.home / 'credentials.json').read_text())
        for role in ('admin', 'user', 'service'):
            self.assertTrue(bcrypt.checkpw(credentials[role].encode(), g[role.upper() + '_PASSWORD_HASH'].encode()))
        self.assertEqual(g['UPSTREAM_API_KEY'], 'key$literal')
        self.assertEqual(g['AGENT_INTERNAL_SHARED_SECRET'], a['AGENT_INTERNAL_SHARED_SECRET'])
        self.assertEqual(credentials['service'], a['GUARDRAIL_SERVICE_PASSWORD'])
        self.assertIn((self.args.home / 'runtime/redis-password').read_text(), (self.args.home / 'runtime/redis.conf').read_text())
        if os.name == 'posix':
            self.assertEqual((self.args.home / 'credentials.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.args.home.stat().st_mode & 0o777, 0o700)

    def test_repeat_never_rotates(self):
        m.prepare(self.args, '')
        before = (self.args.home / 'credentials.json').read_bytes()
        with self.assertRaises(ValueError):
            m.prepare(self.args, '')
        self.assertEqual(before, (self.args.home / 'credentials.json').read_bytes())

    def test_bad_input_no_files(self):
        for key, value in [('llm_model', 'a\nJWT_SECRET=bad'), ('llm_url', 'https://user:pw@llm.example'),
                           ('llm_url', 'http://llm.example'), ('name', '../stand'), ('port', 0)]:
            old = getattr(self.args, key)
            setattr(self.args, key, value)
            with self.assertRaises(ValueError):
                m.prepare(self.args, '')
            self.assertFalse(self.args.home.exists())
            setattr(self.args, key, old)

    def test_mutable_images_rejected(self):
        self.args.images.write_text('{"guardrail":"latest"}')
        with self.assertRaises(ValueError):
            m.prepare(self.args, '')

    def test_kubernetes_consistency(self):
        self.args.backend, self.args.context = 'kubernetes', 'runtime-cluster'
        m.prepare(self.args, 'secret')
        values = yaml.safe_load((self.args.home / 'values.yaml').read_text())
        docs = list(yaml.safe_load_all((self.args.home / 'resources.yaml').read_text()))
        names = {d['metadata']['name'] for d in docs}
        for key in ('guardrailSecret', 'agentSecret', 'redisSecret', 'policyConfigMap', 'profileConfigMap'):
            self.assertIn(values[key], names)
        self.assertTrue(values['useEmbeddedModels'])
        self.assertEqual(values['guardrailEnv']['UPSTREAM_URL'], self.args.llm_url)
        self.assertTrue(all(d['metadata']['namespace'] == 'uter-test' for d in docs))
        with patch.object(m, 'run', return_value='') as run:
            m.check(self.args.home, json.loads((self.args.home / 'install.json').read_text()))
        self.assertEqual(len(run.call_args_list), 2)
        self.assertTrue(all('runtime-cluster' in c.args[0] for c in run.call_args_list))
        self.assertFalse(any('install' in c.args[0] for c in run.call_args_list))

    def test_kubernetes_requires_context(self):
        self.args.backend = 'kubernetes'
        with self.assertRaises(ValueError):
            m.prepare(self.args, '')

    def test_failure_output_redacted(self):
        import subprocess
        with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess(['helm'], 1, 'secret', 'secret')):
            with self.assertRaises(RuntimeError) as exc:
                m.run(['helm', 'template'])
        self.assertNotIn('secret', str(exc.exception).replace('secrets', ''))

    @unittest.skipUnless(os.name == 'posix', 'Linux install safety checks')
    def test_existing_namespace_not_modified(self):
        self.args.backend, self.args.context = 'kubernetes', 'test'
        m.prepare(self.args, '')
        cfg = json.loads((self.args.home / 'install.json').read_text())
        with patch.object(m, 'check'), patch.object(m, 'run', return_value='namespace/uter-test') as run:
            with self.assertRaises(ValueError):
                m.install(self.args.home, cfg)
        self.assertEqual(len(run.call_args_list), 1)
        self.assertFalse((self.args.home / 'install-state.json').exists())

    @unittest.skipUnless(os.name == 'posix', 'Linux install safety checks')
    def test_failed_install_stays_pending_no_retry(self):
        self.args.backend, self.args.context = 'kubernetes', 'test'
        m.prepare(self.args, '')
        cfg = json.loads((self.args.home / 'install.json').read_text())
        with patch.object(m, 'check'), patch.object(m, 'run', side_effect=['', '', '', '', RuntimeError('failure')]):
            with self.assertRaises(RuntimeError):
                m.install(self.args.home, cfg)
        self.assertEqual(json.loads((self.args.home / 'install-state.json').read_text())['status'], 'pending')
        with patch.object(m, 'run') as run:
            with self.assertRaises(ValueError):
                m.install(self.args.home, cfg)
        run.assert_not_called()

    def test_input_directory_cli_and_optional_judge(self):
        self.args.images.rename(self.root / 'images.json')
        self.args.policy.rename(self.root / 'policy.toml')
        self.args.profiles.rename(self.root / 'model_profiles.toml')
        (self.root / 'llm-key').write_text('')
        argv = ['install.py', 'prepare', '--home', str(self.args.home), '--inputs', str(self.root),
                '--llm-url', self.args.llm_url, '--llm-model', self.args.llm_model,
                '--llm-key-file', str(self.root / 'llm-key'), '--judge-url', 'http://judge:11434',
                '--judge-model', 'test-judge', '--guardrail-cpus', '2']
        with patch.object(m.sys, 'argv', argv):
            self.assertEqual(m.main(), 0)
        g = self.env('guardrail.env')
        self.assertEqual(g['JUDGE_ENABLED'], 'true')
        self.assertEqual(g['JUDGE_OLLAMA_URL'], 'http://judge:11434')
        self.assertEqual(g['JUDGE_FAIL_CLOSED'], 'true')
        cfg = json.loads((self.args.home / 'install.json').read_text())
        self.assertEqual(cfg['guardrail_cpus'], 2)
