import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import bcrypt
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

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

    def ca_certificate(self):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test Root CA')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        return cert.public_bytes(serialization.Encoding.PEM)

    def test_credentials_and_permissions(self):
        m.prepare(self.args, 'key$literal')
        g, a = self.env('guardrail.env'), self.env('agent.env')
        credentials = json.loads((self.args.home / 'credentials.json').read_text())
        for role in ('admin', 'user', 'service'):
            self.assertTrue(bcrypt.checkpw(credentials[role].encode(), g[role.upper() + '_PASSWORD_HASH'].encode()))
        self.assertEqual(g['UPSTREAM_API_KEY'], 'key$literal')
        self.assertEqual(g['AGENT_INTERNAL_SHARED_SECRET'], a['AGENT_INTERNAL_SHARED_SECRET'])
        self.assertEqual(credentials['service'], a['GUARDRAIL_SERVICE_PASSWORD'])
        self.assertNotIn('SSL_CERT_FILE', g)
        self.assertNotIn('SSL_CERT_DIR', g)
        self.assertNotIn('REQUESTS_CA_BUNDLE', g)
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

    def test_optional_llm_max_tokens_compose_and_kubernetes(self):
        for backend in ('compose', 'kubernetes'):
            for limit in (None, 64):
                with self.subTest(backend=backend, limit=limit):
                    self.args.home = self.root / (backend + str(limit))
                    self.args.backend = backend
                    self.args.context = 'test-context' if backend == 'kubernetes' else None
                    self.args.llm_max_tokens = limit
                    m.prepare(self.args, 'key')
                    env = self.env('guardrail.env')
                    if limit is None:
                        self.assertNotIn('UPSTREAM_OPENAI_MAX_TOKENS', env)
                    else:
                        self.assertEqual(env['UPSTREAM_OPENAI_MAX_TOKENS'], '64')
                    if backend == 'kubernetes':
                        resources = list(yaml.safe_load_all((self.args.home/'resources.yaml').read_text()))
                        secret = next(x for x in resources if x['kind'] == 'Secret' and x['metadata']['name'] == 'uter-test-guardrail-env')
                        values = yaml.safe_load((self.args.home/'values.yaml').read_text())
                        self.assertEqual(secret['stringData'].get('UPSTREAM_OPENAI_MAX_TOKENS'), None if limit is None else '64')
                        self.assertNotIn('UPSTREAM_OPENAI_MAX_TOKENS', values['guardrailEnv'])

    def test_invalid_llm_max_tokens_creates_no_installation(self):
        for value in (0, -1, 65537, True, 2.5, '64'):
            with self.subTest(value=value):
                self.args.llm_max_tokens = value
                with self.assertRaisesRegex(ValueError, 'LLM max tokens'):
                    m.prepare(self.args, '')
                self.assertFalse(self.args.home.exists())

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
    def test_install_refuses_finalize_anchor_before_inspection_or_mutation(self):
        self.args.home.mkdir()
        for name in ('compose-fence-finalize-anchor.json','compose-fenced-update-intent.json',
                     'compose-fenced-target-start.json','compose-fenced-target-result.json'):
            anchor=self.args.home/name;anchor.symlink_to(self.args.home/'missing')
            with patch.object(m,'check') as check,patch.object(m,'run') as run:
                with self.assertRaisesRegex(ValueError,'^REDIS_FENCE_REQUIRES_INSPECTION$'):
                    m.install(self.args.home,{})
            check.assert_not_called();run.assert_not_called();self.assertTrue(anchor.is_symlink());anchor.unlink()

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
                '--judge-model', 'test-judge', '--guardrail-cpus', '2', '--llm-max-tokens', '64']
        with patch.object(m.sys, 'argv', argv):
            self.assertEqual(m.main(), 0)
        g = self.env('guardrail.env')
        self.assertEqual(g['UPSTREAM_OPENAI_MAX_TOKENS'], '64')
        self.assertEqual(g['JUDGE_ENABLED'], 'true')
        self.assertEqual(g['JUDGE_OLLAMA_URL'], 'http://judge:11434')
        self.assertEqual(g['JUDGE_FAIL_CLOSED'], 'true')
        cfg = json.loads((self.args.home / 'install.json').read_text())
        self.assertEqual(cfg['guardrail_cpus'], 2)

    def test_compose_ca_is_private_and_mounted_through_existing_policies(self):
        pem = self.ca_certificate()
        source = self.root / 'corporate-ca.pem'
        source.write_bytes(pem)
        self.args.llm_ca_bundle = source
        m.prepare(self.args, 'fixture-key')
        env = self.env('guardrail.env')
        self.assertEqual(env['SSL_CERT_FILE'], '/app/policies/upstream-ca.pem')
        self.assertEqual(env['SSL_CERT_DIR'], '/app/policies')
        self.assertEqual(env['REQUESTS_CA_BUNDLE'], env['SSL_CERT_FILE'])
        ca = self.args.home / 'runtime/policies/upstream-ca.pem'
        self.assertEqual(ca.read_bytes(), pem)
        if os.name == 'posix':
            self.assertEqual(ca.stat().st_mode & 0o777, 0o600)
        compose = yaml.safe_load((self.args.home / 'compose/compose.yaml').read_text())
        self.assertIn('${RUNTIME_DIR:?}/policies:/app/policies:ro',
                      compose['services']['guardrail']['volumes'])

    def test_cli_accepts_optional_ca_bundle(self):
        self.args.images.rename(self.root / 'images.json')
        self.args.policy.rename(self.root / 'policy.toml')
        self.args.profiles.rename(self.root / 'model_profiles.toml')
        source = self.root / 'corporate-ca.pem'
        source.write_bytes(self.ca_certificate())
        keyfile = self.root / 'llm-key'
        keyfile.write_text('fixture-key')
        argv = ['install.py', 'prepare', '--home', str(self.args.home), '--inputs', str(self.root),
                '--llm-url', self.args.llm_url, '--llm-model', self.args.llm_model,
                '--llm-key-file', str(keyfile), '--llm-ca-bundle', str(source)]
        with patch.object(m.sys, 'argv', argv):
            self.assertEqual(m.main(), 0)
        self.assertEqual(self.env('guardrail.env')['SSL_CERT_FILE'], '/app/policies/upstream-ca.pem')

    def test_kubernetes_ca_uses_existing_backed_up_policy_configmap(self):
        pem = self.ca_certificate()
        source = self.root / 'corporate-ca.pem'
        source.write_bytes(pem)
        self.args.backend, self.args.context, self.args.llm_ca_bundle = 'kubernetes', 'test', source
        m.prepare(self.args, 'fixture-key')
        resources = list(yaml.safe_load_all((self.args.home / 'resources.yaml').read_text()))
        policy = next(x for x in resources if x['kind'] == 'ConfigMap'
                      and x['metadata']['name'] == 'uter-test-policies')
        guard = next(x for x in resources if x['kind'] == 'Secret'
                     and x['metadata']['name'] == 'uter-test-guardrail-env')
        self.assertEqual(policy['data']['upstream-ca.pem'].encode(), pem)
        self.assertEqual(guard['stringData']['SSL_CERT_FILE'], '/app/policies/upstream-ca.pem')
        self.assertEqual(guard['stringData']['SSL_CERT_DIR'], '/app/policies')
        self.assertEqual(guard['stringData']['REQUESTS_CA_BUNDLE'], '/app/policies/upstream-ca.pem')
        self.assertEqual({x['metadata']['name'] for x in resources},
                         {'uter-test-guardrail-env', 'uter-test-agent-env', 'uter-test-redis-secret',
                          'uter-test-policies', 'uter-test-profiles'})

    def test_ca_rejects_private_keys_invalid_data_and_http_before_creating_home(self):
        source = self.root / 'corporate-ca.pem'
        self.args.llm_ca_bundle = source
        for bad in (b'', b'not a certificate', self.ca_certificate() + b'\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n',
                    b'-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n', b'x' * (m.CA_LIMIT + 1)):
            with self.subTest(size=len(bad)):
                source.write_bytes(bad)
                with self.assertRaises(ValueError):
                    m.prepare(self.args, 'fixture-key')
                self.assertFalse(self.args.home.exists())
        source.write_bytes(self.ca_certificate())
        self.args.llm_url = 'http://llm.example/v1'
        self.args.allow_http_llm = True
        with self.assertRaisesRegex(ValueError, 'requires an HTTPS'):
            m.prepare(self.args, 'fixture-key')
        self.assertFalse(self.args.home.exists())

    def test_kubernetes_rejects_oversized_combined_policy_and_ca(self):
        pem = self.ca_certificate()
        source = self.root / 'corporate-ca.pem'
        source.write_bytes(pem * (m.CA_LIMIT // len(pem)))
        self.args.backend, self.args.context, self.args.llm_ca_bundle = 'kubernetes', 'test', source
        self.args.policy.write_text('[test]\nvalue = "' + 'x' * 20000 + '"\n')
        with self.assertRaisesRegex(ValueError, 'ConfigMap size limit'):
            m.prepare(self.args, 'fixture-key')
        self.assertFalse(self.args.home.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX FIFO and symlink semantics')
    def test_ca_input_rejects_fifo_and_symlink_without_blocking(self):
        source = self.root / 'ca-input'
        os.mkfifo(source)
        self.args.llm_ca_bundle = source
        with self.assertRaisesRegex(ValueError, 'regular file'):
            m.prepare(self.args, 'fixture-key')
        self.assertFalse(self.args.home.exists())
        source.unlink()
        real = self.root / 'real-ca.pem'
        real.write_bytes(self.ca_certificate())
        source.symlink_to(real)
        with self.assertRaises(OSError):
            m.prepare(self.args, 'fixture-key')
        self.assertFalse(self.args.home.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX trust checks')
    def test_ca_rejects_untrusted_ancestors_hardlinks_and_writable_file_before_prepare(self):
        pem = self.ca_certificate()
        source = self.root / 'ca.pem'; source.write_bytes(pem); source.chmod(0o644)
        self.assertEqual(m.read_ca_bundle(source), pem.decode())
        parse_certificates = m.x509.load_pem_x509_certificates
        def replace_after_read(data):
            source.write_bytes(b'changed after read')
            return parse_certificates(data)
        with patch.object(m.x509, 'load_pem_x509_certificates', side_effect=replace_after_read):
            self.assertEqual(m.read_ca_bundle(source), pem.decode())
        source.write_bytes(pem)
        shared = self.root / 'shared'; shared.mkdir(); shared.chmod(0o777)
        bad = shared / 'ca.pem'; bad.write_bytes(pem)
        link = self.root / 'link'; link.symlink_to(self.root, target_is_directory=True)
        hard = self.root / 'hard'; os.link(source, hard)
        fifo = self.root / 'fifo'; os.mkfifo(fifo)
        for candidate in (bad, link / 'ca.pem', hard, fifo):
            with self.subTest(candidate=candidate):
                self.args.llm_ca_bundle = candidate
                with self.assertRaises((ValueError, OSError)):
                    m.prepare(self.args, 'fixture-key')
                self.assertFalse(self.args.home.exists())
        hard.unlink();source.chmod(0o666);self.args.llm_ca_bundle = source
        with self.assertRaises(ValueError):
            m.prepare(self.args, 'fixture-key')
        self.assertFalse(self.args.home.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX file descriptor permissions')
    def test_ca_permissions_apply_only_to_regular_optional_file(self):
        m.prepare_ca_permissions(self.root)  # Legacy installations have no CA file.
        ca = self.root / 'policies' / m.CA_FILE
        ca.parent.mkdir()
        ca.write_bytes(self.ca_certificate())
        with patch.object(m.os, 'fchown') as chown, patch.object(m.os, 'fchmod') as chmod:
            m.prepare_ca_permissions(self.root)
        self.assertEqual(chown.call_args.args[1:], (10001, 10001))
        self.assertEqual(chmod.call_args.args[1:], (0o400,))
        ca.unlink()
        ca.symlink_to(self.root / 'missing-target')
        with self.assertRaises(OSError):
            m.prepare_ca_permissions(self.root)
        ca.unlink()
        other = self.root / 'other-ca'
        other.write_bytes(self.ca_certificate())
        os.link(other, ca)
        with patch.object(m.os, 'fchown') as chown, self.assertRaisesRegex(ValueError, 'hard links'):
            m.prepare_ca_permissions(self.root)
        chown.assert_not_called()
