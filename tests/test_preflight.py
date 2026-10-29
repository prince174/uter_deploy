import argparse
import contextlib
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


spec = importlib.util.spec_from_file_location('preflight', Path(__file__).resolve().parents[1] / 'scripts/preflight.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, value, status=200, headers=None):
        raw = json.dumps(value).encode()
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.server.calls.append(('GET', self.path, self.headers.get('Authorization')))
        if self.server.redirect:
            return self.reply({'private': 'body-canary'}, status=302, headers={'Location': self.server.redirect})
        if self.server.health_status != 200:
            return self.reply({'private': 'body-canary'}, status=self.server.health_status)
        self.reply({'healthy_count': self.server.healthy_count})

    def do_POST(self):
        self.server.calls.append(('POST', self.path, self.headers.get('Authorization')))
        raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.server.last_payload = json.loads(raw)
        self.reply({'choices': [{'message': {'content': 'response-canary'}}]})


@contextlib.contextmanager
def server(cert=None, key=None):
    instance = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    instance.calls = []
    instance.healthy_count = 1
    instance.health_status = 200
    instance.redirect = None
    instance.last_payload = None
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        instance.socket = ctx.wrap_socket(instance.socket, server_side=True)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join()


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.key = self.path / 'secret'
        self.key.write_text('key-canary-123\n')
        if os.name == 'posix':
            self.key.chmod(0o600)

    def args(self, url):
        return argparse.Namespace(backend='compose', context=None, llm_url=url, llm_model='alias-canary',
                                  llm_key_file=self.key, health_url=None, ca_file=None,
                                  allow_http_llm=True, use_env_proxy=False, workdir=self.path, timeout=5)

    def test_actual_http_requests_use_alias_and_do_not_print_sensitive_values(self):
        with server() as s, patch.object(m, 'runtime_checks', return_value=[]):
            base = f'http://127.0.0.1:{s.server_port}/v1'
            result = m.preflight(self.args(base))
            self.assertEqual(result['result'], 'pass_with_unchecked_items')
            self.assertEqual(result['scope'], 'operator_host_only')
            self.assertEqual(result['container_or_pod_network_and_trust'], 'not_checked')
            self.assertEqual([c[:2] for c in s.calls], [('GET', '/health'), ('POST', '/v1/chat/completions')])
            self.assertTrue(all(c[2] == 'Bearer key-canary-123' for c in s.calls))
            self.assertEqual(s.last_payload['model'], 'alias-canary')
            self.assertEqual(s.last_payload['max_tokens'], 4)
            report = json.dumps(result)
            for secret in ('key-canary-123', 'alias-canary', 'response-canary'):
                self.assertNotIn(secret, report)

    def test_health_failure_does_not_hide_successful_completion(self):
        with server() as s:
            s.healthy_count = 0
            checks = m.probe_llm(f'http://127.0.0.1:{s.server_port}/v1',
                                 f'http://127.0.0.1:{s.server_port}/health', 'model', '', 5)
            self.assertEqual(checks[0]['code'], 'NO_HEALTHY_BACKENDS')
            self.assertEqual(checks[0]['status'], 'fail')
            self.assertEqual(checks[1]['status'], 'pass')

    def test_http_error_does_not_return_untrusted_body(self):
        with server() as s:
            s.health_status = 401
            checks = m.probe_llm(f'http://127.0.0.1:{s.server_port}/v1',
                                 f'http://127.0.0.1:{s.server_port}/health', 'model', 'secret-canary', 5)
            self.assertEqual(checks[0]['code'], 'HTTP_401')
            self.assertNotIn('body-canary', json.dumps(checks))
            self.assertNotIn('secret-canary', json.dumps(checks))

    def test_redirect_never_forwards_authorization_to_other_server(self):
        with server() as destination, server() as source:
            source.redirect = f'http://127.0.0.1:{destination.server_port}/leak'
            checks = m.probe_llm(f'http://127.0.0.1:{source.server_port}/v1',
                                 f'http://127.0.0.1:{source.server_port}/health', 'model', 'key-canary', 5)
            self.assertEqual(checks[0]['code'], 'REDIRECT_BLOCKED')
            self.assertEqual(destination.calls, [])

    def test_health_and_completion_must_have_same_origin(self):
        args = self.args('https://llm.example/v1')
        args.health_url = 'https://other.example/health'
        with self.assertRaisesRegex(m.CheckFailure, '^HEALTH_ORIGIN_MISMATCH$'):
            m.preflight(args)

    def test_rejects_http_without_explicit_opt_in_and_userinfo(self):
        with self.assertRaisesRegex(m.CheckFailure, '^HTTP_NOT_ALLOWED$'):
            m.check_url('http://localhost/v1')
        for value in ('https://user:pw@llm.example/v1', 'https://llm.example/v1?secret=value',
                      'https://llm.example:invalid/v1', 'https://llm.example/v1\nunsafe'):
            with self.subTest(value=value), self.assertRaises(m.CheckFailure):
                m.check_url(value)

    @unittest.skipUnless(os.name == 'posix', 'POSIX file permissions')
    def test_key_must_be_private_regular_file_and_no_symlink(self):
        self.key.chmod(0o644)
        with self.assertRaisesRegex(m.CheckFailure, '^KEY_FILE_PERMISSIONS$'):
            m.read_key(self.key)
        self.key.chmod(0o600)
        link = self.path / 'link'
        link.symlink_to(self.key)
        with self.assertRaisesRegex(m.CheckFailure, '^KEY_FILE_INVALID$'):
            m.read_key(link)
        self.key.write_text('a\nb')
        with self.assertRaisesRegex(m.CheckFailure, '^KEY_FILE_INVALID$'):
            m.read_key(self.key)
        self.key.write_text('sensitive-не-ascii', encoding='utf-8')
        with self.assertRaisesRegex(m.CheckFailure, '^KEY_FILE_INVALID$') as exc:
            m.read_key(self.key)
        self.assertNotIn('sensitive', str(exc.exception))

    def test_context_cannot_be_an_option(self):
        with patch.object(m.shutil, 'which', return_value='/usr/bin/tool'), patch.object(m, 'run_command') as run:
            checks = m.runtime_checks('kubernetes', '--dangerous-option')
        self.assertIn('EXPLICIT_CONTEXT_REQUIRED', [c['code'] for c in checks])
        run.assert_not_called()

    def test_old_compose_version_fails(self):
        def fake(args, timeout=15):
            if args[1:3] == ['compose', 'version']:
                return 0, 'v2.29.9'
            if args[1:3] == ['context', 'inspect']:
                return 0, json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}])
            return 0, ''
        with patch.object(m.shutil, 'which', return_value='/usr/bin/docker'), patch.object(m, 'run_command', side_effect=fake), patch.dict(os.environ, {}, clear=True):
            checks = m.runtime_checks('compose', None)
        self.assertIn('COMPOSE_VERSION_UNSUPPORTED', [c['code'] for c in checks])

    def test_private_ca_verifies_hostname_and_never_disables_verification(self):
        private = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'local test CA')])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                .sign(private, hashes.SHA256()))
        certfile, keyfile = self.path / 'cert.pem', self.path / 'key.pem'
        certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keyfile.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
        with server(str(certfile), str(keyfile)) as s:
            origin = f'https://127.0.0.1:{s.server_port}'
            untrusted = m.probe_llm(origin + '/v1', origin + '/health', 'model', 'key', 5)
            self.assertEqual(untrusted[0]['code'], 'TLS_FAILED')
            trusted = m.probe_llm(origin + '/v1', origin + '/health', 'model', 'key', 5, certfile)
            self.assertEqual(trusted[1]['status'], 'pass')
            wrong_host = f'https://localhost:{s.server_port}'
            mismatch = m.probe_llm(wrong_host + '/v1', wrong_host + '/health', 'model', 'key', 5, certfile)
            self.assertEqual(mismatch[0]['code'], 'TLS_FAILED')

    def test_remote_docker_context_never_contacts_daemon(self):
        calls = []
        def fake(args, timeout=15):
            calls.append(args)
            if args[1:3] == ['context', 'inspect']:
                return 0, json.dumps([{'Endpoints': {'docker': {'Host': 'tcp://remote:2376'}}}])
            return 0, ''
        with patch.object(m.shutil, 'which', return_value='/usr/bin/docker'), patch.object(m, 'run_command', side_effect=fake), patch.dict(os.environ, {}, clear=True):
            checks = m.runtime_checks('compose', None)
        self.assertEqual(checks[-1]['code'], 'LOCAL_DEFAULT_UNIX_CONTEXT_REQUIRED')
        self.assertFalse(any('info' in c for c in calls))

    def test_cli_configuration_errors_are_redacted(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = m.main(['--backend', 'compose', '--llm-url', 'https://user:secret-canary@llm.example/v1',
                             '--llm-model', 'model', '--llm-key-file', str(self.key)])
        self.assertEqual(status, 1)
        self.assertNotIn('secret-canary', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['checks'][0]['code'], 'URL_INVALID')


if __name__ == '__main__':
    unittest.main()
