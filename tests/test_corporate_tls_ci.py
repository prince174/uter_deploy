import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib import error

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from scripts import corporate_tls_ci as ci


class CorporateTLSCITests(unittest.TestCase):
    def test_generated_certificates_distinguish_ca_and_hostname(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = ci.create_certificates(Path(tmp), '172.17.0.1')
            root = x509.load_pem_x509_certificate(result['ca'].read_bytes())
            trusted = x509.load_pem_x509_certificate(result['trusted'][0].read_bytes())
            untrusted = x509.load_pem_x509_certificate(result['untrusted'][0].read_bytes())
            hostname = x509.load_pem_x509_certificate(result['hostname'][0].read_bytes())
            root.public_key().verify(trusted.signature, trusted.tbs_certificate_bytes,
                                     padding.PKCS1v15(), hashes.SHA256())
            root.public_key().verify(hostname.signature, hostname.tbs_certificate_bytes,
                                     padding.PKCS1v15(), hashes.SHA256())
            with self.assertRaises(InvalidSignature):
                root.public_key().verify(untrusted.signature, untrusted.tbs_certificate_bytes,
                                         padding.PKCS1v15(), hashes.SHA256())
            valid_names = trusted.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            wrong_names = hostname.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertEqual(str(valid_names.get_values_for_type(x509.IPAddress)[0]), '172.17.0.1')
            self.assertEqual(wrong_names.get_values_for_type(x509.IPAddress), [])
            self.assertEqual(wrong_names.get_values_for_type(x509.DNSName), ['wrong.invalid'])
            if os.name == 'posix':
                for filename in (result['ca'], result['trusted'][1], result['untrusted'][1], result['hostname'][1]):
                    self.assertEqual(filename.stat().st_mode & 0o077, 0)

    def test_public_or_ipv6_gateway_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for address in ('8.8.8.8', '::1', 'not-an-address'):
                with self.subTest(address=address), self.assertRaises(ValueError):
                    ci.create_certificates(Path(tmp), address)

    def test_refuses_local_execution_before_creating_any_resources(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}, clear=True):
            with self.assertRaisesRegex(ci.StageError, 'DISPOSABLE_GITHUB_HOSTED_RUNNER_REQUIRED'):
                ci.main()
        fixture = Path(__file__).resolve().parent/'fixtures/corporate_tls_upstream.py'
        env = dict(os.environ, GITHUB_ACTIONS='false')
        result = subprocess.run([sys.executable, str(fixture)], env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'GitHub-hosted', result.stderr)

    def test_guardrail_probe_uses_configured_ca_without_exposing_credentials(self):
        for backend, expected in [('compose', 'docker'), ('kubernetes', 'kubectl')]:
            with self.subTest(backend=backend), patch.object(ci, 'call', return_value=b'TRUSTED\n') as call:
                self.assertEqual(ci.tls_probe(backend, 'uter-tls-test', 'uter-tls-test-kind',
                                               '172.17.0.1', 1234, {}), 'TRUSTED')
                args, kwargs = call.call_args
                self.assertEqual(args[0][0], expected)
                self.assertIn(b'SSL_CERT_FILE', kwargs['input_data'])
                self.assertNotIn(b'UPSTREAM_API_KEY', kwargs['input_data'])
                self.assertNotIn(b'Authorization', kwargs['input_data'])

    def test_negative_readiness_requires_explicit_upstream_failure(self):
        class Opener:
            def __init__(self, data): self.data = data
            def open(self, *args, **kwargs):
                raise error.HTTPError('http://localhost', 503, 'fixture', {}, io.BytesIO(json.dumps(self.data).encode()))
        with patch.object(ci.request, 'build_opener', return_value=Opener({'ready': False, 'upstream': False})):
            ci.wait_uter(False)
        with patch.object(ci.request, 'build_opener', return_value=Opener({'ready': False, 'upstream': True})), \
             patch.object(ci.time, 'sleep'):
            with self.assertRaisesRegex(ci.StageError, 'UTER_DID_NOT_FAIL_CLOSED'):
                ci.wait_uter(False)

    def test_ci_workflow_uses_anonymous_signed_images_and_candidate_installer(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root/'.github/workflows/corporate-tls.yml').read_text(encoding='utf-8')
        self.assertIn('backend: [compose, kubernetes]', workflow)
        self.assertIn(ci.PUBLISHER_FINGERPRINT, workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertNotIn('secrets.', workflow)
        self.assertIn('driver/scripts/corporate_tls_ci.py', workflow)
        self.assertTrue(ci.NODE_IMAGE.endswith('@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0'))


if __name__ == '__main__':
    unittest.main()
