import contextlib
import io
import json
import socket
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError, URLError

from scripts import install_wizard, smoke_http


def response(data):
    return io.BytesIO(json.dumps(data).encode())


READY = {}
AUTH = {'access_token': 'token-canary'}
HEALTH = {'upstream_available': True, 'agent_runtime_available': True,
          'toxicity_guard': {'available': True}}
CHAT = {'blocked': False}


class SmokeDiagnosticsTests(unittest.TestCase):
    def check_failure(self, outcomes, expected):
        reports = []
        for outcome in outcomes:
            if isinstance(outcome, HTTPError): self.addCleanup(outcome.close)
        with mock.patch('urllib.request.urlopen', side_effect=outcomes):
            with self.assertRaises(Exception):
                smoke_http.check('http://127.0.0.1:1', 'admin', 'secret-canary',
                                 diagnostic=lambda stage, category: reports.append((stage, category)))
        self.assertEqual(reports, [expected])
        self.assertNotIn('canary', repr(reports))

    def test_success_preserves_checks_and_emits_no_failure(self):
        reports = []
        with mock.patch('urllib.request.urlopen', side_effect=[response(x) for x in (READY, AUTH, HEALTH, CHAT)]) as request:
            result = smoke_http.check('http://127.0.0.1:1', 'admin', 'secret-canary',
                                      diagnostic=lambda *args: reports.append(args))
        self.assertEqual(result['chat'], 'pass')
        self.assertEqual(request.call_count, 4)
        self.assertEqual(reports, [])

    def test_stage_and_failure_categories(self):
        cases = [
            ([socket.timeout('secret-canary')], ('READY', 'TIMEOUT')),
            ([response(READY), URLError(socket.timeout('secret-canary'))], ('AUTH', 'TIMEOUT')),
            ([response(READY), response(AUTH), URLError('secret-canary')], ('HEALTH', 'NETWORK_FAILED')),
            ([response(READY), response(AUTH), response(HEALTH),
              HTTPError('secret-canary', 503, 'secret-canary', {}, None)], ('CHAT', 'HTTP_503')),
            ([response(READY), response(AUTH), response(HEALTH),
              HTTPError('secret-canary', 599, 'secret-canary', {}, None)], ('CHAT', 'HTTP_OTHER')),
            ([response(READY), response({})], ('AUTH', 'INVALID_RESPONSE')),
            ([io.BytesIO(b'{"secret-canary"')], ('READY', 'INVALID_RESPONSE')),
            ([response(READY), response(AUTH), response({**HEALTH, 'upstream_available': False})], ('HEALTH', 'NOT_READY')),
            ([response(READY), response(AUTH), response(HEALTH), response({'blocked': True})], ('CHAT', 'BLOCKED_OR_INVALID')),
            ([response(READY), response(AUTH), response(HEALTH), response({})], ('CHAT', 'BLOCKED_OR_INVALID')),
            ([response(READY), response(AUTH), response(HEALTH), ValueError('secret-canary')], ('CHAT', 'FAILED')),
        ]
        for outcomes, expected in cases:
            with self.subTest(expected=expected): self.check_failure(outcomes, expected)

    def test_wizard_reports_original_stage_without_secret_or_response(self):
        output = io.StringIO()
        outcomes = [response(READY), response(AUTH), response(HEALTH),
                    HTTPError('http://secret-canary', 503, 'secret-canary', {}, None)]
        with mock.patch.object(install_wizard.workload_preflight, 'read_trusted_file',
                               return_value=b'{"admin":"secret-canary"}'), \
             mock.patch('urllib.request.urlopen', side_effect=outcomes), \
             contextlib.redirect_stderr(output):
            with self.assertRaisesRegex(install_wizard.WizardError, 'ACCEPTANCE_FAILED'):
                install_wizard.smoke(Path(__file__).resolve().parents[1], Path('unused'), 18000)
        self.assertEqual(output.getvalue(), 'ACCEPTANCE_DIAGNOSTIC=CHAT_HTTP_503\n')
        self.assertNotIn('canary', output.getvalue())


if __name__ == '__main__':
    unittest.main()
