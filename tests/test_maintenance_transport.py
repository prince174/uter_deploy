import json
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from scripts import maintenance_transport as transport


class TransportTests(unittest.TestCase):
    def test_real_child_is_bounded_and_reaped(self):
        self.assertEqual(transport._run([sys.executable, '-c', 'print("ok")']), b'ok\n')
        with self.assertRaises(ValueError):
            transport._run([sys.executable, '-c', 'print("x"*40000)'])
        with self.assertRaises(TimeoutError):
            transport._run([sys.executable, '-c', 'import time;time.sleep(5)'], timeout=.2)

    def test_compose_uses_exact_id_and_never_passes_credentials(self):
        output = json.dumps({'status': 202, 'body': '{"state":"draining"}'}).encode()
        with mock.patch.object(transport, '_run', return_value=output) as call:
            status, body = transport.request(service='agent', method='POST', container_id='a'*64,
                                             identity_guard=lambda: True)
        self.assertEqual((status, body), (202, b'{"state":"draining"}'))
        command = call.call_args.args[0]
        self.assertEqual(command[:4], ['/usr/bin/docker', '--context', 'default', 'exec'])
        self.assertEqual(command[4], 'a'*64)
        self.assertNotIn('X-Uter-Maintenance-Key:', ' '.join(command))

    def test_identity_change_or_unexpected_output_fails(self):
        states = iter([True, False])
        with mock.patch.object(transport, '_run', return_value=b'{"status":200,"body":"{}"}'):
            with self.assertRaises(transport.TransportError):
                transport.request(service='guardrail', method='GET', container_id='b'*64,
                                  identity_guard=lambda: next(states))
        for raw in (b'{"status":200,"status":200,"body":"{}"}', b'{"status":true,"body":"{}"}'):
            with mock.patch.object(transport, '_run', return_value=raw), self.assertRaises(transport.TransportError):
                transport.request(service='guardrail', method='GET', container_id='b'*64,
                                  identity_guard=lambda: True)

    def test_invalid_target_does_not_call_subprocess(self):
        with mock.patch.object(transport, '_run') as run, self.assertRaises(transport.TransportError):
            transport.request(service='guardrail', method='POST', container_id='--privileged', identity_guard=lambda: True)
        run.assert_not_called()

    def test_kubernetes_passes_only_pinned_descriptors_and_exact_pod(self):
        api = SimpleNamespace(binary_fd=9, context='pinned-context')
        inner = SimpleNamespace(api=api, config_fd=10)
        session = SimpleNamespace(site='uter-test', _executor=object(), _record={'schema': 2, 'kubectl_sha256': 'a'*64},
                                  config_sha256='b'*64, _inner=inner, _scope=lambda: None)
        result = b'{"status":200,"body":"{}"}'
        with mock.patch.object(transport, '_run', return_value=result) as run, \
             mock.patch.object(transport.kubernetes_trusted_kubectl, 'verify') as binary, \
             mock.patch.object(transport.kubernetes_sealed_config, 'verify_sealed') as config:
            self.assertEqual(transport.request(service='guardrail', method='GET', session=session,
                                               pod='uter-test-guardrail-abcd-xyz', identity_guard=lambda: True), (200, b'{}'))
        binary.assert_called_once_with(9, 'a'*64)
        config.assert_called_once_with(10, 'b'*64)
        self.assertEqual(run.call_args.kwargs['fds'], (9, 10))
        self.assertIn('pod/uter-test-guardrail-abcd-xyz', run.call_args.args[0])
        with mock.patch.object(transport, '_run') as run, self.assertRaises(transport.TransportError):
            transport.request(service='guardrail', method='GET', session=session,
                              pod='uter-test-agent-abcd-xyz', identity_guard=lambda: True)
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
