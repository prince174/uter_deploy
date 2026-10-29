import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import adopt_installation as m, install_recovery


class AdoptionMetadataTests(unittest.TestCase):
    def setUp(self):
        self.ref = 'registry.example/guardrail@sha256:' + 'a' * 64
        self.digest = 'sha256:' + 'a' * 64
        self.config_id = 'sha256:' + 'b' * 64
        self.manifest = {'images': {'guardrail': self.ref}, 'image_config_ids': {'guardrail': self.config_id}}
        self.cfg = {'backend': 'kubernetes', 'context': 'cluster-test', 'name': 'uter-test'}
        self.pod = 'uter-test-guardrail-abc'
        self.image_id = 'containerd://registry.example/guardrail@' + self.digest
        self.ready = 'true'
        self.calls = []

    def kube_output(self, command, env=None):
        self.calls.append(command)
        idx = command.index('get')
        kind = command[idx + 1]
        expression = command[command.index('-o') + 1]
        if kind == 'deployment':
            return self.ref.encode()
        if kind == 'pods':
            return (self.pod + '\n').encode()
        if kind != 'pod':
            raise AssertionError('Unexpected query')
        if 'deletionTimestamp' in expression:
            return b''
        if 'containers[0].image' in expression:
            return self.ref.encode()
        if '.ready' in expression:
            return self.ready.encode()
        if '.imageID' in expression:
            return self.image_id.encode()
        raise AssertionError('Unexpected metadata expression')

    def test_kubernetes_queries_only_relevant_fields_and_enforces_digest(self):
        with patch.object(m, 'output', side_effect=self.kube_output):
            m.verify_live(Path('.'), self.cfg, self.manifest)
            self.image_id = 'containerd://registry.example/guardrail@sha256:' + 'c' * 64
            with self.assertRaisesRegex(ValueError, 'Expected one ready'):
                m.verify_live(Path('.'), self.cfg, self.manifest)
        self.assertTrue(self.calls)
        for command in self.calls:
            self.assertIn('-o', command)
            self.assertTrue(command[command.index('-o') + 1].startswith('jsonpath='))
            self.assertNotIn('env', ' '.join(command).lower())

    def test_kubernetes_requires_primary_service_ready_not_other_container(self):
        self.ready = 'false'
        with patch.object(m, 'output', side_effect=self.kube_output):
            with self.assertRaisesRegex(ValueError, 'Expected one ready'):
                m.verify_live(Path('.'), self.cfg, self.manifest)

    def test_kubernetes_refuses_ambiguous_or_invalid_pod_list(self):
        for pods in (b'pod-a\npod-b\n', b'bad/name\n'):
            def fake(command, env=None):
                if 'pods' in command:
                    return pods
                return self.kube_output(command, env)
            with self.subTest(pods=pods), patch.object(m, 'output', side_effect=fake):
                with self.assertRaises(ValueError):
                    m.verify_live(Path('.'), self.cfg, self.manifest)

    def test_inspection_failure_does_not_echo_command_output_or_credentials(self):
        with patch.object(install_recovery, 'run_readonly', side_effect=install_recovery.DiagnosticError('secret-canary')):
            with self.assertRaisesRegex(ValueError, '^Runtime inspection failed;') as error:
                m.output(['docker', 'inspect', 'fixture'])
        self.assertNotIn('secret-canary', str(error.exception))


if __name__ == '__main__':
    unittest.main()
