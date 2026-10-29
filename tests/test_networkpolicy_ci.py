import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import networkpolicy_ci as ci


class NetworkPolicyCITests(unittest.TestCase):
    def test_local_execution_refused_before_accessing_runtime(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}, clear=True), \
                patch.object(ci, 'call') as command:
            with self.assertRaisesRegex(ci.StageError, 'DISPOSABLE_GITHUB_HOSTED_RUNNER_REQUIRED'):
                ci.main()
            command.assert_not_called()

    def test_calico_manifest_hash_and_all_image_references_required(self):
        data = ('\n'.join('  image: '+item for item in ci.CALICO_IMAGES)+'\n').encode()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'calico.yaml'
            path.write_bytes(data)
            with patch.object(ci, 'CALICO_SHA256', hashlib.sha256(data).hexdigest()):
                result = ci.calico_manifest(path).decode()
            for original, pinned in ci.CALICO_IMAGES.items():
                self.assertNotIn(original, result)
                self.assertIn(pinned, result)
            path.write_bytes(data + b'changed')
            with self.assertRaisesRegex(ci.StageError, 'HASH_MISMATCH'):
                ci.calico_manifest(path)
            extra = data + b'  image: untrusted/image:latest\n'
            path.write_bytes(extra)
            with patch.object(ci, 'CALICO_SHA256', hashlib.sha256(extra).hexdigest()):
                with self.assertRaisesRegex(ci.StageError, 'IMAGE_SET_INVALID'):
                    ci.calico_manifest(path)

    @unittest.skipUnless(os.name == 'posix', 'FIFO test requires POSIX')
    def test_calico_manifest_rejects_fifo_without_hanging(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'fifo'
            os.mkfifo(path)
            with self.assertRaisesRegex(ci.StageError, 'MANIFEST_INVALID'):
                ci.calico_manifest(path)

    def test_client_pods_are_isolated_and_immutable(self):
        pod = ci.client_pod('ingress-fixture')
        spec = pod['spec']
        self.assertFalse(spec['automountServiceAccountToken'])
        self.assertTrue(spec['securityContext']['runAsNonRoot'])
        container = spec['containers'][0]
        self.assertIn('@sha256:', container['image'])
        self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
        self.assertEqual(container['securityContext']['capabilities']['drop'], ['ALL'])

    def test_only_actual_socket_timeout_counts_as_denied(self):
        for result in ('CONNECTED', 'DNS_OK', 'READY', 'EGRESS_OK'):
            with self.subTest(result=result), self.assertRaisesRegex(ci.StageError, 'DENY_FAILED'):
                ci.require_probe(result, 'TIMEOUT', 'DENY_FAILED')
        ci.require_probe('TIMEOUT', 'TIMEOUT', 'DENY_FAILED')
        for invalid in (b'ERROR\n', b'connection refused', b''):
            with self.subTest(output=invalid), patch.object(ci, 'call', return_value=invalid):
                with self.assertRaisesRegex(ci.StageError, 'OUTPUT_INVALID'):
                    ci.run_probe(['kubectl'], 'ns', 'pod/test', 'print(1)', {})

    def test_tcp_probe_uses_named_namespace_and_syntactically_valid_stdin(self):
        with patch.object(ci, 'call', return_value=b'TIMEOUT\n') as command:
            result = ci.tcp_probe(['kubectl','--context','kind-test'], 'deny-ns', 'pod/network-client',
                                  'uter-guardrail.uter.svc.cluster.local', 8000, {})
        self.assertEqual(result, 'TIMEOUT')
        args, kwargs = command.call_args
        self.assertEqual(args[0][:5], ['kubectl','--context','kind-test','-n','deny-ns'])
        self.assertEqual(args[0][-2:], ['python','-'])
        compile(kwargs['input_data'].decode(), 'network-probe', 'exec')

    def test_workflow_pins_manifest_and_does_not_request_secrets(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root/'.github/workflows/networkpolicy-e2e.yml').read_text(encoding='utf-8')
        self.assertIn(ci.CALICO_SHA256, workflow)
        self.assertIn('v3.33.0/manifests/calico.yaml', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertNotIn('secrets.', workflow)
        self.assertIn('driver/scripts/networkpolicy_ci.py', workflow)
        self.assertTrue((root/'tests/fixtures/scheduled_backup_upstream.py').is_file())
        self.assertTrue(all('@sha256:' in ref for ref in ci.CALICO_IMAGES.values()))


if __name__ == '__main__':
    unittest.main()
