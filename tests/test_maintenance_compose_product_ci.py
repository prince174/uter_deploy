import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import yaml

from scripts import maintenance_compose_product_ci as probe


class ProductProbeTests(unittest.TestCase):
    def test_workflow_is_manual_and_uses_read_only_permissions(self):
        path = Path(__file__).resolve().parents[1]/'.github/workflows/maintenance-product-compose.yml'
        workflow = yaml.load(path.read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow['on']), {'workflow_dispatch'})
        self.assertEqual(workflow['permissions'], {'contents': 'read', 'actions': 'read'})
        self.assertEqual(set(workflow['on']['workflow_dispatch']['inputs']), {'build_run_id', 'patch_sha256'})

    def test_refuses_non_hosted_execution_before_docker(self):
        with mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), \
             mock.patch.object(probe, '_docker') as docker, self.assertRaises(probe.ProbeError):
            probe.exercise('/unused')
        docker.assert_not_called()

    def test_receipts_bound_to_observed_container_identities(self):
        ids = {'agent': '1'*64, 'guardrail': '2'*64, 'redis': '3'*64}
        images = {'agent': 'sha256:'+'a'*64, 'guardrail': 'sha256:'+'b'*64, 'redis': 'sha256:'+'c'*64}
        states = {'agent': 'running', 'guardrail': 'running'}
        events = []
        stopped = set()
        def docker(*args):
            if args[0] == 'stop':
                stopped.add(args[-1])
                return args[-1]
            if args[0] == 'ps':
                service = next(x.rsplit('=', 1)[1] for x in args if x.startswith('label=com.docker.compose.service='))
                return '' if ids[service] in stopped else ids[service]
            if args[0] == 'image':
                return images[args[-1].split('-')[1]]
            service = next(name for name, ident in ids.items() if ident == args[-1])
            return json.dumps({'id': ids[service], 'image': images[service], 'running': True,
                'started': '2026-01-01T00:00:00Z', 'restarts': 0, 'project': 'uter-compiled-ci', 'service': service})
        def request(*, service, method, container_id, identity_guard):
            self.assertEqual(container_id, ids[service]); self.assertTrue(identity_guard())
            events.append((service, method))
            if method == 'POST': states[service] = 'quiesced'; state = 'draining'
            else: state = states[service]
            payload = {'protocol': 1, 'boot_id': ('a' if service == 'agent' else 'b')*32,
                       'state': state, 'safe_to_stop': state == 'quiesced', 'active_requests': 0,
                       'error': None, 'evidence': None}
            if state == 'quiesced':
                payload['evidence'] = ({'requests_drained': True, 'redis': 'not_used', 'audit': 'guardrail_owned'}
                    if service == 'agent' else {'redis_closed': True, 'audit': {'last_seq': 1,
                    'last_hash': 'c'*64, 'fsynced': True, 'verified': True}})
            return (202 if state == 'draining' else 200), json.dumps(payload).encode()
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)/'work'; home = work/'integration'; home.mkdir(parents=True)
            (work/'integration-evidence').mkdir()
            env = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                   'RUNNER_OS': 'Linux', 'UTER_CI_MAINTENANCE': 'true'}
            with mock.patch.dict(os.environ, env), mock.patch.object(probe, '_docker', side_effect=docker), \
                 mock.patch.object(probe.maintenance_transport, 'request', side_effect=request):
                probe.exercise(home)
            self.assertLess(events.index(('agent', 'POST')), events.index(('guardrail', 'POST')))
            self.assertEqual(stopped, {ids['agent']})
            self.assertIn('Stopping the receipted Agent invalidated the inventory',
                          (work/'integration-evidence'/'maintenance.txt').read_text())
            self.assertIn('Redis fence, backup, update and recovery were not tested',
                          (work/'integration-evidence'/'maintenance.txt').read_text())
            self.assertEqual(len(list((home/'maintenance-ci-proof').glob('maintenance-receipt-*'))), 2)


if __name__ == '__main__':
    unittest.main()
