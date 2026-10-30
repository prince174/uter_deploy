import json
import unittest
from contextlib import nullcontext
from unittest import mock

from scripts import compose_maintenance_check as check
import uterctl


class ComposeMaintenanceCheckTests(unittest.TestCase):
    def setUp(self):
        self.adapter = mock.Mock()
        self.plan = {'operation': 'a'*32, 'redis': 'redis-id'}
        self.writers = {'agent': {'id': '1'*64}, 'guardrail': {'id': '2'*64}}
        self.calls = []
        self.snapshot = (self.plan, self.writers, 'b'*64)

    def run_check(self, request=None, observe=None):
        def default_request(*, service, method, container_id, identity_guard):
            self.calls.append((service, method, container_id))
            if not identity_guard(): raise ValueError
            body = {'protocol': 1, 'boot_id': ('a' if service == 'agent' else 'b')*32,
                    'state': 'running', 'safe_to_stop': False, 'active_requests': 0,
                    'error': None, 'evidence': None}
            return 200, json.dumps(body).encode()
        with mock.patch.object(check.backup_snapshot, '_require_fenced_operation_lock'), \
             mock.patch.object(check.journal, 'blocks_mutation', return_value=False), \
             mock.patch.object(check.maintenance_protocol, 'verify_capability', return_value={'version': '1.0.0'}), \
             mock.patch.object(check.fence, 'Adapter', return_value=self.adapter), \
             mock.patch.object(check.start, '_observe', side_effect=observe or (lambda *_: self.snapshot)), \
             mock.patch.object(check.maintenance_transport, 'request', side_effect=request or default_request):
            return check.check('/fixture', '/bundle', '/key', b'k'*32)

    def test_uses_get_for_each_exact_container_and_never_authorizes_update(self):
        result = self.run_check()
        self.assertEqual(self.calls, [('agent', 'GET', '1'*64), ('guardrail', 'GET', '2'*64)])
        self.assertFalse(result['redis_isolated']); self.assertFalse(result['safe_to_update'])
        self.adapter.close.assert_called_once()

    def test_container_identity_change_aborts_and_closes(self):
        changed = dict(self.writers, agent={'id': '3'*64})
        observed = iter([self.snapshot, (self.plan, changed, 'b'*64)])
        with self.assertRaises(check.CheckError):
            self.run_check(observe=lambda *_: next(observed))
        self.assertEqual(len(self.calls), 1)
        self.adapter.close.assert_called_once()

    def test_non_running_or_unsupported_response_is_rejected(self):
        with self.assertRaises(check.CheckError):
            self.run_check(request=lambda **_: (404, b'{"detail":"not found"}'))
        self.adapter.close.assert_called_once()

    def test_existing_operation_blocks_before_capability_or_runtime_access(self):
        with mock.patch.object(check.backup_snapshot, '_require_fenced_operation_lock'), \
             mock.patch.object(check.journal, 'blocks_mutation', return_value=True), \
             mock.patch.object(check.maintenance_protocol, 'verify_capability') as capability, \
             mock.patch.object(check.fence, 'Adapter') as adapter, \
             mock.patch.object(check.maintenance_transport, 'request') as request:
            with self.assertRaises(check.CheckError):
                check.check('/fixture', '/bundle', '/key', b'k'*32)
        capability.assert_not_called();adapter.assert_not_called();request.assert_not_called()

    def test_missing_signed_capability_blocks_before_runtime_access(self):
        with mock.patch.object(check.backup_snapshot, '_require_fenced_operation_lock'), \
             mock.patch.object(check.journal, 'blocks_mutation', return_value=False), \
             mock.patch.object(check.maintenance_protocol, 'verify_capability', side_effect=ValueError), \
             mock.patch.object(check.fence, 'Adapter') as adapter, \
             mock.patch.object(check.maintenance_transport, 'request') as request:
            with self.assertRaises(check.CheckError):
                check.check('/fixture', '/bundle', '/key', b'k'*32)
        adapter.assert_not_called();request.assert_not_called()

    def test_cli_requires_signed_absolute_paths_before_executor_load(self):
        with mock.patch.object(uterctl, '_load_signed_fence_executor') as load:
            with self.assertRaisesRegex(ValueError, 'PATH_NOT_ABSOLUTE'):
                uterctl.main(['maintenance-check-compose', '--home', 'relative', '--bundle', '/bundle',
                              '--key', '/publisher', '--executor-key', '/executor'])
        load.assert_not_called()

    def test_cli_loads_executor_and_uses_fenced_lock(self):
        result = {'backend': 'compose', 'safe_to_update': False}
        with mock.patch.object(uterctl, '_load_signed_fence_executor') as load, \
             mock.patch.object(uterctl, '_fence_secret_inputs', return_value=('/home', '/backup-key', b'k'*32)), \
             mock.patch.object(uterctl, 'fenced_locked', return_value=nullcontext()) as lock, \
             mock.patch.object(check, 'check', return_value=result) as execute, \
             mock.patch('builtins.print') as output:
            uterctl.main(['maintenance-check-compose', '--home', '/home', '--bundle', '/bundle',
                          '--key', '/publisher', '--executor-key', '/executor', '--backup-key', '/backup-key'])
        load.assert_called_once(); lock.assert_called_once_with('/home'); execute.assert_called_once()
        self.assertIn('"safe_to_update": false', output.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
