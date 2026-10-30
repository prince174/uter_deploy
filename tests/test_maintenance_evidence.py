import json
import hashlib
import hmac
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import (maintenance_evidence as evidence, maintenance_protocol as protocol,
                     maintenance_transport as transport, redis_fence_journal as journal)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.operation = 'a'*32
        self.plan = 'b'*64
        self.boot = 'c'*32
        journal.create(self.home, backend='compose', site='uter-test', resource='d'*64,
                       plan_sha256=self.plan, operation=self.operation)
        self.locked = True
        self.recorder = evidence.Recorder(self.home, b'k'*32, operation=self.operation,
                                          backend='compose', plan_sha256=self.plan, lock_guard=lambda: self.locked)
        self.receipt = {'protocol': 1, 'boot_id': self.boot, 'state': 'quiesced', 'safe_to_stop': True,
                        'active_requests': 0, 'error': None,
                        'evidence': {'requests_drained': True, 'redis': 'not_used', 'audit': 'guardrail_owned'}}

    def test_write_once_receipt_is_bound_to_intent_and_scope(self):
        self.assertTrue(self.recorder.intent('agent', 'exact-container-id', self.boot))
        self.assertTrue(self.recorder.receipt('agent', 'exact-container-id', self.boot, self.receipt))
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.intent('agent', 'exact-container-id', self.boot)
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.receipt('agent', 'different-container', self.boot, self.receipt)

    def test_tampered_intent_and_wrong_boot_rejected(self):
        self.recorder.intent('agent', 'instance', self.boot)
        path = next(self.home.glob('maintenance-intent-*'))
        value = json.loads(path.read_text()); value['record']['boot_id'] = 'e'*32
        path.write_text(json.dumps(value))
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.receipt('agent', 'instance', self.boot, self.receipt)

    def test_lost_lock_or_changed_journal_rejects_write(self):
        self.locked = False
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.intent('agent', 'instance', self.boot)
        self.locked = True
        journal.advance(self.home, operation=self.operation, expected='prepared', next_phase='isolating')
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.intent('agent', 'instance', self.boot)
        self.assertFalse(list(self.home.glob('maintenance-intent-*')))

    def test_receipt_must_be_complete_and_guardrail_cannot_use_agent_evidence(self):
        self.recorder.intent('guardrail', 'instance', self.boot)
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.receipt('guardrail', 'instance', self.boot, self.receipt)
        self.assertFalse(list(self.home.glob('maintenance-receipt-*')))

    def test_coordinator_records_both_receipts_before_completion(self):
        inventory = {'agent': ('agent-id',), 'guardrail': ('guard-id',)}
        boots = {'agent-id': 'e'*32, 'guard-id': 'f'*32}
        states = dict.fromkeys(boots, 'running')
        def request(service, instance, method, timeout):
            if method == 'POST':
                states[instance] = 'quiesced'; state = 'draining'
            else:
                state = states[instance]
            data = dict(self.receipt, boot_id=boots[instance], state=state, safe_to_stop=state == 'quiesced',
                        evidence=None)
            if state == 'quiesced':
                data['evidence'] = (self.receipt['evidence'] if service == 'agent' else
                                    {'redis_closed': True, 'audit': {'last_seq': 1, 'last_hash': 'd'*64,
                                                                     'fsynced': True, 'verified': True}})
            return (202 if state == 'draining' else 200), json.dumps(data).encode()
        receipts = protocol.collect(inventory, observe_inventory=lambda: dict(inventory), request=request,
                                    record_intent=self.recorder.intent, record_receipt=self.recorder.receipt)
        self.assertEqual(set(receipts), set(boots))
        self.assertEqual(len(list(self.home.glob('maintenance-intent-*'))), 2)
        self.assertEqual(len(list(self.home.glob('maintenance-receipt-*'))), 2)
        self.assertEqual(journal.read(self.home)['phase'], 'prepared')

    def test_partial_operation_cannot_replay_intent(self):
        self.recorder.intent('agent', 'instance', self.boot)
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.intent('agent', 'instance', self.boot)
        self.assertEqual(journal.read(self.home)['phase'], 'prepared')

    def test_evidence_is_key_bound_and_backend_bound(self):
        self.recorder.intent('agent', 'instance', self.boot)
        wrong = evidence.Recorder(self.home, b'z'*32, operation=self.operation,
                                  backend='compose', plan_sha256=self.plan, lock_guard=lambda: True)
        with self.assertRaises(evidence.EvidenceError):
            wrong.receipt('agent', 'instance', self.boot, self.receipt)
        with self.assertRaises(evidence.EvidenceError):
            evidence.Recorder(self.home, b'k'*32, operation=self.operation,
                              backend='kubernetes', plan_sha256=self.plan, lock_guard=lambda: True)

    def test_late_phase_reads_validate_intent_and_receipt_without_new_writes(self):
        self.recorder.intent('agent', 'instance', self.boot)
        self.recorder.receipt('agent', 'instance', self.boot, self.receipt)
        for previous, phase in (('prepared', 'isolating'), ('isolating', 'isolated'),
                                ('isolated', 'capturing'), ('capturing', 'captured'),
                                ('captured', 'snapshot_releasing'), ('snapshot_releasing', 'redis_released')):
            journal.advance(self.home, operation=self.operation, expected=previous, next_phase=phase)
            # Recreate the reader as after a process restart; the caller is
            # responsible for authenticating its expected operation and plan.
            reader = evidence.Recorder(self.home, b'k'*32, operation=self.operation,
                                       backend='compose', plan_sha256=self.plan, lock_guard=lambda: self.locked)
            self.assertEqual(reader.read_intent('agent', 'instance', self.boot, site='uter-test', resource='d'*64)['operation'], self.operation)
            self.assertEqual(reader.read_receipt('agent', 'instance', self.boot, site='uter-test', resource='d'*64), self.receipt)
            with self.assertRaises(evidence.EvidenceError):
                reader.intent('agent', 'other-instance', self.boot)
            with self.assertRaises(evidence.EvidenceError):
                reader.receipt('agent', 'instance', self.boot, self.receipt)

    def test_missing_intent_or_receipt_cannot_be_interpreted_as_success(self):
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.read_intent('agent', 'instance', self.boot, site='uter-test', resource='d'*64)
        self.recorder.intent('agent', 'instance', self.boot)
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.read_receipt('agent', 'instance', self.boot, site='uter-test', resource='d'*64)
        self.recorder.receipt('agent', 'instance', self.boot, self.receipt)
        next(self.home.glob('maintenance-intent-*')).unlink()
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.read_receipt('agent', 'instance', self.boot, site='uter-test', resource='d'*64)

    def test_tamper_wrong_key_boot_service_and_scope_are_rejected(self):
        self.recorder.intent('agent', 'instance', self.boot)
        self.recorder.receipt('agent', 'instance', self.boot, self.receipt)
        for args in (('agent', 'instance', 'e'*32), ('guardrail', 'instance', self.boot),
                     ('agent', 'other-instance', self.boot)):
            with self.subTest(args=args), self.assertRaises(evidence.EvidenceError):
                self.recorder.read_receipt(*args, site='uter-test', resource='d'*64)
        wrong = evidence.Recorder(self.home, b'z'*32, operation=self.operation,
                                  backend='compose', plan_sha256=self.plan, lock_guard=lambda: True)
        with self.assertRaises(evidence.EvidenceError):
            wrong.read_receipt('agent', 'instance', self.boot, site='uter-test', resource='d'*64)
        path = next(self.home.glob('maintenance-receipt-*'))
        data = json.loads(path.read_text()); data['record']['receipt']['safe_to_stop'] = False
        path.write_text(json.dumps(data))
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.read_receipt('agent', 'instance', self.boot, site='uter-test', resource='d'*64)

    def test_authenticated_wrong_operation_or_invalid_receipt_is_rejected(self):
        self.recorder.intent('agent', 'instance', self.boot)
        self.recorder.receipt('agent', 'instance', self.boot, self.receipt)
        path = next(self.home.glob('maintenance-receipt-*'))
        original = json.loads(path.read_text())
        for mutate in (lambda item: item['identity'].update(operation='f'*32),
                       lambda item: item['identity'].update(plan_sha256='f'*64),
                       lambda item: item['receipt'].update(safe_to_stop=False)):
            envelope = json.loads(json.dumps(original))
            mutate(envelope['record'])
            envelope['mac'] = hmac.new(self.recorder.key, evidence._canonical(envelope['record']),
                                       hashlib.sha256).hexdigest()
            path.write_text(json.dumps(envelope))
            with self.assertRaises(evidence.EvidenceError):
                self.recorder.read_receipt('agent', 'instance', self.boot, site='uter-test', resource='d'*64)

    def test_lock_or_journal_changes_during_read_are_rejected(self):
        self.recorder.intent('agent', 'instance', self.boot)
        self.locked = False
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.read_intent('agent', 'instance', self.boot, site='uter-test', resource='d'*64)
        self.locked = True
        real_read = journal.read
        calls = 0
        def changed(home):
            nonlocal calls
            calls += 1
            state = real_read(home)
            return dict(state, phase='isolating') if calls > 1 else state
        with mock.patch.object(journal, 'read', side_effect=changed):
            with self.assertRaisesRegex(evidence.EvidenceError, 'SCOPE_UNVERIFIED'):
                self.recorder.read_intent('agent', 'instance', self.boot, site='uter-test', resource='d'*64)

    def test_all_journal_scope_fields_must_match_independent_expectations(self):
        self.recorder.intent('agent', 'instance', self.boot)
        self.recorder.receipt('agent', 'instance', self.boot, self.receipt)
        for site, resource in (('other-site', 'd'*64), ('uter-test', 'f'*64)):
            with self.subTest(site=site, resource=resource), self.assertRaises(evidence.EvidenceError):
                self.recorder.read_receipt('agent', 'instance', self.boot, site=site, resource=resource)
        journal_path = self.home/journal.NAME
        original = json.loads(journal_path.read_text())
        for field, value in (('site', 'other-site'), ('resource', 'f'*64),
                             ('operation', 'f'*32), ('plan_sha256', 'f'*64),
                             ('backend', 'kubernetes'), ('schema', 2)):
            with self.subTest(field=field):
                journal_path.write_text(json.dumps(dict(original, **{field: value})))
                with self.assertRaises(evidence.EvidenceError):
                    self.recorder.read_receipt('agent', 'instance', self.boot,
                                               site='uter-test', resource='d'*64)
        journal_path.write_text(json.dumps(original))

    def test_failed_fsync_preserves_uncertain_intent_and_prevents_replay(self):
        with mock.patch.object(evidence.os, 'fsync', side_effect=OSError):
            with self.assertRaisesRegex(evidence.EvidenceError, 'WRITE_UNCERTAIN'):
                self.recorder.intent('agent', 'instance', self.boot)
        self.assertEqual(len(list(self.home.glob('maintenance-intent-*'))), 1)
        with self.assertRaisesRegex(evidence.EvidenceError, 'WRITE_UNCERTAIN'):
            self.recorder.intent('agent', 'instance', self.boot)
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.read_receipt('agent', 'instance', self.boot, site='uter-test', resource='d'*64)

    def test_untrusted_file_type_permissions_and_duplicate_fields_rejected(self):
        self.recorder.intent('agent', 'instance', self.boot)
        path = next(self.home.glob('maintenance-intent-*'))
        path.chmod(0o644)
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.read_intent('agent', 'instance', self.boot, site='uter-test', resource='d'*64)
        path.chmod(0o600); path.write_text('{"record":{},"record":{},"mac":"x"}')
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.read_intent('agent', 'instance', self.boot, site='uter-test', resource='d'*64)
        path.unlink(); os.symlink('missing', path)
        with self.assertRaises(evidence.EvidenceError):
            self.recorder.read_intent('agent', 'instance', self.boot, site='uter-test', resource='d'*64)

    def test_kubernetes_scope_requires_its_own_journal(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            journal.create(home, backend='kubernetes', site='uter-test',
                           resource='12345678-1234-1234-1234-123456789abc',
                           plan_sha256=self.plan, operation=self.operation)
            recorder = evidence.Recorder(home, b'k'*32, operation=self.operation, backend='kubernetes',
                                         plan_sha256=self.plan, lock_guard=lambda: True)
            self.assertTrue(recorder.intent('agent', 'pod-uid/container-id', self.boot))
            self.assertTrue(recorder.receipt('agent', 'pod-uid/container-id', self.boot, self.receipt))

    def test_composed_transport_coordinator_and_evidence_for_both_backends(self):
        for backend in ('compose', 'kubernetes'):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as folder:
                home = Path(folder)
                resource = 'd'*64 if backend == 'compose' else '12345678-1234-1234-1234-123456789abc'
                journal.create(home, backend=backend, site='uter-test', resource=resource,
                               plan_sha256=self.plan, operation=self.operation)
                recorder = evidence.Recorder(home, b'k'*32, operation=self.operation, backend=backend,
                                             plan_sha256=self.plan, lock_guard=lambda: True)
                identities = {'agent': ('1'*64,), 'guardrail': ('2'*64,)}
                boots = {'agent': 'a'*32, 'guardrail': 'b'*32}
                states = {'agent': 'running', 'guardrail': 'running'}
                events = []
                api = SimpleNamespace(binary_fd=9, context='pinned-context')
                session = SimpleNamespace(site='uter-test', _executor=object(),
                    _record={'schema': 2, 'kubectl_sha256': 'c'*64}, config_sha256='d'*64,
                    _inner=SimpleNamespace(api=api, config_fd=10), _scope=lambda: None)
                def run(command, *, fds=(), timeout=8):
                    method, port = command[-2:]
                    service = 'agent' if port == '8001' else 'guardrail'
                    events.append((service, method))
                    if method == 'POST': states[service] = 'quiesced'; state = 'draining'
                    else: state = states[service]
                    item = {'protocol': 1, 'boot_id': boots[service], 'state': state,
                            'safe_to_stop': state == 'quiesced', 'active_requests': 0, 'error': None, 'evidence': None}
                    if state == 'quiesced':
                        item['evidence'] = (self.receipt['evidence'] if service == 'agent' else
                            {'redis_closed': True, 'audit': {'last_seq': 1, 'last_hash': 'f'*64,
                                                             'fsynced': True, 'verified': True}})
                    return json.dumps({'status': 202 if state == 'draining' else 200,
                                       'body': json.dumps(item)}).encode()
                def request(service, instance, method, timeout):
                    target = ({'container_id': instance} if backend == 'compose' else
                              {'session': session, 'pod': 'uter-test-'+service+'-abcd-xyz'})
                    return transport.request(service=service, method=method, identity_guard=lambda: True, **target)
                with mock.patch.object(transport, '_run', side_effect=run), \
                     mock.patch.object(transport.kubernetes_trusted_kubectl, 'verify'), \
                     mock.patch.object(transport.kubernetes_sealed_config, 'verify_sealed'):
                    result = protocol.collect(identities, observe_inventory=lambda: dict(identities), request=request,
                                              record_intent=recorder.intent, record_receipt=recorder.receipt)
                self.assertEqual(set(result), {'1'*64, '2'*64})
                self.assertLess(events.index(('agent', 'POST')), events.index(('guardrail', 'POST')))
                self.assertEqual(len(list(home.glob('maintenance-receipt-*'))), 2)
                self.assertEqual(journal.read(home)['phase'], 'prepared')


if __name__ == '__main__':
    unittest.main()
