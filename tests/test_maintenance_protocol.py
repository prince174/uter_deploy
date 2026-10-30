import json
import unittest

from scripts import maintenance_protocol as protocol


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.inventory = {'agent': ('agent-1', 'agent-2'), 'guardrail': ('guard-1',)}
        self.events = []
        self.boots = {name: format(index + 1, '032x') for index, name in
                      enumerate(name for instances in self.inventory.values() for name in instances)}
        self.states = {name: 'running' for name in self.boots}
        self.now = 0

    def observe(self):
        return dict(self.inventory)

    def request(self, service, name, method, timeout):
        self.events.append((method, name))
        if method == 'POST':
            self.states[name] = 'quiesced'
            state = 'draining'
        else:
            state = self.states[name]
        evidence = None
        if state == 'quiesced':
            evidence = ({'requests_drained': True, 'redis': 'not_used', 'audit': 'guardrail_owned'} if service == 'agent'
                        else {'redis_closed': True, 'audit': {'last_seq': 1, 'last_hash': 'c' * 64,
                                                              'verified': True, 'fsynced': True}})
        obj = {'protocol': 1, 'boot_id': self.boots[name], 'state': state, 'safe_to_stop': state == 'quiesced',
               'active_requests': 0, 'error': None, 'evidence': evidence}
        return (202 if state == 'draining' else 200), json.dumps(obj).encode()

    def record(self, service, name, boot):
        self.events.append(('intent', name))
        return True

    def run_protocol(self, request=None, observe=None, record=None, save=None):
        return protocol.collect(self.inventory, observe_inventory=observe or self.observe, request=request or self.request,
                                record_intent=record or self.record, record_receipt=save or (lambda *_: True), clock=lambda: self.now,
                                sleep=lambda seconds: setattr(self, 'now', self.now + seconds))

    def test_agents_complete_before_guardrail_and_intent_precedes_post(self):
        result = self.run_protocol()
        self.assertEqual(set(result), set(self.boots))
        self.assertLess(self.events.index(('GET', 'agent-2'), 3), self.events.index(('POST', 'guard-1')))
        for name in self.boots:
            self.assertLess(self.events.index(('intent', name)), self.events.index(('POST', name)))

    def test_no_post_if_initial_inventory_changes(self):
        with self.assertRaises(protocol.ProtocolError):
            self.run_protocol(observe=lambda: {'agent': ('agent-1',), 'guardrail': ('guard-1',)})
        self.assertFalse(any(e[0] == 'POST' for e in self.events))

    def test_post_timeout_is_not_retried_and_same_boot_is_observed(self):
        def request(service, name, method, timeout):
            if method == 'POST' and name == 'agent-1':
                self.events.append((method, name)); self.states[name] = 'quiesced'; raise TimeoutError
            return self.request(service, name, method, timeout)
        self.run_protocol(request=request)
        self.assertEqual(self.events.count(('POST', 'agent-1')), 1)

    def test_restart_or_bad_receipt_blocks_guardrail(self):
        def request(service, name, method, timeout):
            status, raw = self.request(service, name, method, timeout)
            if method == 'GET' and name == 'agent-1' and self.states[name] == 'quiesced':
                obj = json.loads(raw); obj['boot_id'] = 'd' * 32; raw = json.dumps(obj).encode()
            return status, raw
        with self.assertRaises(protocol.ProtocolError):
            self.run_protocol(request=request)
        self.assertNotIn(('POST', 'guard-1'), self.events)

    def test_missing_durable_intent_blocks_post(self):
        with self.assertRaises(protocol.ProtocolError):
            self.run_protocol(record=lambda *_: False)
        self.assertFalse(any(e[0] == 'POST' for e in self.events))

    def test_duplicate_process_boots_block_all_posts(self):
        self.boots['agent-2'] = self.boots['agent-1']
        with self.assertRaisesRegex(protocol.ProtocolError, 'BOOT_ID_DUPLICATE'):
            self.run_protocol()
        self.assertFalse(any(e[0] == 'POST' for e in self.events))

    def test_slow_intent_does_not_allow_post_after_deadline(self):
        def record(*_):
            self.now += 71
            return True
        with self.assertRaisesRegex(protocol.ProtocolError, 'DEADLINE_EXCEEDED'):
            self.run_protocol(record=record)
        self.assertFalse(any(e[0] == 'POST' for e in self.events))

    def test_uncertain_receipt_persistence_blocks_remaining_writers(self):
        with self.assertRaisesRegex(protocol.ProtocolError, 'RECEIPT_PERSISTENCE_UNVERIFIED'):
            self.run_protocol(save=lambda *_: False)
        self.assertIn(('POST', 'agent-1'), self.events)
        self.assertNotIn(('POST', 'agent-2'), self.events)
        self.assertNotIn(('POST', 'guard-1'), self.events)


if __name__ == '__main__':
    unittest.main()
