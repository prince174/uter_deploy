import json
import unittest

from scripts import maintenance_receipt as receipt


class MaintenanceReceiptTests(unittest.TestCase):
    def setUp(self):
        self.boot = 'a' * 32
        self.agent = {'protocol': 1, 'boot_id': self.boot, 'state': 'quiesced', 'safe_to_stop': True,
                      'active_requests': 0, 'error': None,
                      'evidence': {'requests_drained': True, 'redis': 'not_used', 'audit': 'guardrail_owned'}}
        self.guard = dict(self.agent, evidence={'redis_closed': True, 'audit': {
            'last_seq': 1, 'last_hash': 'b' * 64, 'fsynced': True, 'verified': True}})

    def check(self, value, service='agent', boot=None):
        return receipt.validate(json.dumps(value).encode(), service=service, expected_boot=boot or self.boot)

    def test_valid_receipts(self):
        self.assertEqual(self.check(self.agent), self.agent)
        self.assertEqual(self.check(self.guard, 'guardrail'), self.guard)

    def test_rejects_restarts_failures_and_ambiguous_types(self):
        for changes in ({'boot_id': 'c' * 32}, {'state': 'failed'}, {'state': 'draining'},
                        {'safe_to_stop': 1}, {'active_requests': False}, {'active_requests': 1},
                        {'error': 'TimeoutError'}, {'protocol': True}):
            with self.subTest(changes=changes), self.assertRaises(receipt.ReceiptError):
                self.check(dict(self.agent, **changes))

    def test_rejects_incomplete_or_invalid_evidence(self):
        for evidence in ({'redis_closed': True}, {'redis_closed': True, 'audit': {}},
                         {'redis_closed': True, 'audit': {'last_seq': 1, 'last_hash': 'x', 'fsynced': True, 'verified': True}}):
            with self.subTest(evidence=evidence), self.assertRaises(receipt.ReceiptError):
                self.check(dict(self.guard, evidence=evidence), 'guardrail')

    def test_rejects_duplicate_json_keys_and_oversize(self):
        for raw in (b'{"protocol":1,"protocol":1}', b' ' * 16385):
            with self.assertRaises(receipt.ReceiptError):
                receipt.validate(raw, service='agent', expected_boot=self.boot)


if __name__ == '__main__':
    unittest.main()
