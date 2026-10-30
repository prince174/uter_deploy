import json
import tempfile
import unittest
from pathlib import Path

from scripts import maintenance_evidence as evidence, redis_fence_journal as journal


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


if __name__ == '__main__':
    unittest.main()
