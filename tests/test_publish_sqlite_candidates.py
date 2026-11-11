import json
from pathlib import Path
import tempfile
import unittest

from scripts import publish_sqlite_candidates as publisher, sqlite_vex_gate as gate
from tests.test_sqlite_vex_gate import SQLiteVexGateTests


class PublicationEvidenceTests(unittest.TestCase):
    def setUp(self):
        fixture = SQLiteVexGateTests()
        fixture.setUp()
        self.fixture = fixture
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.security = self.root / 'security'
        self.security.mkdir()
        _, result = gate.assess_evidence(fixture.report, fixture.image, fixture.measure)
        for name, value in [('agent.json', fixture.report), ('agent-sqlite.json', fixture.measure),
                            ('agent-vex-summary.json', result),
                            ('agent-source-audit.json', {'schema': 2, 'violations': []})]:
            (self.security / name).write_text(json.dumps(value))
        (self.security / 'agent-image-id.txt').write_text(fixture.image + '\n')

    def test_accepts_exact_evidence_but_reports_raw_high(self):
        result = publisher.verify_evidence(self.root, 'agent', self.fixture.image)
        self.assertEqual(result['raw_high'], 3)
        self.assertFalse(result['release_gate_passed'])
        self.assertTrue(result['vex_gate_passed'])

    def test_rejects_changed_image_vex_or_source_audit(self):
        with self.assertRaises(ValueError):
            publisher.verify_evidence(self.root, 'agent', 'sha256:' + 'b' * 64)
        (self.security / 'agent-vex-summary.json').write_text('{}')
        with self.assertRaises(ValueError):
            publisher.verify_evidence(self.root, 'agent', self.fixture.image)
        _, result = gate.assess_evidence(self.fixture.report, self.fixture.image, self.fixture.measure)
        (self.security / 'agent-vex-summary.json').write_text(json.dumps(result))
        (self.security / 'agent-source-audit.json').write_text(json.dumps({'schema': 2, 'violations': ['source']}))
        with self.assertRaises(ValueError):
            publisher.verify_evidence(self.root, 'agent', self.fixture.image)


if __name__ == '__main__':
    unittest.main()
