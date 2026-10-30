import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import uterctl
from scripts import bundle


class BundleProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        key = Ed25519PrivateKey.generate()
        self.private = self.root / 'private.pem'
        self.public = self.root / 'public.pem'
        self.private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
        self.public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                               serialization.PublicFormat.SubjectPublicKeyInfo))

    def make_bundle(self, gated=True):
        manifest = {'schema': 1, 'config_schema': 1, 'tooling_schema': 1,
                    'status': 'released', 'version': '0.1.7', 'source_commit': 'a' * 40,
                    'data_epoch': 2 if gated else 1, 'upgrade_from': ['0.1.6'],
                    'images': {name: 'registry.example/' + name + '@sha256:' + 'b' * 64
                               for name in ('guardrail', 'agent', 'redis')}}
        if gated:
            manifest['session_identity_gate'] = {'schema': 1, 'from_epoch': 1, 'to_epoch': 2,
                                                   'policy': 'block_unverified_sessions'}
        source = self.root / 'manifest.json'
        source.write_text(json.dumps(manifest), encoding='utf-8')
        result = self.root / 'bundle'
        bundle.build(source, result, self.private)
        return result

    def test_gated_bundle_signs_exact_placeholder_and_document(self):
        result = self.make_bundle()
        placeholder = result / 'scripts/session_provenance.py'
        doc = result / 'docs/session-provenance-contract.md'
        source = uterctl.ROOT / 'scripts/session_provenance.py'
        self.assertEqual(placeholder.read_bytes(), source.read_bytes())
        self.assertTrue(doc.is_file())
        inventory = json.loads((result / 'checksums.json').read_text(encoding='utf-8'))
        self.assertEqual(inventory['scripts/session_provenance.py'], hashlib.sha256(placeholder.read_bytes()).hexdigest())
        self.assertIn('docs/session-provenance-contract.md', inventory)
        self.assertEqual(uterctl.verify(result, self.public)['session_identity_gate']['policy'],
                         'block_unverified_sessions')

    def test_changed_or_deleted_placeholder_rejected_by_signed_inventory(self):
        result = self.make_bundle()
        placeholder = result / 'scripts/session_provenance.py'
        original = placeholder.read_bytes()
        for mutation in ('change', 'delete'):
            with self.subTest(mutation=mutation):
                if mutation == 'change':
                    placeholder.write_bytes(original + b'\n# modified\n')
                else:
                    placeholder.unlink()
                with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
                    uterctl.verify(result, self.public)
                placeholder.write_bytes(original)
        uterctl.verify(result, self.public)

    def test_non_gated_bundle_keeps_previous_inventory(self):
        result = self.make_bundle(gated=False)
        self.assertFalse((result / 'scripts/session_provenance.py').exists())
        self.assertFalse((result / 'scripts/session_migration_guard.py').exists())
        self.assertEqual((result / 'scripts/redis_fence_journal.py').read_bytes(),
                         (uterctl.ROOT / 'scripts/redis_fence_journal.py').read_bytes())
        for name in ('compose_nsfirewall_adapter.py','compose_nsfirewall_protocol.py',
                     'compose_nsfirewall_checkpoint.py','compose_fence_adapter.py','compose_fence_recovery_plan.py',
                     'compose_redis_diagnostic.py','compose_systemd_activation.py','experimental_docker_activation_ci.py',
                     'compose_snapshot_only.py','snapshot_only_receipts.py','compose_fence_start.py','compose_fence_resume.py',
                     'compose_fence_origin.py'):
            with self.subTest(name=name):
                path=result/'scripts'/name
                self.assertEqual(path.read_bytes(),(uterctl.ROOT/'scripts'/name).read_bytes())
                self.assertIn('scripts/'+name,json.loads((result/'checksums.json').read_text()))
        self.assertEqual(uterctl.verify(result, self.public)['data_epoch'], 1)
