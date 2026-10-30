import json
from pathlib import Path
import tempfile
import unittest

from scripts.release_manifest import make_manifest


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.images = {x: 'ghcr.io/test/'+x+'@sha256:'+'a'*64 for x in ('guardrail','agent','redis')}
        self.records = {x: {'image_id': 'sha256:'+'b'*64} for x in self.images}
        self.records['guardrail']['source_commit'] = 'c'*40
        self.records['agent']['source_commit'] = 'c'*40
        self.write()

    def write(self):
        (self.root/'images.json').write_text(json.dumps(self.images))
        (self.root/'publication.json').write_text(json.dumps({'images': self.records}))

    def test_compatibility_is_explicit(self):
        m = make_manifest(self.root, '1.2.3', 4, ['1.2.2'])
        self.assertEqual((m['data_epoch'], m['upgrade_from']), (4, ['1.2.2']))
        self.assertEqual(m['images'], self.images)

    def test_session_identity_gate_must_be_an_explicit_epoch_two_release(self):
        m = make_manifest(self.root, '0.1.7', 2, ['0.1.6'], session_identity_gate=True)
        self.assertEqual(m['session_identity_gate'], {
            'schema': 1, 'from_epoch': 1, 'to_epoch': 2, 'policy': 'block_unverified_sessions',
        })
        self.assertNotIn('session_identity_gate', make_manifest(self.root, '0.1.6', 1, []))
        with self.assertRaisesRegex(ValueError, 'requires epoch 2'):
            make_manifest(self.root, '0.1.7', 1, ['0.1.6'], session_identity_gate=True)
        with self.assertRaisesRegex(ValueError, 'explicit upgrade source'):
            make_manifest(self.root, '0.1.7', 2, [], session_identity_gate=True)

    def test_refuses_different_source_commits(self):
        self.records['agent']['source_commit'] = 'd'*40
        self.write()
        with self.assertRaisesRegex(ValueError, 'commits differ'):
            make_manifest(self.root, '1.2.3', 1, [])

    def test_snapshot_provenance_is_signed_and_identical_across_all_services(self):
        state = {'kind':'uncommitted_patch', 'baseline_commit':'c'*40, 'patch_sha256':'d'*64}
        for service in self.records: self.records[service]['source_state'] = dict(state)
        self.records['redis']['application_commit'] = 'c'*40
        self.write()
        self.assertEqual(make_manifest(self.root, '1.2.3', 1, [])['source_state'], state)
        self.records['agent']['source_state']['patch_sha256'] = 'e'*64; self.write()
        with self.assertRaisesRegex(ValueError, 'differs across images'):
            make_manifest(self.root, '1.2.3', 1, [])
        del self.records['redis']['source_state']; self.write()
        with self.assertRaisesRegex(ValueError, 'missing'):
            make_manifest(self.root, '1.2.3', 1, [])

    def test_manifest_rejects_snapshot_baseline_disagreement(self):
        from uterctl import validate
        manifest = make_manifest(self.root, '1.2.3', 1, [])
        manifest['source_state'] = {'kind':'uncommitted_patch', 'baseline_commit':'f'*40, 'patch_sha256':'b'*64}
        with self.assertRaisesRegex(ValueError, 'snapshot provenance'):
            validate(manifest)

    def test_refuses_mutable_image(self):
        self.images['agent'] = 'ghcr.io/test/agent:latest'
        self.write()
        with self.assertRaisesRegex(ValueError, 'digest'):
            make_manifest(self.root, '1.2.3', 1, [])

    def test_refuses_redis_from_another_application_commit(self):
        self.records['redis']['application_commit']='d'*40
        self.write()
        with self.assertRaisesRegex(ValueError,'Redis publication application commit'):
            make_manifest(self.root,'1.2.3',1,[])
