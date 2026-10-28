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

    def test_refuses_different_source_commits(self):
        self.records['agent']['source_commit'] = 'd'*40
        self.write()
        with self.assertRaisesRegex(ValueError, 'commits differ'):
            make_manifest(self.root, '1.2.3', 1, [])

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
