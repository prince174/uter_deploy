import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import published_pair_ci as p

class PublishedPairSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.old=self.root/'old';self.new=self.root/'new';self.old.mkdir();self.new.mkdir()
        self.key=self.root/'key';self.key.write_text('fixture')
        self.env={'UTER_CI_RELEASE_MODE':'published','OLD_SIGNED_BUNDLE_PATH':str(self.old),
                  'NEW_SIGNED_BUNDLE_PATH':str(self.new),'PUBLISHER_KEY_PATH':str(self.key)}
        self.old_m={'images':{x:'old-'+x for x in ('guardrail','agent','redis')},'image_config_ids':{x:'id-'+x for x in ('guardrail','agent','redis')}}
        self.new_m={'images':{x:'new-'+x for x in ('guardrail','agent','redis')},'image_config_ids':{x:'new-id-'+x for x in ('guardrail','agent','redis')}}
        for release, m in [('published-old',self.old_m),('published-new',self.new_m)]:
            folder=self.root/'input'/release;folder.mkdir(parents=True)
            (folder/'images.json').write_text(json.dumps(m['images']))
            (folder/'publication.json').write_text(json.dumps({'images':{n:{'image_id':v} for n,v in m['image_config_ids'].items()}}))

    def test_default_mode_is_synthetic(self):
        self.assertEqual(p.select_mode({},self.root),{'mode':'synthetic'})
        with self.assertRaisesRegex(ValueError,'explicit published'):
            p.select_mode({'OLD_SIGNED_BUNDLE_PATH':str(self.old)},self.root)
        with self.assertRaisesRegex(ValueError,'Unsupported'):
            p.select_mode({'UTER_CI_RELEASE_MODE':'other'},self.root)

    def test_published_requires_signature_pair_and_uses_old_installer(self):
        with patch.object(p,'verify_pair',return_value=(self.old_m,self.new_m)) as verify:
            result=p.select_mode(self.env,self.root)
        verify.assert_called_once_with(self.old.resolve(),self.new.resolve(),self.key.resolve(),p.FINGERPRINT,'0.1.2','0.1.3')
        self.assertEqual(result['installer'],self.old.resolve()/'scripts/install.py')
        self.assertEqual(result['old_manifest'],self.old_m)
        self.assertEqual(result['new_manifest'],self.new_m)

    def test_invalid_signed_transition_fails_before_install(self):
        with patch.object(p,'verify_pair',side_effect=ValueError('Unsupported upgrade path')):
            with self.assertRaisesRegex(ValueError,'Unsupported upgrade path'):
                p.select_mode(self.env,self.root)
        bad=dict(self.env);bad.pop('PUBLISHER_KEY_PATH')
        with self.assertRaisesRegex(ValueError,'requires both'):
            p.select_mode(bad,self.root)

    def test_mismatched_images_or_configuration_ids_refused(self):
        with patch.object(p,'verify_pair',return_value=(self.old_m,self.new_m)):
            images=self.root/'input'/'published-old'/'images.json'
            images.write_text(json.dumps(dict(self.old_m['images'],agent='tampered')))
            with self.assertRaisesRegex(ValueError,'images do not match'):
                p.select_mode(self.env,self.root)
            images.write_text(json.dumps(self.old_m['images']))
            publication=self.root/'input'/'published-new'/'publication.json'
            publication.write_text(json.dumps({'images':{n:{'image_id':'tampered'} for n in self.new_m['images']}}))
            with self.assertRaisesRegex(ValueError,'identities do not match'):
                p.select_mode(self.env,self.root)

    def test_signed_update_pretty_json_and_trailing_warning(self):
        payload=json.dumps({'version':'0.1.3','backup':'/tmp/backup'},indent=2).encode()+b'\nStore key securely\n'
        self.assertEqual(p.parse_update_output(payload)['backup'],'/tmp/backup')
        with self.assertRaises(ValueError):
            p.parse_update_output(b'{"version":"0.1.3"}')
        with self.assertRaises(ValueError):
            p.parse_update_output(b'not-json')
