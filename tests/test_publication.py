import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.error

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).resolve().parents[1] / 'scripts/publish_images.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class PublicationTests(unittest.TestCase):
    def test_anonymous_private_denied(self):
        for code in (401, 403, 404):
            with patch.object(m.urllib.request, 'urlopen', side_effect=urllib.error.HTTPError('url', code, '', {}, None)):
                m.anonymous_denied('owner/package')

    def test_registry_errors_fail_closed(self):
        with patch.object(m.urllib.request, 'urlopen', side_effect=urllib.error.HTTPError('url', 500, '', {}, None)):
            with self.assertRaises(urllib.error.HTTPError):
                m.anonymous_denied('owner/package')

    def test_public_package_rejected(self):
        import io
        with patch.object(m.urllib.request, 'urlopen', return_value=io.BytesIO(b'{"token":"public-token"}')):
            with self.assertRaises(RuntimeError):
                m.anonymous_denied('owner/package')

    def test_publisher_refuses_local_execution(self):
        with patch.dict(m.os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                m.main()

class MirrorPrivacyTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('mirror', Path(__file__).resolve().parents[1] / 'scripts/mirror_dockerhub.py')
        self.mirror = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mirror)

    def test_existing_public_repository_rejected(self):
        with patch.object(self.mirror, 'api', return_value={'is_private': False}):
            with self.assertRaises(RuntimeError):
                self.mirror.private_repository('owner', 'uter-agent', 'token')

    def test_missing_repository_created_explicitly_private(self):
        missing = urllib.error.HTTPError('url', 404, '', {}, None)
        with patch.object(self.mirror, 'api', side_effect=[missing, {}, {'is_private': True}]) as api:
            self.mirror.private_repository('owner', 'uter-agent', 'token')
        self.assertIs(api.call_args_list[1].args[2]['is_private'], True)

    def test_failed_visibility_lookup_never_creates_repository(self):
        denied = urllib.error.HTTPError('url', 403, '', {}, None)
        with patch.object(self.mirror, 'api', side_effect=denied) as api:
            with self.assertRaises(urllib.error.HTTPError):
                self.mirror.private_repository('owner', 'uter-agent', 'token')
        self.assertEqual(api.call_count, 1)
