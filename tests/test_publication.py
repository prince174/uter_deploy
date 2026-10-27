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
