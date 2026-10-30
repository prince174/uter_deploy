import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.error

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).resolve().parents[1] / 'scripts/publish_images.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class PublicationTests(unittest.TestCase):
    def test_snapshot_identity_must_match_before_publication(self):
        import json, tempfile
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); state = {'kind':'uncommitted_patch', 'baseline_commit':'a'*40, 'patch_sha256':'b'*64}
            for service in ('guardrail', 'agent', 'redis'):
                folder = root / ('protected-'+service) / 'evidence'; folder.mkdir(parents=True)
                (folder/'source-sha.txt').write_text('a'*40+'\n')
                (folder/'source-state.json').write_text(json.dumps(state))
            self.assertEqual(m.snapshot_identity(root), state)
            (root/'protected-agent/evidence/source-state.json').write_text(json.dumps(dict(state, patch_sha256='c'*64)))
            with self.assertRaisesRegex(ValueError, 'differs'): m.snapshot_identity(root)
            (root/'protected-agent/evidence/source-state.json').unlink()
            with self.assertRaisesRegex(ValueError, 'differs'): m.snapshot_identity(root)

    def test_public_verification_uses_empty_separate_docker_config(self):
        with patch.object(m.subprocess, 'run') as run, patch.object(m, 'anonymous_denied') as denied:
            m.verify_visibility('owner/package','ghcr.io/owner/package@sha256:'+'a'*64,'public')
        args=run.call_args.args[0]
        self.assertEqual(args[:2],['docker','--config'])
        self.assertEqual(args[3:5],['pull','ghcr.io/owner/package@sha256:'+'a'*64])
        self.assertTrue(run.call_args.kwargs['check']);denied.assert_not_called()

    def test_visibility_rejects_unknown_mode(self):
        with self.assertRaises(ValueError):m.verify_visibility('owner/package','ref','unknown')

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
