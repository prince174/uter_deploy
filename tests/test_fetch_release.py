import base64
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib import request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import uterctl
from scripts import fetch_release


def drip_worker(connection, path):
    # Simulate a peer that continuously delivers bytes and never finishes.
    try:
        while True:
            with open(path, 'ab') as output:
                output.write(b'x')
            time.sleep(0.02)
    finally:
        connection.close()


class FetchReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.fingerprint = hashlib.sha256(self.public).hexdigest()
        self.images = {name: 'registry.example/' + name + '@sha256:' + 'a' * 64
                       for name in ('guardrail', 'agent', 'redis')}
        self.assets = self.make_assets()

    def make_assets(self, *, archive_images=None, signed_hash=True):
        inputs = io.BytesIO()
        with tarfile.open(fileobj=inputs, mode='w:gz') as archive:
            for name in sorted(('images.json', 'policy.toml', 'model_profiles.toml', 'publication.json')):
                content = json.dumps(archive_images or self.images).encode() if name == 'images.json' else b'{}'
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        input_bytes = inputs.getvalue()
        digest = hashlib.sha256(input_bytes).hexdigest()
        manifest = {'schema': 1, 'config_schema': 1, 'status': 'released', 'version': '0.1.4',
                    'source_commit': 'c' * 40, 'data_epoch': 1, 'upgrade_from': [], 'images': self.images}
        if signed_hash:
            manifest['installation_archive_sha256'] = digest
        bundle = self.root / ('fixture-bundle-' + str(len(list(self.root.iterdir()))))
        (bundle / 'compose').mkdir(parents=True)
        (bundle / 'charts/uter').mkdir(parents=True)
        (bundle / 'scripts').mkdir(parents=True)
        (bundle / 'compose/compose.yaml').write_text('services: {}')
        (bundle / 'charts/uter/Chart.yaml').write_text('name: uter')
        (bundle / 'scripts/extract_release_inputs.py').write_text('# fixture')
        (bundle / 'manifest.json').write_text(json.dumps(manifest))
        inventory = json.dumps(uterctl.inventory(bundle), sort_keys=True).encode()
        (bundle / 'checksums.json').write_bytes(inventory)
        (bundle / 'checksums.sig').write_bytes(base64.b64encode(self.private.sign(inventory)))
        bundle_bytes = io.BytesIO()
        with tarfile.open(fileobj=bundle_bytes, mode='w:gz') as archive:
            archive.add(bundle, arcname='bundle')
        return {'publisher-public.pem': self.public, 'signed-bundle.tar.gz': bundle_bytes.getvalue(),
                'installation-inputs.tar.gz': input_bytes,
                'installation-inputs.tar.gz.sha256': (digest + '  installation-inputs.tar.gz\n').encode()}

    def fake_download(self, url, destination, limit):
        self.assertTrue(url.startswith(fetch_release.RELEASE_BASE + 'deploy-test/'))
        payload = self.assets[Path(url).name]
        self.assertLessEqual(len(payload), limit)
        destination.write_bytes(payload)

    def fetch(self, output=None, fingerprint=None, version='0.1.4'):
        with patch.object(fetch_release, 'download', side_effect=self.fake_download):
            return fetch_release.fetch('deploy-test', fingerprint or self.fingerprint, version, output or self.root/'result')

    def test_real_signature_and_signed_inputs_are_checked(self):
        result = self.fetch()
        out = Path(result['output'])
        self.assertEqual(result['version'], '0.1.4')
        self.assertEqual(json.loads((out/'inputs/images.json').read_text()), self.images)
        self.assertEqual(uterctl.verify(out/'bundle', out/'downloads/publisher-public.pem')['version'], '0.1.4')
        self.assertFalse((out/'INCOMPLETE').exists())
        if os.name == 'posix':
            self.assertEqual((out.stat().st_mode & 0o077), 0)

    def test_fingerprint_and_expected_version_are_mandatory(self):
        for fingerprint, version in [('0'*64, '0.1.4'), (self.fingerprint, '0.1.5')]:
            with self.subTest(version=version, fingerprint=fingerprint):
                with self.assertRaises(ValueError):
                    self.fetch(fingerprint=fingerprint, version=version)
                self.assertFalse((self.root/'result').exists())

    def test_checksum_replacement_does_not_bypass_signed_archive_hash(self):
        payload = self.assets['installation-inputs.tar.gz'] + b'tampered'
        self.assets['installation-inputs.tar.gz'] = payload
        self.assets['installation-inputs.tar.gz.sha256'] = (
            hashlib.sha256(payload).hexdigest() + '  installation-inputs.tar.gz\n').encode()
        with self.assertRaisesRegex(ValueError, 'signed manifest'):
            self.fetch()
        self.assertFalse((self.root/'result').exists())

    def test_signature_and_signed_images_mismatch_fail_closed(self):
        tampered = bytearray(self.assets['signed-bundle.tar.gz'])
        tampered[len(tampered)//2] ^= 1
        self.assets['signed-bundle.tar.gz'] = bytes(tampered)
        with self.assertRaises(Exception):
            self.fetch()
        self.assertFalse((self.root/'result').exists())
        other_images = dict(self.images)
        other_images['redis'] = 'registry.example/redis@sha256:' + 'b'*64
        self.assets = self.make_assets(archive_images=other_images)
        with self.assertRaisesRegex(ValueError, 'images differ'):
            self.fetch()
        self.assertFalse((self.root/'result').exists())

    def test_legacy_release_without_signed_input_hash_is_rejected(self):
        self.assets = self.make_assets(signed_hash=False)
        with self.assertRaisesRegex(ValueError, 'signed manifest'):
            self.fetch()
        self.assertFalse((self.root/'result').exists())

    def test_existing_output_and_symlink_are_not_overwritten(self):
        existing = self.root/'result'
        existing.mkdir()
        (existing/'keep').write_text('original')
        with patch.object(fetch_release, 'download') as download:
            with self.assertRaisesRegex(ValueError, 'already exists'):
                fetch_release.fetch('deploy-test', self.fingerprint, '0.1.4', existing)
            download.assert_not_called()
        self.assertEqual((existing/'keep').read_text(), 'original')
        link = self.root/'link'
        try:
            link.symlink_to(existing, target_is_directory=True)
        except OSError:
            return
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.fetch(output=link)

    def test_incomplete_output_marked_when_final_verification_fails(self):
        original = uterctl.verify
        calls = 0
        def verifier(*args):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise ValueError('simulated post-publication failure')
            return original(*args)
        with patch.object(uterctl, 'verify', side_effect=verifier):
            with self.assertRaisesRegex(ValueError, 'simulated'):
                self.fetch()
        self.assertTrue((self.root/'result/INCOMPLETE').is_file())

    def test_failure_before_atomic_publish_leaves_no_destination(self):
        with patch.object(fetch_release, 'publish_no_replace', side_effect=RuntimeError('interrupted')):
            with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                self.fetch()
        self.assertFalse((self.root/'result').exists())

    def test_atomic_publish_does_not_overwrite_competing_destination(self):
        original = fetch_release.publish_no_replace
        def competitor(stage, output):
            output.mkdir()
            (output/'keep').write_text('competitor')
            original(stage, output)
        with patch.object(fetch_release, 'publish_no_replace', side_effect=competitor):
            with self.assertRaises(OSError):
                self.fetch()
        self.assertEqual((self.root/'result/keep').read_text(), 'competitor')
        self.assertFalse((self.root/'result/INCOMPLETE').exists())

    def test_published_key_rechecked_against_independent_fingerprint(self):
        original = fetch_release.publish_no_replace
        def substitute(stage, output):
            original(stage, output)
            other = Ed25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            (output/'downloads/publisher-public.pem').write_bytes(other)
        with patch.object(fetch_release, 'publish_no_replace', side_effect=substitute):
            with self.assertRaisesRegex(ValueError, 'fingerprint'):
                self.fetch()
        self.assertTrue((self.root/'result/INCOMPLETE').is_file())

    def test_published_input_symlink_fails_closed(self):
        original = fetch_release.publish_no_replace
        def substitute(stage, output):
            original(stage, output)
            victim = output/'inputs/policy.toml'
            victim.unlink()
            victim.symlink_to(self.root/'outside')
        try:
            probe = self.root/'probe-link'
            probe.symlink_to(self.root/'outside')
            probe.unlink()
        except OSError:
            self.skipTest('Symlink creation unavailable')
        with patch.object(fetch_release, 'publish_no_replace', side_effect=substitute):
            with self.assertRaisesRegex(ValueError, 'link or special file'):
                self.fetch()
        self.assertTrue((self.root/'result/INCOMPLETE').is_file())

    @unittest.skipUnless(os.name == 'posix', 'POSIX owner and mode checks')
    def test_writable_parent_is_rejected_before_download(self):
        unsafe = self.root/'unsafe'
        unsafe.mkdir(mode=0o700)
        unsafe.chmod(0o777)
        self.addCleanup(unsafe.chmod, 0o700)
        with patch.object(fetch_release, 'download') as download:
            with self.assertRaisesRegex(ValueError, 'not writable by others'):
                fetch_release.fetch('deploy-test', self.fingerprint, '0.1.4', unsafe/'result')
            download.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'POSIX ancestor checks')
    def test_writable_ancestor_is_rejected_before_download(self):
        unsafe = self.root/'writable-ancestor'
        private = unsafe/'private'
        unsafe.mkdir(mode=0o700)
        private.mkdir(mode=0o700)
        unsafe.chmod(0o777)
        self.addCleanup(unsafe.chmod, 0o700)
        with patch.object(fetch_release, 'download') as download:
            with self.assertRaisesRegex(ValueError, 'untrusted writable ancestor'):
                fetch_release.fetch('deploy-test', self.fingerprint, '0.1.4', private/'result')
            download.assert_not_called()

    def test_hard_deadline_stops_drip_feed_worker(self):
        marker = self.root/'drip'
        start = time.monotonic()
        with self.assertRaises(TimeoutError):
            fetch_release.supervise(drip_worker, (str(marker),), 2)
        self.assertLess(time.monotonic() - start, 8)
        self.assertGreater(marker.stat().st_size, 1)
        size = marker.stat().st_size
        time.sleep(0.15)
        self.assertEqual(marker.stat().st_size, size)

    def test_invalid_tag_and_untrusted_redirects_are_rejected(self):
        for tag in ('../bad', 'bad/tag', '', 'a?b'):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                fetch_release.fetch(tag, self.fingerprint, '0.1.4', self.root/'result')
        for url in ('http://github.com/file', 'https://evil.example/file',
                    'https://user@github.com/file', 'https://github.com:444/file'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                fetch_release.trusted_url(url)
        handler = fetch_release.TrustedRedirect()
        req = request.Request('https://github.com/original')
        with self.assertRaises(ValueError):
            handler.redirect_request(req, None, 302, 'Found', {}, 'https://evil.example/file')

    def test_download_enforces_length_even_without_header(self):
        class Response(io.BytesIO):
            headers = {}
            def geturl(self): return 'https://github.com/asset'
        class Opener:
            def open(self, req, timeout): return Response(b'12345')
        with patch.object(fetch_release.request, 'build_opener', return_value=Opener()):
            with self.assertRaisesRegex(ValueError, 'limit'):
                fetch_release.download('https://github.com/asset', self.root/'asset', 4)


if __name__ == '__main__':
    unittest.main()
