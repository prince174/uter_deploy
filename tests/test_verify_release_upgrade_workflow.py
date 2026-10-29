import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import yaml

import uterctl
from scripts import release_upgrade_preflight_ci as m


class PublishedUpgradePreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                         serialization.PublicFormat.SubjectPublicKeyInfo)
        self.fingerprint = hashlib.sha256(self.public).hexdigest()
        self.images = {name: 'registry.example/' + name + '@sha256:' + 'a' * 64
                       for name in ('guardrail', 'agent', 'redis')}
        self.commits = {'old-tag': 'a' * 40, 'new-tag': 'b' * 40}
        self.make_release('old', '0.1.4', self.commits['old-tag'], [])
        self.make_release('new', '0.1.5', self.commits['new-tag'], ['0.1.4'])

    def make_release(self, side, version, commit, upgrade_from, *, epoch=1, image_override=None):
        folder = self.root / 'work' / 'pair' / side
        folder.mkdir(parents=True)
        (folder / 'publisher-public.pem').write_bytes(self.public)
        images = image_override or self.images
        inputs = {'images.json': json.dumps(images).encode(), 'policy.toml': b'[policy]\n',
                  'model_profiles.toml': b'[profile]\n', 'publication.json': b'{}'}
        archive = folder / 'installation-inputs.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for name, data in inputs.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (folder / 'installation-inputs.tar.gz.sha256').write_text(digest + '  ' + archive.name + '\n')
        manifest = {'schema': 1, 'config_schema': 1, 'status': 'released', 'version': version,
                    'source_commit': 'd' * 40, 'data_epoch': epoch, 'upgrade_from': upgrade_from,
                    'deployment_commit': commit, 'installation_archive_sha256': digest, 'images': images}
        # Minimal signed fixture obeying the same inventory and schema checks.
        bundle = self.root / ('build-' + side)
        for directory in ('compose', 'charts/uter', 'scripts'):
            (bundle / directory).mkdir(parents=True, exist_ok=True)
        (bundle / 'manifest.json').write_text(json.dumps(manifest))
        (bundle / 'compose/compose.yaml').write_text('services: {}\n')
        (bundle / 'charts/uter/Chart.yaml').write_text('apiVersion: v2\nname: test\nversion: 1.0.0\n')
        (bundle / 'scripts/extract_release_inputs.py').write_text('# fixture\n')
        raw = json.dumps(uterctl.inventory(bundle), sort_keys=True, indent=2).encode()
        (bundle / 'checksums.json').write_bytes(raw)
        (bundle / 'checksums.sig').write_bytes(base64.b64encode(self.key.sign(raw)))
        with tarfile.open(folder / 'signed-bundle.tar.gz', 'w:gz') as tar:
            tar.add(bundle, arcname='bundle')
        return manifest

    def verify(self, *, tag_resolver=None):
        resolver = tag_resolver or (lambda root, tag: self.commits[tag])
        with patch.object(m, 'FINGERPRINT', self.fingerprint):
            return m.verify_assets(self.root, 'old-tag', 'new-tag', '0.1.4', '0.1.5', resolve_tag=resolver)

    def test_both_signed_release_archives_and_exact_tag_commits(self):
        result = self.verify()
        self.assertEqual(result['old_version'], '0.1.4')
        self.assertEqual(result['new_version'], '0.1.5')
        self.assertTrue(result['product_image_digests_unchanged'])
        self.assertEqual(result['arbitrary_data_migration'], 'not_verified')
        for side in ('published-old', 'published-new'):
            self.assertEqual(json.loads((self.root / 'work' / 'input' / side / 'images.json').read_text()), self.images)

    def test_both_installation_archives_must_match_signed_hashes(self):
        for side in ('old', 'new'):
            with self.subTest(side=side), tempfile.TemporaryDirectory() as directory:
                previous = self.root
                self.root = Path(directory)
                try:
                    self.make_release('old', '0.1.4', self.commits['old-tag'], [])
                    self.make_release('new', '0.1.5', self.commits['new-tag'], ['0.1.4'])
                    (self.root / 'work' / 'pair' / side / 'installation-inputs.tar.gz').write_bytes(b'tampered')
                    with self.assertRaisesRegex(ValueError, 'signed manifest'):
                        self.verify()
                finally:
                    self.root = previous

    def test_target_tag_commit_must_match_signed_manifest(self):
        with self.assertRaisesRegex(ValueError, 'New signed deployment commit'):
            self.verify(tag_resolver=lambda root, tag: 'c' * 40)

    def test_old_tag_commit_must_match_signed_manifest(self):
        def resolve(root, tag):
            return self.commits[tag] if tag == 'new-tag' else 'c' * 40
        with self.assertRaisesRegex(ValueError, 'Old signed deployment commit'):
            self.verify(tag_resolver=resolve)

    def test_invalid_fingerprint_or_different_key_is_rejected(self):
        (self.root / 'work' / 'pair' / 'new' / 'publisher-public.pem').write_bytes(b'untrusted')
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            self.verify()

    def test_path_or_shell_injection_in_tag_is_rejected(self):
        for bad in ('../../outside', '-flag', 'v1;echo bad', 'tag\ncommand', 'v1?key=secret'):
            with self.subTest(tag=bad), self.assertRaises(ValueError):
                m.check_inputs(bad, 'new-tag', '0.1.4', '0.1.5')
        with self.assertRaises(ValueError):
            m.check_inputs('old', 'new', '١.٢.٣', '0.1.5')

    def test_checksum_filename_cannot_escape_input_directory(self):
        side = self.root / 'work' / 'pair' / 'old'
        (side / 'installation-inputs.tar.gz.sha256').write_text('a' * 64 + '  ../../other\n')
        with self.assertRaisesRegex(ValueError, 'checksum file'):
            self.verify()

    def test_invalid_signed_transition_and_epoch_are_refused(self):
        for upgrade, epoch in [([], 1), (['0.1.4'], 2)]:
            with self.subTest(upgrade=upgrade, epoch=epoch), tempfile.TemporaryDirectory() as directory:
                previous = self.root
                self.root = Path(directory)
                try:
                    self.make_release('old', '0.1.4', self.commits['old-tag'], [])
                    self.make_release('new', '0.1.5', self.commits['new-tag'], upgrade, epoch=epoch)
                    with self.assertRaises(ValueError):
                        self.verify()
                finally:
                    self.root = previous

    def test_changed_image_digest_is_not_reported_as_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = self.root
            self.root = Path(directory)
            try:
                self.make_release('old', '0.1.4', self.commits['old-tag'], [])
                changed = dict(self.images, agent='registry.example/agent@sha256:' + 'b' * 64)
                self.make_release('new', '0.1.5', self.commits['new-tag'], ['0.1.4'], image_override=changed)
                result = self.verify()
                self.assertFalse(result['product_image_digests_unchanged'])
                self.assertEqual(result['arbitrary_data_migration'], 'not_verified')
            finally:
                self.root = previous

    def test_live_entrypoint_refuses_non_ci_without_touching_docker(self):
        env = dict(os.environ)
        env.pop('GITHUB_ACTIONS', None)
        script = Path(__file__).resolve().parents[1] / 'scripts/release_upgrade_preflight_ci.py'
        result = subprocess.run([sys.executable, str(script), '--old-tag', 'old-tag', '--new-tag', 'new-tag',
                                 '--old-version', '0.1.4', '--new-version', '0.1.5'],
                                env=env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Disposable GitHub-hosted Linux runner required', result.stderr)


class WorkflowContractTests(unittest.TestCase):
    def test_dispatch_is_parameterized_no_secrets_and_evidence_excludes_raw_logs(self):
        path = Path(__file__).resolve().parents[1] / '.github/workflows/verify-release-upgrade.yml'
        text = path.read_text(encoding='utf-8')
        workflow = yaml.safe_load(text)
        dispatch = workflow.get('on', workflow.get(True))['workflow_dispatch']
        self.assertEqual(set(dispatch['inputs']), {'old_tag', 'new_tag', 'old_version', 'new_version'})
        self.assertTrue(all(value['required'] is True for value in dispatch['inputs'].values()))
        job = workflow['jobs']['upgrade']
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(job['strategy']['matrix']['backend'], ['compose', 'kubernetes'])
        self.assertNotIn('secrets.', text)
        self.assertNotIn('REGISTRY_TOKEN', text)
        self.assertNotIn('--legacy-unverified', text)
        self.assertIn('RUNNER_ENVIRONMENT', text)
        self.assertIn('credential.helper=', text)
        self.assertIn('GIT_TERMINAL_PROMPT', text)
        self.assertNotIn('actions/checkout@', text)
        steps = job['steps']
        self.assertTrue(any('release_upgrade_preflight_ci.py' in step.get('run', '') for step in steps))
        self.assertTrue(any('scripts/adopt_backup_ci.py' in step.get('run', '') for step in steps))
        for step in steps:
            self.assertNotIn('${{ inputs.', step.get('run', ''))
        artifact = next(step for step in steps if 'upload-artifact@' in step.get('uses', ''))
        paths = artifact['with']['path']
        self.assertIn('result.json', paths)
        self.assertNotIn('logs', paths)


if __name__ == '__main__':
    unittest.main()
