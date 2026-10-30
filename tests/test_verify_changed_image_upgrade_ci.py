import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import verify_changed_image_upgrade_ci as ci


def images(a, b, redis='c'):
    return {'guardrail': 'ghcr.io/example/guard@sha256:'+a*64,
            'agent': 'ghcr.io/example/agent@sha256:'+b*64,
            'redis': 'ghcr.io/example/redis@sha256:'+redis*64}


class ChangedImageUpgradeTests(unittest.TestCase):
    def test_both_product_digests_must_change_but_redis_may_stay(self):
        old = images('a', 'b')
        ci.require_new_images(old, images('d', 'e'))
        for same in (images('a', 'b'), images('a', 'e'), images('d', 'b')):
            with self.assertRaisesRegex(ci.CheckFailure, '^PRODUCT_IMAGE_DIGEST_UNCHANGED$'):
                ci.require_new_images(old, same)

    def test_rejects_missing_and_malformed_digest(self):
        for malformed in ({}, {'guardrail': 'ghcr.io/example:g', 'agent': 42},
                          {'guardrail':'@sha256:'+'f'*64, 'agent':'x@sha256:'+'f'*64}):
            with self.assertRaisesRegex(ci.CheckFailure, '^IMAGE_INPUT_INVALID$'):
                ci.require_new_images(images('a', 'b'), malformed)

    def test_invalid_runner_or_same_images_rejected_before_harness(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for side in ('published-old', 'published-new'):
                path = root/'work/input'/side
                path.mkdir(parents=True)
                (path/'images.json').write_text(json.dumps(images('a', 'b')))
            env = {'UTER_CI_STRICT_RUNNER':'true', 'UTER_CI_RELEASE_MODE':'published',
                   'BACKEND':'compose','UTER_CI_OLD_VERSION':'0.1.6','UTER_CI_NEW_VERSION':'0.1.7'}
            with mock.patch.object(ci.harness, 'runner_guard'), mock.patch.object(ci.harness, 'main') as run, \
                 mock.patch.object(ci, 'ROOT', root), mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(ci.CheckFailure, '^PRODUCT_IMAGE_DIGEST_UNCHANGED$'):
                    ci.main()
                run.assert_not_called()
            env['DOCKER_HOST'] = 'tcp://other-host:2375'
            with mock.patch.object(ci.harness, 'runner_guard'):
                with self.assertRaisesRegex(ci.CheckFailure, '^DISPOSABLE_RUNNER_REQUIRED$'):
                    ci.validate_inputs(env, root)

    def test_restore_requires_expected_version_and_never_logs_backup_secret(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); work = root/'work'; work.mkdir()
            backup = work/'managed-backups'/'id'; backup.mkdir(parents=True)
            env = {'UTER_CI_NEW_VERSION':'0.1.7', 'NEW_SIGNED_BUNDLE_PATH':str(root/'bundle'),
                   'PUBLISHER_KEY_PATH':str(root/'public')}
            output = json.dumps({'version':'0.1.7','backup':str(backup)}).encode()
            def fake_recovery(home, saved, key, public, expected, recovery_bundle=None):
                target = ci.recovery_compose_api_ci.ROOT/'work/restored-compose-api'
                target.mkdir()
                (target/'state.json').write_text(json.dumps({'current':{'version':'0.1.7'},'pending':None}))
                self.assertEqual(saved, backup)
            with mock.patch.object(ci.harness, 'call', side_effect=[b'', output]) as call, \
                 mock.patch.object(ci.recovery_compose_api_ci, 'test', side_effect=fake_recovery):
                ci.restore_post_update(root, 'compose', {'first_sha256':'x'}, env)
            self.assertEqual(call.call_count, 2)
            self.assertEqual(call.call_args_list[0].args[0][2], 'register')
            self.assertEqual(call.call_args_list[1].args[0][2], 'backup')

    def test_wrong_version_in_backup_fails_before_recovery(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root/'work').mkdir()
            backup = root/'work/managed-backups/id'; backup.mkdir(parents=True)
            env = {'UTER_CI_NEW_VERSION':'0.1.7', 'NEW_SIGNED_BUNDLE_PATH':str(root/'bundle'),
                   'PUBLISHER_KEY_PATH':str(root/'public')}
            output = json.dumps({'version':'0.1.6','backup':str(backup)}).encode()
            with mock.patch.object(ci.harness, 'call', side_effect=[b'', output]), \
                 mock.patch.object(ci.recovery_compose_api_ci, 'test') as restore:
                with self.assertRaisesRegex(ci.CheckFailure, '^CURRENT_BACKUP_INVALID$'):
                    ci.restore_post_update(root, 'compose', {}, env)
                restore.assert_not_called()

    def test_never_reports_success_without_executing_post_update_restore(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root/'work').mkdir()
            env = {'BACKEND':'compose','UTER_CI_OLD_VERSION':'0.1.6', 'UTER_CI_NEW_VERSION':'0.1.7'}
            original = ci.harness.audit_and_redis
            with mock.patch.object(ci, 'ROOT', root), mock.patch.object(ci, 'validate_inputs'), \
                 mock.patch.object(ci.harness, 'main'), mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(ci.CheckFailure, '^POST_UPDATE_RESTORE_MISSING$'):
                    ci.main()
            self.assertIs(ci.harness.audit_and_redis, original)
            self.assertFalse((root/'work/changed-image-upgrade-evidence.json').exists())

    def test_checks_hmac_audit_then_post_update_recovery_before_reporting(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); evidence_dir = root/'work/adopt-backup-evidence'
            evidence_dir.mkdir(parents=True)
            (root/'work/managed').mkdir()
            (root/'work/managed/credentials.json').write_text(json.dumps({'openai_ingress_key':'secret-canary'}))
            (evidence_dir/'result.json').write_text(json.dumps({
                'product_image_digests_unchanged':False,'running_images_match_new_release':'pass',
                'audit_chain_and_persistence':'pass','redis_types_and_expiry':'pass',
                'full_restore_to_workloads':'production recovery command and isolated installation passed'}))
            events = []
            def audit(cmd, env, action):
                events.append('hmac-audit-'+action)
                return {'first_sha256':'known-test-hash'}
            def upgrade():
                ci.harness.audit_and_redis([], None, 'write')
                ci.harness.audit_and_redis([], None, 'check')
            def restore(*args):
                events.append('restore')
                ci.harness.audit_and_redis([], None, 'read')
            env = {'BACKEND':'compose','UTER_CI_OLD_VERSION':'0.1.6','UTER_CI_NEW_VERSION':'0.1.7'}
            with mock.patch.object(ci, 'ROOT', root), mock.patch.object(ci, 'validate_inputs'), \
                 mock.patch.object(ci.harness, 'audit_and_redis', side_effect=audit), \
                 mock.patch.object(ci.harness, 'main', side_effect=upgrade), \
                 mock.patch.object(ci.sessions, 'prepare_baseline', return_value={'synthetic':'baseline'}), \
                 mock.patch.object(ci.sessions, 'verify_after_update', return_value={'legacy_alias_history_automatically_accessible':'yes'}), \
                 mock.patch.object(ci.sessions, 'snapshot', return_value={'synthetic':'snapshot'}), \
                 mock.patch.object(ci.sessions, 'verify_restored'), \
                 mock.patch.object(ci, 'restore_post_update', side_effect=restore), \
                 mock.patch.dict(os.environ, env, clear=True):
                ci.main()
            self.assertEqual(events, ['hmac-audit-write', 'hmac-audit-check', 'restore', 'hmac-audit-read'])
            report = json.loads((root/'work/changed-image-upgrade-evidence.json').read_text())
            self.assertTrue(report['guardrail_and_agent_image_digests_changed'])
            self.assertIn('arbitrary migrations not verified', report['data_scope'])

    def test_detected_alias_incompatibility_emits_evidence_but_fails_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); evidence_dir = root/'work/adopt-backup-evidence'
            evidence_dir.mkdir(parents=True)
            (root/'work/managed').mkdir()
            (root/'work/managed/credentials.json').write_text(json.dumps({'openai_ingress_key':'secret-canary'}))
            (evidence_dir/'result.json').write_text(json.dumps({
                'product_image_digests_unchanged':False,'running_images_match_new_release':'pass',
                'audit_chain_and_persistence':'pass','redis_types_and_expiry':'pass',
                'full_restore_to_workloads':'production recovery command and isolated installation passed'}))
            def upgrade():
                ci.harness.audit_and_redis([], None, 'write')
                ci.harness.audit_and_redis([], None, 'check')
            def restore(*args):
                ci.harness.audit_and_redis([], None, 'read')
            env = {'BACKEND':'compose','UTER_CI_OLD_VERSION':'0.1.6','UTER_CI_NEW_VERSION':'0.1.7'}
            with mock.patch.object(ci, 'ROOT', root), mock.patch.object(ci, 'validate_inputs'), \
                 mock.patch.object(ci.harness, 'audit_and_redis', return_value={}), \
                 mock.patch.object(ci.harness, 'main', side_effect=upgrade), \
                 mock.patch.object(ci.sessions, 'prepare_baseline', return_value={}), \
                 mock.patch.object(ci.sessions, 'verify_after_update', return_value={'legacy_alias_history_automatically_accessible':'no'}), \
                 mock.patch.object(ci.sessions, 'snapshot', return_value={}), \
                 mock.patch.object(ci.sessions, 'verify_restored'), \
                 mock.patch.object(ci, 'restore_post_update', side_effect=restore), mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(ci.CheckFailure, '^LEGACY_SESSION_COMPATIBILITY_NOT_PRESERVED$'):
                    ci.main()
            report = json.loads((root/'work/changed-image-upgrade-evidence.json').read_text())
            self.assertEqual(report['session_identity']['legacy_alias_history_automatically_accessible'], 'no')


if __name__ == '__main__':
    unittest.main()
