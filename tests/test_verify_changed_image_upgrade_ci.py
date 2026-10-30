import json
import contextlib
import io
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest import mock

from scripts import verify_changed_image_upgrade_ci as ci


def images(a, b, redis='c'):
    return {'guardrail': 'ghcr.io/example/guard@sha256:'+a*64,
            'agent': 'ghcr.io/example/agent@sha256:'+b*64,
            'redis': 'ghcr.io/example/redis@sha256:'+redis*64}


class ChangedImageUpgradeTests(unittest.TestCase):
    def test_public_assets_reject_symlink_parent_and_symlink_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root/'real').mkdir(); (root/'real/asset').write_text('public')
            (root/'parent-link').symlink_to(root/'real', target_is_directory=True)
            with self.assertRaisesRegex(ci.CheckFailure, '^PUBLIC_ASSET_INVALID$'):
                ci.copy_public_asset(root, 'parent-link/asset', root/'output')
            (root/'file-link').symlink_to(root/'real/asset')
            with self.assertRaisesRegex(ci.CheckFailure, '^PUBLIC_ASSET_INVALID$'):
                ci.copy_public_asset(root, 'file-link', root/'output')
            ci.copy_public_asset(root, 'real/asset', root/'output')
            self.assertEqual((root/'output').read_text(), 'public')

    def test_staged_snapshot_uses_exact_git_commit_not_uncommitted_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); repo = root/'repo'; stage = root/'stage'; repo.mkdir(); stage.mkdir()
            def git(*args):
                return subprocess.check_output(['git','-C',str(repo),*args], stderr=subprocess.DEVNULL).decode().strip()
            git('init','-q'); git('config','user.name','test'); git('config','user.email','test@example.invalid')
            (repo/'scripts').mkdir(); (repo/'scripts/test.py').write_text('trusted')
            (repo/'uterctl.py').write_text('controller')
            (repo/'requirements.txt').write_text('')
            git('add','.'); git('commit','-qm','snapshot'); commit = git('rev-parse','HEAD')
            (repo/'scripts/test.py').write_text('uncommitted')
            ci.export_ci_git_snapshot(repo, stage, commit)
            self.assertEqual((stage/'scripts/test.py').read_text(), 'trusted')
            with self.assertRaisesRegex(ci.CheckFailure, '^CI_SNAPSHOT_INVALID$'):
                ci.export_ci_git_snapshot(repo, root/'other', '0'*40)
            # Untracked Git info/attributes must not silently alter the archive.
            (repo/'.git/info/attributes').write_text('scripts/test.py export-ignore\n')
            other = root/'altered'; other.mkdir()
            with self.assertRaisesRegex(ci.CheckFailure, '^CI_SNAPSHOT_INVALID$'):
                ci.export_ci_git_snapshot(repo, other, commit)

    def test_stage_is_removed_even_if_snapshot_export_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder); observed = []
            for side in ('old','new'):
                path = repo/'work/pair'/side; path.mkdir(parents=True)
                for name in ('signed-bundle.tar.gz','publisher-public.pem','installation-inputs.tar.gz',
                             'installation-inputs.tar.gz.sha256'):
                    (path/name).write_text('test')
            env = {'GITHUB_SHA':'a'*40,'UTER_CI_OLD_TAG':'old','UTER_CI_NEW_TAG':'new',
                   'UTER_CI_OLD_VERSION':'0.1.6','UTER_CI_NEW_VERSION':'0.1.7'}
            def export(_, stage, sha):
                observed.append(stage)
                raise ci.CheckFailure('CI_SNAPSHOT_INVALID')
            with mock.patch.object(ci, 'export_ci_git_snapshot', side_effect=export):
                with self.assertRaisesRegex(ci.CheckFailure, '^CI_SNAPSHOT_INVALID$'):
                    with ci.stage_workspace(repo, env): pass
            self.assertEqual(len(observed),1)
            self.assertFalse(observed[0].exists())

    def test_evidence_rejects_symlink_destination_and_existing_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); stage = root/'stage'; workspace = root/'workspace'
            path = stage/'work/adopt-backup-evidence'; path.mkdir(parents=True)
            (path/'result.json').write_text('{"safe":true}')
            workspace.mkdir(); (workspace/'work').symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ci.CheckFailure, '^EVIDENCE_DESTINATION_INVALID$'):
                ci.publish_safe_evidence(stage, workspace)
            (workspace/'work').unlink(); (workspace/'work').mkdir()
            ci.publish_safe_evidence(stage, workspace)
            self.assertEqual((workspace/'work/adopt-backup-evidence/result.json').read_text(), '{"safe":true}')
            with self.assertRaisesRegex(ci.CheckFailure, '^EVIDENCE_DESTINATION_INVALID$'):
                ci.publish_safe_evidence(stage, workspace)

    def test_private_child_runs_isolated_from_stage_and_filters_untrusted_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); stage = root/'stage'; workspace = root/'workspace'
            (stage/'scripts').mkdir(parents=True); workspace.mkdir()
            script = stage/'scripts/verify_changed_image_upgrade_ci.py'
            script.write_text("import json,os,sys\nfrom pathlib import Path\n"
                              "Path(__file__).parent.joinpath('proof.json').write_text(json.dumps({"
                              "'isolated':sys.flags.isolated,'workspace':os.environ['GITHUB_WORKSPACE']}))\n"
                              "print('raw-secret-canary')\n"
                              "print('Changed image upgrade check failed: LEGACY_SESSION_COMPATIBILITY_NOT_PRESERVED')\n"
                              "sys.exit(1)\n")
            env = {'PATH':os.environ.get('PATH',''), 'PYTHONPATH':'/untrusted', 'BACKEND':'compose'}
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                with self.assertRaisesRegex(ci.CheckFailure, '^LEGACY_SESSION_COMPATIBILITY_NOT_PRESERVED$'):
                    ci.run_private_child(Path(os.sys.executable),stage,workspace,env,timeout=30)
            proof = json.loads((stage/'scripts/proof.json').read_text())
            self.assertEqual(proof, {'isolated':1,'workspace':str(stage)})
            self.assertNotIn('raw-secret-canary', output.getvalue())

    def test_staged_child_reverifies_releases_before_workloads(self):
        env = {'SOURCE_GIT_WORKSPACE':'/trusted-commit-repository', 'UTER_CI_OLD_TAG':'old',
               'UTER_CI_NEW_TAG':'new', 'UTER_CI_OLD_VERSION':'0.1.6', 'UTER_CI_NEW_VERSION':'0.1.7'}
        order = []
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(ci.release,'verify_assets',side_effect=lambda *a,**k:order.append('verify')), \
             mock.patch.object(ci,'run_staged',side_effect=lambda *a:order.append('workloads')):
            ci.staged_main()
        self.assertEqual(order,['verify','workloads'])

    def test_private_python_does_not_inherit_pip_or_python_overrides(self):
        calls = []
        def run(args, **kwargs):
            calls.append((args,kwargs))
            return subprocess.CompletedProcess(args,0)
        with mock.patch.dict(os.environ, {'PATH':'/usr/bin','PYTHONPATH':'/bad','PIP_INDEX_URL':'secret-canary'}, clear=True), \
             mock.patch.object(ci.subprocess,'run',side_effect=run):
            self.assertEqual(ci.prepare_private_python(Path('/safe')),Path('/safe/venv/bin/python'))
        self.assertEqual(calls[0][0][:3], ['/usr/bin/python3','-m','venv'])
        self.assertIn('-I', calls[1][0])
        self.assertNotIn('PYTHONPATH',calls[1][1]['env'])
        self.assertNotIn('PIP_INDEX_URL',calls[1][1]['env'])
        self.assertEqual(calls[1][1]['env']['PIP_CONFIG_FILE'],os.devnull)

    def test_main_keeps_parent_environment_and_exports_evidence_on_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); stage = root/'stage'; stage.mkdir()
            env = {'GITHUB_WORKSPACE':'old-workspace','DOCKER_CONFIG':'old-config',
                   'OLD_SIGNED_BUNDLE_PATH':'old-bundle'}
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(ci, 'ROOT', root), mock.patch.object(ci, 'validate_inputs'), \
                 mock.patch.object(ci, 'stage_workspace', return_value=contextlib.nullcontext(stage)), \
                 mock.patch.object(ci, 'prepare_private_python', return_value=stage/'venv/bin/python'), \
                 mock.patch.object(ci, 'run_private_child', side_effect=ci.CheckFailure('STAGED_CHILD_FAILED')), \
                 mock.patch.object(ci, 'publish_safe_evidence') as publish:
                with self.assertRaisesRegex(ci.CheckFailure, '^STAGED_CHILD_FAILED$'):
                    ci.main()
                self.assertEqual(dict(os.environ),env)
            publish.assert_called_once_with(stage,root)

    def test_both_product_digests_must_change_but_redis_may_stay(self):
        old = images('a', 'b')
        ci.require_new_images(old, images('d', 'e'))
        for same in (images('a', 'b'), images('a', 'e'), images('d', 'b')):
            with self.assertRaisesRegex(ci.CheckFailure, '^PRODUCT_IMAGE_DIGEST_UNCHANGED$'):
                ci.require_new_images(old, same)

    def test_recovery_diagnostics_never_expose_untrusted_error_text(self):
        self.assertEqual(ci.recovery_failure_category(ValueError('Recovery test project already exists')),
                         'CURRENT_RECOVERY_PROJECT_EXISTS')
        self.assertEqual(ci.recovery_failure_category(ValueError('Signed recovery failed; category=unclassified; phase=preparing')),
                         'CURRENT_RECOVERY_UNCLASSIFIED_PREPARING')
        self.assertEqual(ci.recovery_failure_category(ValueError('secret-canary')),
                         'CURRENT_BACKUP_RECOVERY_FAILED')

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
            def fake_recovery(home, saved, key, public, expected, recovery_bundle=None, *, name, port):
                target = ci.recovery_compose_api_ci.ROOT/'work/restored-compose-api'
                target.mkdir()
                (target/'state.json').write_text(json.dumps({'current':{'version':'0.1.7'},'pending':None}))
                self.assertEqual(saved, backup)
                self.assertEqual((name,port),('uter-restored-after-ci',18006))
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
                    ci.run_staged(root)
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
                ci.run_staged(root)
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
                    ci.run_staged(root)
            report = json.loads((root/'work/changed-image-upgrade-evidence.json').read_text())
            self.assertEqual(report['session_identity']['legacy_alias_history_automatically_accessible'], 'no')


if __name__ == '__main__':
    unittest.main()
