"""Disposable CI: verify a signed upgrade between different product images.

The shared upgrade harness checks live Redis types/expiry, HMAC audit integrity,
automatic backup and restoration of the pre-upgrade snapshot.  This wrapper
also backs up the updated installation and restores it under another isolated
project, checking its data and exact version before accepting evidence.
"""
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import adopt_backup_ci as harness
from scripts import recovery_compose_api_ci, recovery_kubernetes_api_ci
from scripts import session_identity_upgrade_ci as sessions
from scripts import wizard_real_llm_ci as runner

VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')


class CheckFailure(Exception):
    """A fixed, non-secret diagnostic category."""


def require_new_images(old, new):
    if not isinstance(old, dict) or not isinstance(new, dict):
        raise CheckFailure('IMAGE_INPUT_INVALID')
    for service in ('guardrail', 'agent'):
        first, second = old.get(service), new.get(service)
        if not isinstance(first, str) or not isinstance(second, str):
            raise CheckFailure('IMAGE_INPUT_INVALID')
        before, separator1, first_digest = first.rpartition('@')
        after, separator2, second_digest = second.rpartition('@')
        if not before or not after or not separator1 or not separator2 or not DIGEST.fullmatch(first_digest) or not DIGEST.fullmatch(second_digest):
            raise CheckFailure('IMAGE_INPUT_INVALID')
        if first_digest == second_digest:
            raise CheckFailure('PRODUCT_IMAGE_DIGEST_UNCHANGED')


def validate_inputs(environ, root):
    harness.runner_guard(environ, root)
    if (environ.get('UTER_CI_STRICT_RUNNER') != 'true'
            or environ.get('UTER_CI_RELEASE_MODE') != 'published'
            or environ.get('BACKEND') not in ('compose', 'kubernetes')
            or environ.get('DOCKER_HOST') or environ.get('DOCKER_CONTEXT') not in (None, '', 'default')):
        raise CheckFailure('DISPOSABLE_RUNNER_REQUIRED')
    old, new = environ.get('UTER_CI_OLD_VERSION', ''), environ.get('UTER_CI_NEW_VERSION', '')
    if not VERSION.fullmatch(old) or not VERSION.fullmatch(new) or old == new:
        raise CheckFailure('RELEASE_VERSION_INVALID')
    for side in ('published-old', 'published-new'):
        path = Path(root)/'work/input'/side/'images.json'
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise CheckFailure('IMAGE_INPUT_INVALID')
    try:
        first = json.loads((Path(root)/'work/input/published-old/images.json').read_text())
        second = json.loads((Path(root)/'work/input/published-new/images.json').read_text())
    except (OSError, ValueError, UnicodeError):
        raise CheckFailure('IMAGE_INPUT_INVALID') from None
    require_new_images(first, second)


def restore_post_update(root, backend, expected_audit, environ):
    work = Path(root)/'work'
    home = work/'managed'
    current = Path(environ['NEW_SIGNED_BUNDLE_PATH'])
    publisher = Path(environ['PUBLISHER_KEY_PATH'])
    backup_root = work/'managed-backups'
    key = work/'managed-backup-keys/backup.key'
    # This directory is new, private and solely owned by this disposable runner.
    identity_dir = work/'new-image-upgrade-identity'
    identity_dir.mkdir(mode=0o700, exist_ok=False)
    identity = identity_dir/'identity.json'
    context = 'kind-uter-upgrade-ci' if backend == 'kubernetes' else 'default'
    tool = current/'scripts/backup_installation.py'
    args = ['--home', home, '--publisher-key', publisher, '--identity-file', identity,
            '--expected-backend', backend, '--expected-name', 'uter-upgrade-ci',
            '--expected-context', context]
    harness.call([sys.executable, tool, 'register', *args])
    result = json.loads(harness.call([sys.executable, tool, 'backup', *args,
                                     '--backup-root', backup_root, '--backup-key', key]))
    backup = Path(result['backup'])
    if (result.get('version') != environ['UTER_CI_NEW_VERSION'] or not backup.is_dir()
            or not backup.resolve().is_relative_to(backup_root.resolve())):
        raise CheckFailure('CURRENT_BACKUP_INVALID')
    # Recovery helper uses its own fixed, ownership-checked destination names.
    # Isolate its local state from its earlier pre-update restoration.
    stage = work/'post-update-recovery'
    (stage/'work').mkdir(mode=0o700, parents=True, exist_ok=False)
    recovery = recovery_kubernetes_api_ci if backend == 'kubernetes' else recovery_compose_api_ci
    previous_root = recovery.ROOT
    try:
        recovery.ROOT = stage
        recovery.test(home, backup, key, publisher, expected_audit, recovery_bundle=current)
        state = json.loads((stage/'work'/('restored-'+backend+'-api')/'state.json').read_text())
        if state.get('current', {}).get('version') != environ['UTER_CI_NEW_VERSION'] or state.get('pending') is not None:
            raise CheckFailure('RESTORED_VERSION_INVALID')
    finally:
        recovery.ROOT = previous_root


def main():
    validate_inputs(os.environ, ROOT)
    original_audit = harness.audit_and_redis
    restored = []
    baseline = []
    identity_report = []
    session_before_backup = []
    session_restored = []

    def checked_audit(cmd, env, action):
        outcome = original_audit(cmd, env, action)
        if action in ('write', 'check'):
            context = 'kind-uter-upgrade-ci'
            forward = runner.forward_ready(context, 'uter-upgrade-ci', 18000) if os.environ['BACKEND'] == 'kubernetes' else None
            try:
                ingress = json.loads((ROOT/'work/managed/credentials.json').read_text())['openai_ingress_key']
                if not isinstance(ingress, str) or not ingress:
                    raise CheckFailure('SESSION_INGRESS_INVALID')
                if action == 'write':
                    if baseline:
                        raise CheckFailure('SESSION_BASELINE_REPEATED')
                    baseline.append(sessions.prepare_baseline(cmd, env, ingress))
                else:
                    if len(baseline) != 1 or identity_report:
                        raise CheckFailure('SESSION_BASELINE_MISSING')
                    identity_report.append(sessions.verify_after_update(cmd, env, ingress, baseline[0]))
                    session_before_backup.append(sessions.snapshot(cmd, env))
            finally:
                runner.stop_forward(forward)
        if action == 'read' and identity_report:
            if len(session_before_backup) != 1 or session_restored:
                raise CheckFailure('SESSION_RESTORE_PHASE_INVALID')
            sessions.verify_restored(cmd, env, session_before_backup[0])
            session_restored.append(True)
        if action == 'check':
            if restored:
                raise CheckFailure('POST_UPDATE_RESTORE_REPEATED')
            print('Stage: backup and restore the updated image version', flush=True)
            restore_post_update(ROOT, os.environ['BACKEND'], outcome, os.environ)
            restored.append(True)
        return outcome

    harness.audit_and_redis = checked_audit
    try:
        harness.main()
        if restored != [True] or session_restored != [True]:
            raise CheckFailure('POST_UPDATE_RESTORE_MISSING')
        path = ROOT/'work/adopt-backup-evidence/result.json'
        evidence = json.loads(path.read_text())
        if (evidence.get('product_image_digests_unchanged') is not False
                or evidence.get('running_images_match_new_release') != 'pass'
                or evidence.get('audit_chain_and_persistence') != 'pass'
                or evidence.get('redis_types_and_expiry') != 'pass'
                or evidence.get('full_restore_to_workloads') != 'production recovery command and isolated installation passed'):
            raise CheckFailure('UPGRADE_EVIDENCE_INVALID')
        report = {'backend': os.environ['BACKEND'], 'old_version': os.environ['UTER_CI_OLD_VERSION'],
                  'new_version': os.environ['UTER_CI_NEW_VERSION'], 'guardrail_and_agent_image_digests_changed': True,
                  'signed_upgrade_and_active_images': 'pass', 'redis_and_hmac_audit': 'pass',
                  'encrypted_backup_before_upgrade_and_restore': 'pass',
                  'encrypted_backup_after_upgrade_and_restore': 'pass',
                  'session_identity': identity_report[0] if len(identity_report) == 1 else 'not verified',
                  'data_scope': 'synthetic Redis types, expiry, HMAC audit; arbitrary migrations not verified'}
        output = ROOT/'work/changed-image-upgrade-evidence.json'
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2)
        print(json.dumps(report))
        if len(identity_report) != 1 or identity_report[0].get('legacy_alias_history_automatically_accessible') != 'yes':
            raise CheckFailure('LEGACY_SESSION_COMPATIBILITY_NOT_PRESERVED')
    finally:
        harness.audit_and_redis = original_audit


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        code = str(exc) if isinstance(exc, (CheckFailure, sessions.SessionCheckFailure)) and re.fullmatch(r'[A-Z_0-9]+', str(exc)) else 'CHANGED_IMAGE_UPGRADE_FAILED'
        print('Changed image upgrade check failed: '+code, file=sys.stderr)
        raise SystemExit(1)
