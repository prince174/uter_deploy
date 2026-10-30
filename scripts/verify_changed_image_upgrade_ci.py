"""Disposable CI: verify a signed upgrade between different product images.

The shared upgrade harness checks live Redis types/expiry, HMAC audit integrity,
automatic backup and restoration of the pre-upgrade snapshot.  This wrapper
also backs up the updated installation and restores it under another isolated
project, checking its data and exact version before accepting evidence.
"""
import json
import hashlib
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import adopt_backup_ci as harness
from scripts import recovery_compose_api_ci, recovery_kubernetes_api_ci
from scripts import session_identity_upgrade_ci as sessions
from scripts import wizard_real_llm_ci as runner
from scripts import wizard_ci as common
from scripts import release_upgrade_preflight_ci as release

VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')


class CheckFailure(Exception):
    """A fixed, non-secret diagnostic category."""


def copy_public_asset(workspace, relative, destination):
    """Copy only bounded regular files under the checkout, never symlinks."""
    base = Path(workspace).resolve(strict=True)
    current = base
    for part in Path(relative).parts:
        if part in ('', '.', '..'):
            raise CheckFailure('PUBLIC_ASSET_INVALID')
        current = current/part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise CheckFailure('PUBLIC_ASSET_INVALID')
    if not stat.S_ISREG(info.st_mode) or info.st_size > 128*1024*1024:
        raise CheckFailure('PUBLIC_ASSET_INVALID')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(current, flags)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_ino != info.st_ino
                or opened.st_dev != info.st_dev or opened.st_size != info.st_size):
            raise CheckFailure('PUBLIC_ASSET_INVALID')
        with os.fdopen(fd, 'rb', closefd=False) as source, destination.open('xb') as target:
            shutil.copyfileobj(source, target, 1024*1024)
    finally:
        os.close(fd)
    os.chmod(destination, 0o600)


def export_ci_git_snapshot(workspace, stage, expected_sha):
    if not re.fullmatch(r'[0-9a-f]{40}', expected_sha or ''):
        raise CheckFailure('CI_SNAPSHOT_INVALID')
    git = ['git', '-c', 'safe.directory='+str(workspace), '-C', str(workspace)]
    try:
        actual = subprocess.check_output(git+['rev-parse', '--verify', 'HEAD^{commit}'],
                                         stderr=subprocess.DEVNULL, timeout=15, text=True).strip()
        if actual != expected_sha:
            raise CheckFailure('CI_SNAPSHOT_INVALID')
        raw = subprocess.check_output(git+['ls-tree', '-r', '-z', expected_sha, '--',
                                           'scripts', 'uterctl.py', 'requirements.txt'],
                                      stderr=subprocess.DEVNULL, timeout=30)
        expected = {}
        for record in raw.split(b'\0'):
            if not record:
                continue
            header, raw_name = record.split(b'\t', 1)
            mode, kind, blob = header.decode('ascii').split(' ')
            name = raw_name.decode('utf-8')
            if (mode not in ('100644', '100755') or kind != 'blob'
                    or not re.fullmatch(r'[0-9a-f]{40}', blob) or name in expected):
                raise CheckFailure('CI_SNAPSHOT_INVALID')
            expected[name] = blob
        if not expected or not {'uterctl.py', 'requirements.txt'}.issubset(expected):
            raise CheckFailure('CI_SNAPSHOT_INVALID')
        seen = set()
        with tempfile.TemporaryFile() as stream:
            process = subprocess.run(git+['archive', '--format=tar', expected_sha, 'scripts', 'uterctl.py', 'requirements.txt'],
                                     stdout=stream, stderr=subprocess.DEVNULL, timeout=60)
            if process.returncode:
                raise CheckFailure('CI_SNAPSHOT_INVALID')
            stream.seek(0)
            with tarfile.open(fileobj=stream, mode='r:') as archive:
                entries = archive.getmembers()
                if len(entries) > 10000:
                    raise CheckFailure('CI_SNAPSHOT_INVALID')
                for item in entries:
                    parts = Path(item.name).parts
                    if (not parts or any(x in ('', '.', '..') for x in parts)
                            or not (item.isdir() or item.isfile()) or item.size > 128*1024*1024
                            or not (parts[0] == 'scripts' or item.name in ('uterctl.py', 'requirements.txt'))):
                        raise CheckFailure('CI_SNAPSHOT_INVALID')
                    target = stage.joinpath(*parts)
                    if item.isdir():
                        target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    else:
                        if item.name not in expected or item.name in seen:
                            raise CheckFailure('CI_SNAPSHOT_INVALID')
                        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        digest = hashlib.sha1(b'blob '+str(item.size).encode()+b'\0')
                        with archive.extractfile(item) as source, target.open('xb') as dest:
                            while True:
                                chunk = source.read(1024*1024)
                                if not chunk:
                                    break
                                digest.update(chunk); dest.write(chunk)
                        if digest.hexdigest() != expected[item.name]:
                            raise CheckFailure('CI_SNAPSHOT_INVALID')
                        seen.add(item.name)
                        os.chmod(target, 0o600)
        if seen != set(expected):
            raise CheckFailure('CI_SNAPSHOT_INVALID')
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError):
        raise CheckFailure('CI_SNAPSHOT_INVALID') from None


@contextmanager
def stage_workspace(workspace, environ):
    """Stage public Git snapshot and release archives in a private checkout."""
    with tempfile.TemporaryDirectory(prefix='uter-changed-image-', dir='/tmp') as folder:
        stage = Path(folder)
        info = stage.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise CheckFailure('PRIVATE_STAGE_INVALID')
        export_ci_git_snapshot(workspace, stage, environ.get('GITHUB_SHA', ''))
        for side in ('old', 'new'):
            target = stage/'work/pair'/side
            target.mkdir(mode=0o700, parents=True)
            for name in ('signed-bundle.tar.gz', 'publisher-public.pem',
                         'installation-inputs.tar.gz', 'installation-inputs.tar.gz.sha256'):
                copy_public_asset(workspace, Path('work/pair')/side/name, target/name)
        yield stage


def prepare_private_python(stage):
    """Create private Python tooling using only the pinned staged requirements."""
    clean = {name:value for name,value in os.environ.items()
             if not name.startswith(('PIP_', 'PYTHON'))}
    clean['PIP_CONFIG_FILE'] = os.devnull
    try:
        created = subprocess.run(['/usr/bin/python3', '-m', 'venv', '--copies', str(stage/'venv')],
                                 env=clean, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        if created.returncode:
            raise CheckFailure('PRIVATE_PYTHON_SETUP_FAILED')
        python = stage/'venv/bin/python'
        installed = subprocess.run([str(python), '-I', '-m', 'pip', 'install', '-r', str(stage/'requirements.txt')],
                                   env=clean, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
        if installed.returncode:
            raise CheckFailure('PRIVATE_DEPENDENCY_SETUP_FAILED')
        return python
    except (OSError, subprocess.TimeoutExpired):
        raise CheckFailure('PRIVATE_PYTHON_SETUP_FAILED') from None


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
    try:
        harness.call([sys.executable, tool, 'register', *args])
    except Exception:
        raise CheckFailure('CURRENT_BACKUP_REGISTRATION_FAILED') from None
    try:
        raw_result = harness.call([sys.executable, tool, 'backup', *args,
                                   '--backup-root', backup_root, '--backup-key', key])
    except Exception:
        raise CheckFailure('CURRENT_BACKUP_COMMAND_FAILED') from None
    try:
        result = json.loads(raw_result)
    except (ValueError, TypeError, UnicodeError):
        raise CheckFailure('CURRENT_BACKUP_OUTPUT_INVALID') from None
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
        try:
            recovery.test(home, backup, key, publisher, expected_audit, recovery_bundle=current)
        except sessions.SessionCheckFailure:
            raise
        except Exception:
            raise CheckFailure('CURRENT_BACKUP_RECOVERY_FAILED') from None
        try:
            state = json.loads((stage/'work'/('restored-'+backend+'-api')/'state.json').read_text())
        except (OSError, ValueError, UnicodeError):
            raise CheckFailure('RESTORED_STATE_UNAVAILABLE') from None
        if state.get('current', {}).get('version') != environ['UTER_CI_NEW_VERSION'] or state.get('pending') is not None:
            raise CheckFailure('RESTORED_VERSION_INVALID')
    finally:
        recovery.ROOT = previous_root


def run_staged(work_root):
    validate_inputs(os.environ, work_root)
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
                ingress = json.loads((work_root/'work/managed/credentials.json').read_text())['openai_ingress_key']
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
            restore_post_update(work_root, os.environ['BACKEND'], outcome, os.environ)
            restored.append(True)
        return outcome

    harness.audit_and_redis = checked_audit
    try:
        harness.main()
        if restored != [True] or session_restored != [True]:
            raise CheckFailure('POST_UPDATE_RESTORE_MISSING')
        path = work_root/'work/adopt-backup-evidence/result.json'
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
        output = work_root/'work/changed-image-upgrade-evidence.json'
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2)
        print(json.dumps(report))
        if len(identity_report) != 1 or identity_report[0].get('legacy_alias_history_automatically_accessible') != 'yes':
            raise CheckFailure('LEGACY_SESSION_COMPATIBILITY_NOT_PRESERVED')
    finally:
        harness.audit_and_redis = original_audit


def publish_safe_evidence(stage, workspace):
    """Copy only allowlisted, non-secret JSON evidence from the private stage."""
    base = workspace.resolve(strict=True)
    if workspace.is_symlink():
        raise CheckFailure('EVIDENCE_DESTINATION_INVALID')
    for relative in ('work/adopt-backup-evidence/result.json',
                     'work/adopt-backup-evidence/kubernetes-categories.json',
                     'work/changed-image-upgrade-evidence.json'):
        source = stage/relative
        if not source.exists():
            continue
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 1024*1024:
            raise CheckFailure('EVIDENCE_SOURCE_INVALID')
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0)
        parent_fd = os.open(base, flags)
        try:
            for part in Path(relative).parts[:-1]:
                try:
                    os.mkdir(part, mode=0o755, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(part, flags, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
            output_fd = os.open(Path(relative).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                getattr(os, 'O_NOFOLLOW', 0), 0o644, dir_fd=parent_fd)
            with os.fdopen(output_fd, 'wb') as target, source.open('rb') as data:
                shutil.copyfileobj(data, target, 1024*1024)
                os.fchmod(target.fileno(), 0o644)
        except OSError:
            raise CheckFailure('EVIDENCE_DESTINATION_INVALID') from None
        finally:
            os.close(parent_fd)


def staged_main():
    """Entry point executing exclusively from the owner-private Git snapshot."""
    workspace = Path(os.environ['SOURCE_GIT_WORKSPACE'])
    try:
        release.verify_assets(ROOT, os.environ['UTER_CI_OLD_TAG'], os.environ['UTER_CI_NEW_TAG'],
                              os.environ['UTER_CI_OLD_VERSION'], os.environ['UTER_CI_NEW_VERSION'],
                              resolve_tag=lambda _, tag: common.tag_commit(workspace, tag))
    except Exception:
        raise CheckFailure('STAGED_RELEASE_VERIFICATION_FAILED') from None
    run_staged(ROOT)


def run_private_child(python, stage, workspace, environ, timeout=3300):
    names = ('GITHUB_ACTIONS','GITHUB_SHA','RUNNER_ENVIRONMENT','RUNNER_OS','BACKEND',
             'UTER_CI_RELEASE_MODE','UTER_CI_STRICT_RUNNER','UTER_CI_OLD_VERSION',
             'UTER_CI_NEW_VERSION','UTER_CI_OLD_TAG','UTER_CI_NEW_TAG','LANG','HOME')
    child_env = {key:environ[key] for key in names if key in environ}
    child_env.update({'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'GITHUB_WORKSPACE':str(stage), 'SOURCE_GIT_WORKSPACE':str(workspace),
        'OLD_SIGNED_BUNDLE_PATH':str(stage/'work/pair/old/bundle'),
        'NEW_SIGNED_BUNDLE_PATH':str(stage/'work/pair/new/bundle'),
        'PUBLISHER_KEY_PATH':str(stage/'work/pair/old/publisher-public.pem')})
    try:
        proc = subprocess.Popen([str(python), '-I', '-B', str(stage/'scripts/verify_changed_image_upgrade_ci.py'),
                                 '--staged'], env=child_env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    except OSError:
        raise CheckFailure('STAGED_CHILD_START_FAILED') from None
    def stop_child():
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
    data = bytearray(); deadline = time.monotonic()+timeout
    try:
        while True:
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                stop_child()
                raise CheckFailure('STAGED_CHILD_TIMEOUT_CLEANUP_INCONCLUSIVE')
            ready, _, _ = select.select([proc.stdout], [], [], min(remaining, 1))
            if ready:
                chunk = os.read(proc.stdout.fileno(), 8192)
                if not chunk: break
                data.extend(chunk)
                if len(data) > 1024*1024: del data[:-1024*1024]
        status = proc.wait(timeout=max(0.01, deadline-time.monotonic()))
    except subprocess.TimeoutExpired:
        stop_child()
        raise CheckFailure('STAGED_CHILD_TIMEOUT_CLEANUP_INCONCLUSIVE') from None
    except BaseException:
        if proc.poll() is None:
            stop_child()
        raise
    finally:
        proc.stdout.close()
    allowed_stages = {
        'Stage: start isolated Ollama', 'Stage: download and verify model',
        'Stage: prepare isolated runtime', 'Stage: real LLM and persistent state before update',
        'Stage: automatic adoption, encrypted backup and upgrade',
        'Stage: real LLM and persistent state after update',
        'Stage: backup and restore the updated image version',
        'Production Compose recovery command: full new instance and state preservation PASS',
        'Production Kubernetes recovery command: full new instance and state preservation PASS',
    }
    code = None
    for line in data.decode('utf-8','replace').splitlines():
        if line in allowed_stages:
            print(line, flush=True)
        match = re.fullmatch(r'Changed image upgrade check failed: ([A-Z_0-9]{1,100})', line)
        if match:
            code = match.group(1)
    if status:
        raise CheckFailure(code or 'STAGED_CHILD_FAILED')


def main():
    validate_inputs(os.environ, ROOT)
    with stage_workspace(ROOT, os.environ) as stage:
        try:
            python = prepare_private_python(stage)
            run_private_child(python, stage, ROOT, os.environ)
        finally:
            publish_safe_evidence(stage, ROOT)


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--staged']:
            staged_main()
        elif not sys.argv[1:]:
            main()
        else:
            raise CheckFailure('ARGUMENT_INVALID')
    except (Exception, KeyboardInterrupt) as exc:
        code = str(exc) if isinstance(exc, (CheckFailure, sessions.SessionCheckFailure)) and re.fullmatch(r'[A-Z_0-9]+', str(exc)) else 'CHANGED_IMAGE_UPGRADE_FAILED'
        print('Changed image upgrade check failed: '+code, file=sys.stderr)
        raise SystemExit(1)
