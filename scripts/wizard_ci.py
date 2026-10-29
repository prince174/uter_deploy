#!/usr/bin/env python3
"""Exercise published installation and update wizards only on a disposable runner.

Uses no product sources or external credentials. The fresh-install phase uses a
deterministic HTTP fixture. The upgrade/recovery phase uses isolated Ollama with
real inference. Successful evidence contains categories, not process output.
"""
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'scripts')]
import uterctl
from scripts import adopt_backup_ci as upgrade, extract_release_inputs, extract_signed_bundle
from scripts import installation_ci as installation, release_upgrade_preflight_ci as release
from scripts.verify_release_pair import verify_pair

FINGERPRINT = release.FINGERPRINT
DISALLOWED_TAG = 'deploy-2026.10.28-signed-5'


class CheckFailure(Exception):
    """Fixed safe diagnostic category only."""


def runner_guard(env, root, *, uid=None, platform=None):
    uid = os.geteuid() if uid is None and hasattr(os, 'geteuid') else uid
    platform = sys.platform if platform is None else platform
    if (platform != 'linux' or uid != 0 or env.get('GITHUB_ACTIONS') != 'true'
            or env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or env.get('RUNNER_ENVIRONMENT') != 'github-hosted' or env.get('RUNNER_OS') != 'Linux'
            or env.get('GITHUB_REPOSITORY') != 'prince174/uter_deploy'
            or not env.get('GITHUB_WORKSPACE')
            or Path(env['GITHUB_WORKSPACE']).resolve() != Path(root).resolve()
            or env.get('BACKEND') not in ('compose', 'kubernetes')):
        raise CheckFailure('DISPOSABLE_GITHUB_HOSTED_RUNNER_REQUIRED')


def command(argv, *, timeout=900, input_data=None, env=None):
    try:
        result = subprocess.run([str(x) for x in argv], input=input_data, env=env,
                                capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise CheckFailure('COMMAND_UNAVAILABLE_OR_TIMED_OUT') from None
    return result


def require_success(argv, *, timeout=900, env=None):
    result = command(argv, timeout=timeout, env=env)
    if result.returncode:
        raise CheckFailure('COMMAND_FAILED')
    return result.stdout


def copy_file(source, target, mode=0o600):
    source, target = Path(source), Path(target)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 128 * 1024 * 1024:
        raise CheckFailure('PUBLIC_ASSET_INVALID')
    with source.open('rb') as src, target.open('xb') as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
    os.chmod(target, mode)


def tag_commit(workspace, tag):
    """Resolve the selected public tag without changing global Git configuration."""
    if not release.TAG.fullmatch(tag): raise CheckFailure('TAG_INVALID')
    raw = require_success(['git', '-c', 'safe.directory='+str(workspace), '-C', workspace,
                           'rev-parse', '--verify', 'refs/tags/'+tag+'^{commit}'], timeout=15)
    commit = raw.decode('ascii', 'strict').strip()
    if not re.fullmatch(r'[0-9a-f]{40}', commit): raise CheckFailure('TAG_COMMIT_INVALID')
    return commit


def stage_releases(workspace, stage, old_tag, new_tag):
    """Copy public assets into root-owned staging, then independently reverify."""
    release.check_inputs(old_tag, new_tag, '0.1.5', '0.1.6')
    work = stage/'work'
    (work/'pair').mkdir(parents=True, mode=0o700)
    key_bytes = None
    for side in ('old', 'new'):
        source = workspace/'work/pair'/side
        target = work/'pair'/side
        target.mkdir(mode=0o700)
        for name in ('signed-bundle.tar.gz', 'publisher-public.pem',
                     'installation-inputs.tar.gz', 'installation-inputs.tar.gz.sha256'):
            copy_file(source/name, target/name)
        current_key = (target/'publisher-public.pem').read_bytes()
        if len(current_key) > 4096 or hashlib.sha256(current_key).hexdigest() != FINGERPRINT:
            raise CheckFailure('PUBLISHER_FINGERPRINT_MISMATCH')
        if key_bytes is not None and current_key != key_bytes:
            raise CheckFailure('PUBLISHER_KEYS_DIFFER')
        key_bytes = current_key
        extract_signed_bundle.extract(target/'signed-bundle.tar.gz', target/'publisher-public.pem', target/'bundle')
    old, new = work/'pair/old/bundle', work/'pair/new/bundle'
    public = work/'pair/old/publisher-public.pem'
    previous, current = verify_pair(old, new, public, FINGERPRINT, '0.1.5', '0.1.6')
    if (previous.get('deployment_commit') != tag_commit(workspace, old_tag)
            or current.get('deployment_commit') != tag_commit(workspace, new_tag)):
        raise CheckFailure('SIGNED_TAG_COMMIT_MISMATCH')
    (work/'input').mkdir(mode=0o700)
    for side, label in (('old', 'published-old'), ('new', 'published-new')):
        folder = work/'pair'/side
        extract_release_inputs.extract(folder/'installation-inputs.tar.gz', folder/'installation-inputs.tar.gz.sha256',
                                       work/'input'/label, bundle=folder/'bundle', key=public)
    disallowed = work/'disallowed'
    disallowed.mkdir(mode=0o700)
    copy_file(workspace/'work/disallowed/signed-bundle.tar.gz', disallowed/'signed-bundle.tar.gz')
    extract_signed_bundle.extract(disallowed/'signed-bundle.tar.gz', public, disallowed/'bundle')
    reject = uterctl.verify(disallowed/'bundle', public)
    if reject.get('version') != '0.1.4' or reject.get('deployment_commit') != tag_commit(workspace, DISALLOWED_TAG):
        raise CheckFailure('DISALLOWED_RELEASE_INVALID')
    try:
        uterctl.transition(previous, reject)
    except Exception:
        pass
    else:
        raise CheckFailure('DISALLOWED_TRANSITION_WAS_PERMITTED')
    return {'old': old, 'new': new, 'public': public, 'disallowed': disallowed/'bundle',
            'old_manifest': previous, 'new_manifest': current}


def trusted_tag_checkout(workspace, destination, tag, signed_bundle, manifest):
    """Export the verified tag without accepting archives containing links or traversal.

    The bundle signs the Git commit and inventories the deployment scripts. Git,
    Python and the dependency index remain independent bootstrap trust assumptions.
    """
    if not release.TAG.fullmatch(tag) or tag_commit(workspace, tag) != manifest.get('deployment_commit'):
        raise CheckFailure('CHECKOUT_COMMIT_NOT_SIGNED')
    destination.mkdir(mode=0o700)
    with tempfile.TemporaryFile() as stream:
        result = subprocess.run(['git', '-c', 'safe.directory='+str(workspace), '-C', str(workspace), 'archive', '--format=tar',
                                 'refs/tags/'+tag, '--', 'scripts', 'uterctl.py', 'requirements.txt'],
                                stdout=stream, stderr=subprocess.DEVNULL, timeout=90)
        if result.returncode: raise CheckFailure('PUBLIC_CHECKOUT_EXPORT_FAILED')
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:') as tar:
            seen, total = set(), 0
            for member in tar:
                path = PurePosixPath(member.name)
                total += member.size
                if (path.is_absolute() or '..' in path.parts or '\\' in member.name
                        or member.name in seen or not (member.isdir() or member.isfile())
                        or member.size < 0 or member.size > 32*1024*1024 or total > 256*1024*1024
                        or len(seen) >= 10000):
                    raise CheckFailure('PUBLIC_CHECKOUT_ARCHIVE_INVALID')
                seen.add(member.name)
                target = destination.joinpath(*path.parts)
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with target.open('xb') as output, tar.extractfile(member) as source:
                        shutil.copyfileobj(source, output, 1024*1024)
                    os.chmod(target, 0o600)
    required = ('uterctl.py', 'requirements.txt', 'scripts/install_wizard.py', 'scripts/update_wizard.py')
    for name in required:
        if not (signed_bundle/name).is_file(): raise CheckFailure('SIGNED_CHECKOUT_FILE_MISSING')
    # Every executable script shipped in the signed bundle must match the exact
    # tag checkout. No contents are printed and the signed bundle is immutable.
    files = [Path('uterctl.py'), Path('requirements.txt')]
    files.extend(Path('scripts')/p.name for p in (signed_bundle/'scripts').glob('*.py'))
    for relative in files:
        signed, checked_out = signed_bundle/relative, destination/relative
        if (not checked_out.is_file() or checked_out.is_symlink()
                or hashlib.sha256(signed.read_bytes()).digest() != hashlib.sha256(checked_out.read_bytes()).digest()):
            raise CheckFailure('CHECKOUT_DIFFERS_FROM_SIGNED_BUNDLE')
    for name in ('bootstrap_wizard.py', 'uter_wizard.py'):
        if not (destination/'scripts'/name).is_file():
            raise CheckFailure('CHECKOUT_BOOTSTRAP_MISSING')
    return destination


def install_command(python, wizard, tag, home, fetched, backend, name, url, key_file, *, fingerprint=FINGERPRINT):
    argv = [python, wizard, '--non-interactive', '--release', tag, '--version', '0.1.6',
            '--fingerprint', fingerprint, '--release-dir', fetched, '--backend', backend,
            '--home', home, '--name', name, '--llm-url', url, '--llm-model', 'test-model',
            '--llm-key-file', key_file, '--allow-http-llm', '--guardrail-cpus', '2']
    if backend == 'kubernetes':
        argv += ['--context', 'kind-uter-ci']
    return [str(x) for x in argv]


def bootstrap_command(python, checkout, environment, action, wizard_argv):
    if action not in ('install', 'update') or len(wizard_argv) < 2:
        raise CheckFailure('BOOTSTRAP_ACTION_INVALID')
    expected = Path(checkout)/'scripts'/(action+'_wizard.py')
    if Path(wizard_argv[1]) != expected:
        raise CheckFailure('BOOTSTRAP_WIZARD_MISMATCH')
    return [str(python), '-I', str(Path(checkout)/'scripts/bootstrap_wizard.py'), '--venv-dir',
            str(environment), action, *[str(x) for x in wizard_argv[2:]]]


def update_command(python, old, new, home, public, backups, key, *, target=None, fingerprint=FINGERPRINT, check_only=False):
    argv = [python, new/'scripts/update_wizard.py', '--home', home, '--current-bundle', old,
            '--bundle', target or new, '--publisher-key', public, '--fingerprint', fingerprint,
            '--backup-root', backups, '--backup-key', key]
    argv += ['--check-only'] if check_only else ['--confirm', '--json']
    return [str(x) for x in argv]


class Fixture(BaseHTTPRequestHandler):
    """Bounded, deterministic test upstream; not a real LLM."""
    def reply(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply({'status': 'ok', 'data': [{'id': 'test-model'}]})

    def do_POST(self):
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 <= size <= 65536: raise ValueError
            data = json.loads(self.rfile.read(size))
        except (ValueError, TypeError):
            self.send_error(400)
            return
        text = 'Contact alice@example.com for help.' if 'fixture-output-pii' in json.dumps(data) else 'TechCorp offers software solutions.'
        self.reply({'id': 'fixture-completion', 'object': 'chat.completion', 'model': 'test-model',
                    'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': text}, 'finish_reason': 'stop'}]})

    def log_message(self, *_):
        pass


def gateway_for_kind():
    raw = require_success(['docker', '--context', 'default', 'network', 'inspect', 'kind',
                           '--format', '{{json .IPAM.Config}}'])
    values = json.loads(raw)
    import ipaddress
    addresses = [v.get('Gateway') for v in values if v.get('Gateway') and ':' not in v['Gateway']]
    if len(addresses) != 1 or not ipaddress.ip_address(addresses[0]).is_private:
        raise CheckFailure('KIND_GATEWAY_INVALID')
    return addresses[0]


def option(argv, name):
    try:
        index = [str(x) for x in argv].index(name)
        return str(argv[index+1])
    except (ValueError, IndexError):
        raise CheckFailure('INSTALL_HARNESS_ARGUMENTS_INVALID') from None


def install_failure_category(stderr):
    """Never echo stderr; retain only fixed categories emitted by the wizard."""
    allowed = ('RELEASE_DOWNLOAD_OR_VERIFICATION_FAILED', 'RELEASE_VERIFICATION_FAILED',
               'SIGNED_INPUTS_INVALID', 'HOST_PREFLIGHT_FAILED', 'PREPARE_FAILED',
               'CHECK_FAILED', 'INSTALL_FAILED', 'KUBERNETES_FORWARD_FAILED',
               'ACCEPTANCE_FAILED', 'LOCAL_PORT_UNAVAILABLE', 'INPUT_OR_PATH_INVALID')
    for item in allowed:
        if item.encode('ascii') in stderr:
            return 'INSTALL_WIZARD_' + item
    return 'SIGNED_INSTALL_WIZARD_FAILED'


def cluster_absent(name):
    raw = require_success(['kind', 'get', 'clusters'])
    if name in raw.decode('utf-8').splitlines():
        raise CheckFailure('TEST_CLUSTER_ALREADY_EXISTS')


def fresh_install(stage, staged, checkout, environment, new_tag, backend):
    """Reuse acceptance/cleanup harness while replacing its installer with the signed wizard."""
    driver = stage/'fresh'
    (driver/'work').mkdir(parents=True, mode=0o700)
    (driver/'tests/fixtures').mkdir(parents=True, mode=0o700)
    (driver/'scripts').mkdir(mode=0o700)
    copy_file(ROOT/'tests/fixtures/upstream.py', driver/'tests/fixtures/upstream.py')
    copy_file(ROOT/'scripts/container_acceptance.py', driver/'scripts/container_acceptance.py')
    shutil.copytree(stage/'work/input/published-new', driver/'work/published')
    # A valid privately staged release lets the negative test fail specifically
    # on its intentionally wrong fingerprint, not on a transient network error.
    reused = driver/'work/preverified-release'
    reused.mkdir(mode=0o700)
    shutil.copytree(staged['new'], reused/'bundle')
    (reused/'downloads').mkdir(mode=0o700)
    for name in ('publisher-public.pem', 'installation-inputs.tar.gz', 'installation-inputs.tar.gz.sha256'):
        copy_file(stage/'work/pair/new'/name, reused/'downloads'/name)
    upgrade.assert_compose_project_absent('uter-install-ci')
    if backend == 'kubernetes': cluster_absent('uter-ci')
    original_root, original_run = installation.ROOT, installation.run
    old_env = {key: os.environ.get(key) for key in ('PUBLIC_REGISTRY', 'BACKEND', 'SIGNED_BUNDLE_PATH', 'PUBLISHER_KEY_PATH')}
    os.environ.update({'PUBLIC_REGISTRY': '1', 'BACKEND': backend,
                       'SIGNED_BUNDLE_PATH': str(staged['new']), 'PUBLISHER_KEY_PATH': str(staged['public'])})
    installation.ROOT = driver
    seen = []
    fixture = thread = None
    wizard = staged['new']/'scripts/install_wizard.py'
    if not wizard.is_file() or wizard.is_symlink(): raise CheckFailure('SIGNED_INSTALL_WIZARD_MISSING')
    checkout_wizard = checkout/'scripts/install_wizard.py'

    def dispatch(argv, **kwargs):
        nonlocal fixture, thread
        values = [str(x) for x in argv]
        if len(values) >= 3 and values[1] == str(staged['new']/'scripts/install.py') and values[2] in ('prepare', 'check', 'install'):
            phase = values[2]
            if phase == 'prepare':
                if seen: raise CheckFailure('INSTALL_SEQUENCE_INVALID')
                home = Path(option(argv, '--home'))
                url = option(argv, '--llm-url')
                if backend == 'kubernetes':
                    fixture = ThreadingHTTPServer((gateway_for_kind(), 0), Fixture)
                    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
                    thread.start()
                    url = 'http://' + gateway_for_kind() + ':' + str(fixture.server_port) + '/v1'
                key_file = Path(option(argv, '--llm-key-file'))
                # First prove the real wizard rejects a wrong publisher fingerprint
                # before creating the installation or any project resources.
                invalid = install_command(sys.executable, checkout_wizard, new_tag, home, reused,
                                          backend, 'uter-install-ci', url, key_file, fingerprint='0'*64)
                invalid.append('--reuse-release')
                result = command(bootstrap_command(sys.executable, checkout, environment, 'install', invalid), timeout=900)
                if (result.returncode == 0 or b'RELEASE_VERIFICATION_FAILED' not in result.stderr
                        or home.exists() or home.is_symlink()):
                    raise CheckFailure('WRONG_FINGERPRINT_NOT_REJECTED')
                upgrade.assert_compose_project_absent('uter-install-ci')
                real = install_command(sys.executable, checkout_wizard, new_tag, home, driver/'work/wizard-release',
                                       backend, 'uter-install-ci', url, key_file)
                result = command(bootstrap_command(sys.executable, checkout, environment, 'install', real), timeout=1800)
                if result.returncode:
                    raise CheckFailure(install_failure_category(result.stderr))
                if json.loads((home/'install-state.json').read_text()).get('status') != 'ready':
                    raise CheckFailure('WIZARD_INSTALL_NOT_READY')
                seen.append('prepare')
                return b''
            if seen != (['prepare'] if phase == 'check' else ['prepare', 'check']):
                raise CheckFailure('INSTALL_SEQUENCE_INVALID')
            # The signed wizard already performed these phases itself. Do not
            # invoke the low-level installer a second time against live state.
            seen.append(phase)
            return b''
        return original_run(argv, **kwargs)

    installation.run = dispatch
    try:
        installation.main()
        if seen != ['prepare', 'check', 'install']:
            raise CheckFailure('SIGNED_INSTALL_WIZARD_NOT_EXERCISED')
    finally:
        installation.run, installation.ROOT = original_run, original_root
        for key, value in old_env.items():
            if value is None: os.environ.pop(key, None)
            else: os.environ[key] = value
        if fixture:
            fixture.shutdown(); fixture.server_close(); thread.join(timeout=10)


def state_snapshot(home, backups, key):
    home, backups, key = Path(home), Path(backups), Path(key)
    result = {}
    for name in ('install.json', 'install-state.json', 'state.json', 'backup-operation.json'):
        path = home/name
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    result['backup_files'] = sorted(p.name for p in backups.iterdir()) if backups.exists() else []
    result['backup_key_exists'] = key.exists() or key.is_symlink()
    return result


def workload_snapshot(backend):
    """Use identities only, never read environment, secrets or workload logs."""
    if backend == 'compose':
        result = {}
        for kind in ('container', 'network', 'volume'):
            argv = ['docker', '--context', 'default', kind, 'ls']
            if kind == 'container': argv.append('--all')
            argv += ['--quiet', '--filter', 'label=com.docker.compose.project=uter-upgrade-ci']
            result[kind] = sorted(require_success(argv, timeout=30).decode('ascii').splitlines())
        return result
    if backend == 'kubernetes':
        kube = ['kubectl', '--context', 'kind-uter-upgrade-ci']
        args = ['-n', 'uter-upgrade-ci', 'get', 'deployments,pods,pvc',
                '-o', 'jsonpath={range .items[*]}{.kind}{"/"}{.metadata.uid}{"\\n"}{end}']
        return sorted(require_success(kube+args, timeout=30).decode('utf-8').splitlines())
    raise CheckFailure('BACKEND_INVALID')


def check_disallowed_transition(backend, staged, home, backups, key, checkout, environment):
    """Prove a valid plan succeeds and a forbidden plan fails without mutations."""
    before = state_snapshot(home, backups, key)
    workloads_before = workload_snapshot(backend)
    allowed = update_command(sys.executable, staged['old'], staged['new'], home, staged['public'], backups, key,
                             check_only=True)
    allowed[1] = str(checkout/'scripts/update_wizard.py')
    result = command(bootstrap_command(sys.executable, checkout, environment, 'update', allowed), timeout=900)
    if (result.returncode != 0 or state_snapshot(home, backups, key) != before
            or workload_snapshot(backend) != workloads_before):
        raise CheckFailure('VALID_READ_ONLY_PLAN_FAILED_OR_CHANGED_STATE')
    denied = update_command(sys.executable, staged['old'], staged['new'], home, staged['public'], backups, key,
                            target=staged['disallowed'], check_only=True)
    denied[1] = str(checkout/'scripts/update_wizard.py')
    result = command(bootstrap_command(sys.executable, checkout, environment, 'update', denied), timeout=900)
    if (result.returncode == 0 or state_snapshot(home, backups, key) != before
            or workload_snapshot(backend) != workloads_before):
        raise CheckFailure('DISALLOWED_TRANSITION_NOT_REJECTED')


def check_ci_max_tokens(stage, backend, phase):
    """Verify only the explicit test setting on disposable runner-owned resources."""
    if phase not in ('before_update', 'restored', 'after_update'):
        raise CheckFailure('MAX_TOKENS_PHASE_INVALID')
    try:
        if backend == 'compose':
            folder = 'restored-compose-api' if phase == 'restored' else 'managed'
            path = stage/'work'/folder/'runtime/guardrail.env'
            if path.is_symlink() or path.stat().st_size > 65536:
                raise ValueError
            values = [line.partition('=')[2] for line in path.read_text(encoding='utf-8').splitlines()
                      if line.startswith('UPSTREAM_OPENAI_MAX_TOKENS=')]
            if values != ['64']:
                raise ValueError
        elif backend == 'kubernetes':
            name = 'uter-restored-api-ci' if phase == 'restored' else 'uter-upgrade-ci'
            result = command(['kubectl', '--context', 'kind-uter-upgrade-ci', '-n', name,
                              'get', 'secret', name+'-guardrail-env', '-o',
                              'jsonpath={.data.UPSTREAM_OPENAI_MAX_TOKENS}'], timeout=30)
            if result.returncode or result.stdout != b'NjQ=':
                raise ValueError
        else:
            raise ValueError
    except (OSError, UnicodeError, ValueError):
        raise CheckFailure('MAX_TOKENS_SETTING_NOT_PRESERVED') from None


def update_upgrade(stage, staged, checkout, environment, old_tag, new_tag, backend):
    """Reuse real signed release backup, data, LLM and recovery checks."""
    work = stage/'work'
    cluster_absent('uter-upgrade-ci') if backend == 'kubernetes' else upgrade.assert_compose_project_absent('uter-upgrade-ci')
    if command(['docker', '--context', 'default', 'container', 'inspect', 'uter-real-llm-ci']).returncode == 0:
        raise CheckFailure('TEST_LLM_CONTAINER_ALREADY_EXISTS')
    original_root, original_builder, original_call = upgrade.ROOT, upgrade.published_update_command, upgrade.call
    original_audit = upgrade.audit_and_redis
    import scripts.recovery_compose_api_ci as recover_compose
    import scripts.recovery_kubernetes_api_ci as recover_kubernetes
    old_recovery_roots = recover_compose.ROOT, recover_kubernetes.ROOT
    keys = ('GITHUB_WORKSPACE', 'BACKEND', 'UTER_CI_RELEASE_MODE', 'UTER_CI_STRICT_RUNNER', 'UTER_CI_OLD_VERSION',
            'UTER_CI_NEW_VERSION', 'UTER_CI_OLD_TAG', 'UTER_CI_NEW_TAG', 'OLD_SIGNED_BUNDLE_PATH',
            'NEW_SIGNED_BUNDLE_PATH', 'PUBLISHER_KEY_PATH')
    old_env = {key: os.environ.get(key) for key in keys}
    os.environ.update({'GITHUB_WORKSPACE': str(stage), 'BACKEND': backend, 'UTER_CI_RELEASE_MODE': 'published',
        'UTER_CI_STRICT_RUNNER': 'true', 'UTER_CI_OLD_VERSION': '0.1.5', 'UTER_CI_NEW_VERSION': '0.1.6',
        'UTER_CI_OLD_TAG': old_tag, 'UTER_CI_NEW_TAG': new_tag, 'OLD_SIGNED_BUNDLE_PATH': str(staged['old']),
        'NEW_SIGNED_BUNDLE_PATH': str(staged['new']), 'PUBLISHER_KEY_PATH': str(staged['public'])})
    upgrade.ROOT = recover_compose.ROOT = recover_kubernetes.ROOT = stage
    attempted = []
    checked_settings = []

    def builder(python, old, new, home, public, backups, key):
        argv = update_command(python, old, new, home, public, backups, key)
        argv[1] = str(checkout/'scripts/update_wizard.py')
        return bootstrap_command(python, checkout, environment, 'update', argv)

    def run_checked(argv, **kwargs):
        values = [str(x) for x in argv]
        if len(values) > 2 and values[1:3] == ['-I', str(checkout/'scripts/bootstrap_wizard.py')]:
            if attempted: raise CheckFailure('UPDATE_WIZARD_REPEATED')
            home, backups, key = Path(option(values, '--home')), Path(option(values, '--backup-root')), Path(option(values, '--backup-key'))
            check_disallowed_transition(backend, staged, home, backups, key, checkout, environment)
            attempted.append(True)
        return original_call(argv, **kwargs)

    def audit_checked(argv, env, action):
        phase = {'write': 'before_update', 'read': 'restored', 'check': 'after_update'}.get(action)
        if phase is None or phase in checked_settings:
            raise CheckFailure('MAX_TOKENS_PHASE_INVALID')
        check_ci_max_tokens(stage, backend, phase)
        result = original_audit(argv, env, action)
        checked_settings.append(phase)
        return result

    upgrade.published_update_command, upgrade.call, upgrade.audit_and_redis = builder, run_checked, audit_checked
    try:
        upgrade.main()
        if attempted != [True]: raise CheckFailure('SIGNED_UPDATE_WIZARD_NOT_EXERCISED')
        if checked_settings != ['before_update', 'restored', 'after_update']:
            raise CheckFailure('MAX_TOKENS_PHASE_INCOMPLETE')
        result = json.loads((work/'adopt-backup-evidence/result.json').read_text())
        if (result.get('upgrade') != 'pass' or result.get('full_restore_to_workloads') != 'production recovery command and isolated installation passed'
                or result.get('real_inference') != 'pass'):
            raise CheckFailure('UPGRADE_EVIDENCE_INVALID')
        unchanged = result.get('product_image_digests_unchanged')
        if not isinstance(unchanged, bool): raise CheckFailure('IMAGE_COMPARISON_UNAVAILABLE')
        return unchanged
    finally:
        upgrade.ROOT, upgrade.published_update_command, upgrade.call = original_root, original_builder, original_call
        upgrade.audit_and_redis = original_audit
        recover_compose.ROOT, recover_kubernetes.ROOT = old_recovery_roots
        for key, value in old_env.items():
            if value is None: os.environ.pop(key, None)
            else: os.environ[key] = value


def main():
    runner_guard(os.environ, ROOT)
    old_tag, new_tag, backend = os.environ['OLD_TAG'], os.environ['NEW_TAG'], os.environ['BACKEND']
    release.check_inputs(old_tag, new_tag, '0.1.5', '0.1.6')
    if os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT') not in (None, '', 'default'):
        raise CheckFailure('DOCKER_CONTEXT_INVALID')
    os.environ['DOCKER_CONTEXT'] = 'default'
    # Private, root-owned local files: protected from the runner account while
    # signed wizards validate bundle/key/home paths. Nothing is copied from local stands.
    with tempfile.TemporaryDirectory(prefix='uter-wizard-ci-', dir='/tmp') as temporary:
        stage = Path(temporary)
        staged = stage_releases(ROOT, stage, old_tag, new_tag)
        checkout = trusted_tag_checkout(ROOT, stage/'trusted-checkout', new_tag,
                                        staged['new'], staged['new_manifest'])
        environment = stage/'wizard-venv'
        shutil.copytree(ROOT/'scripts', stage/'scripts', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        copy_file(ROOT/'uterctl.py', stage/'uterctl.py')
        print('Stage: signed fresh installation wizard and acceptance', flush=True)
        fresh_install(stage, staged, checkout, environment, new_tag, backend)
        print('Stage: signed update wizard, backup and real-LLM recovery', flush=True)
        unchanged = update_upgrade(stage, staged, checkout, environment, old_tag, new_tag, backend)
        report = {'backend': backend, 'signed_install_wizard': 'pass', 'wrong_fingerprint_rejected': 'pass',
                  'signed_update_wizard': 'pass', 'disallowed_transition_rejected': 'pass',
                  'encrypted_backup_and_restore': 'pass', 'fresh_llm': 'HTTP fixture',
                  'explicit_max_tokens_setting': 64, 'max_tokens_preserved_in_update_and_restore': 'pass',
                  'upgrade_llm': 'isolated Ollama real inference',
                  'bootstrap_trust': 'signed Git commit; Git/Python/package index independently trusted',
                  'product_image_digests_unchanged': unchanged, 'arbitrary_data_migration': 'not_verified'}
        destination = ROOT/'work/wizard-evidence.json'
        with destination.open('x', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2); stream.write('\n')
        print(json.dumps(report))


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        # Do not print subprocess outputs, runtime config, paths or exception text.
        code = str(exc) if isinstance(exc, CheckFailure) and re.fullmatch(r'[A-Z_]+', str(exc)) else 'WIZARD_CI_FAILED'
        print('Wizard CI failed: ' + code, file=sys.stderr)
        sys.exit(1)
