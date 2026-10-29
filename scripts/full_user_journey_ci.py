"""Disposable hosted-runner test of one published user journey with real LLMs.

The wrapper uses the regular signed fresh-install harness, then runs an independent
0.1.5 installation, signed update, and full recovery while the same LiteLLM/vLLM
remain online. No local operator workloads, product source, or external credentials.
"""
import json
import os
from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts')]
from scripts import wizard_real_llm_ci as real, wizard_ci as common
from scripts import install, adopt_backup_ci, verify_release_pair
from scripts import recovery_compose_api_ci, recovery_kubernetes_api_ci

OLD_TAG = 'deploy-2026.10.29-signed-1'
OLD_VERSION = '0.1.5'
NEW_VERSION = '0.1.6'


def option(argv, name, default=None):
    try:
        index = argv.index(name)
        return str(argv[index + 1])
    except (ValueError, IndexError):
        if default is None:
            raise real.Failure('JOURNEY_ARGUMENT_MISSING') from None
        return default


def run(argv, category, timeout=1800):
    return real.command(argv, category, timeout=timeout)[1]


def parse_update(raw, backups, key):
    matches = []
    for line in raw.decode('utf-8', 'replace').splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and set(value) == {'version', 'backup', 'backup_id', 'backup_key'}:
            matches.append(value)
    if len(matches) != 1 or matches[0]['version'] != NEW_VERSION or matches[0]['backup_key'] != str(key):
        raise real.Failure('UPDATE_OUTPUT_INVALID')
    backup = Path(matches[0]['backup'])
    if not backup.resolve().is_relative_to(backups.resolve()) or not backup.is_dir():
        raise real.Failure('UPDATE_BACKUP_INVALID')
    return backup


def require_inference(before, url, stage):
    after = real.metric(url)
    if after <= before:
        raise real.Failure(stage + '_NO_LLM_TOKENS')
    return after


def smoke_installed(home, backend, context, name, port):
    """Authenticated local acceptance with no proxy, redirect or secret output."""
    forward = real.forward_ready(context, name, port) if backend == 'kubernetes' else None
    try:
        from scripts import smoke_http
        import urllib.request
        opener = urllib.request._opener
        urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({}), real.NoRedirect()))
        try:
            credentials = json.loads((home/'credentials.json').read_text())
            smoke_http.check('http://127.0.0.1:'+str(port), 'admin', credentials['admin'])
        finally:
            urllib.request._opener = opener
    finally:
        real.stop_forward(forward)


def old_install_and_recovery(wizard_argv):
    """Run only after published 0.1.6 wizard has completed on disposable runner."""
    backend = option(wizard_argv, '--backend')
    home = Path(option(wizard_argv, '--home'))
    stage = home.parent
    fresh_name = option(wizard_argv, '--name')
    old_name = fresh_name + '-old'
    context = option(wizard_argv, '--context', 'default')
    release = Path(option(wizard_argv, '--release-dir'))
    key = release / 'downloads/publisher-public.pem'
    new = release / 'bundle'
    old_release = stage / 'old-release'
    old_home = stage / 'old-home'
    backups = stage / 'backups'
    key_dir = stage / 'backup-key'
    backups.mkdir(mode=0o700)
    key_dir.mkdir(mode=0o700)
    backup_key = key_dir / 'backup.key'
    checkout = stage / 'trusted-checkout'
    environment = Path(option(wizard_argv, '--venv-dir'))
    vllm_url = 'http://127.0.0.1:' + str(real.llm.VLLM_PORT)
    old_started = False
    old_manifest = None
    recovery = recovery_compose_api_ci if backend == 'compose' else recovery_kubernetes_api_ci
    old_root = recovery.ROOT
    old_context = recovery.CONTEXT if backend == 'kubernetes' else None
    try:
        print('Stage: fetch old public release and verify signed transition', flush=True)
        run([sys.executable, ROOT/'scripts/fetch_release.py', '--release', OLD_TAG,
             '--version', OLD_VERSION, '--fingerprint', common.FINGERPRINT, '--output', old_release],
            'OLD_RELEASE_FETCH_FAILED', timeout=900)
        old = old_release / 'bundle'
        old_manifest, new_manifest = verify_release_pair.verify_pair(old, new, key, common.FINGERPRINT, OLD_VERSION, NEW_VERSION)
        if old_manifest.get('deployment_commit') != common.tag_commit(ROOT, OLD_TAG):
            raise real.Failure('OLD_RELEASE_IDENTITY_MISMATCH')
        if old_manifest['images'] != new_manifest['images']:
            raise real.Failure('PRODUCT_IMAGES_DIFFER')
        real.require_project_absent(old_name) if backend == 'compose' else None
        installer = old/'scripts/install.py'
        prepare = [sys.executable, installer, 'prepare', '--home', old_home, '--backend', backend,
                   '--name', old_name, '--inputs', old_release/'inputs', '--llm-url', option(wizard_argv, '--llm-url'),
                   '--llm-model', option(wizard_argv, '--llm-model'), '--llm-key-file', option(wizard_argv, '--llm-key-file'),
                   '--allow-http-llm', '--port', '18005', '--guardrail-cpus', '2']
        if backend == 'kubernetes':
            prepare += ['--context', context]
        print('Stage: install prior release against same LiteLLM', flush=True)
        run(prepare, 'OLD_PREPARE_FAILED')
        # 0.1.5 lacks --llm-max-tokens; the operator explicitly sets the same
        # bounded fixture policy as the current signed wizard's --llm-max-tokens 64.
        with (old_home/'runtime/guardrail.env').open('a', encoding='utf-8') as stream:
            stream.write('UPSTREAM_OPENAI_MAX_TOKENS=64\n')
        if backend == 'kubernetes':
            path = old_home/'resources.yaml'
            resources = list(yaml.safe_load_all(path.read_text(encoding='utf-8')))
            secret = next(item for item in resources if item['kind'] == 'Secret'
                          and item['metadata']['name'] == old_name+'-guardrail-env')
            secret['stringData']['UPSTREAM_OPENAI_MAX_TOKENS'] = '64'
            path.write_text(yaml.safe_dump_all(resources), encoding='utf-8')
            os.chmod(path, 0o600)
        run([sys.executable, installer, 'check', '--home', old_home], 'OLD_CHECK_FAILED')
        old_started = True
        run([sys.executable, installer, 'install', '--home', old_home], 'OLD_INSTALL_FAILED')
        cfg = json.loads((old_home/'install.json').read_text())
        if backend == 'compose':
            command, env = install.commands(old_home, cfg)
            audit_command = command + ['exec', '-T', 'guardrail', 'python', '-']
        else:
            audit_command = ['kubectl', '--context', context, '-n', old_name, 'exec', '-i',
                             'deployment/'+old_name+'-guardrail', '--', 'python', '-']
            env = None
        # Force a real request through the old Uter, not merely a model probe.
        metrics = real.metric(vllm_url)
        smoke_installed(old_home, backend, context, old_name, 18005)
        metrics = require_inference(metrics, vllm_url, 'OLD_INSTALL')
        audit_before = adopt_backup_ci.audit_and_redis(audit_command, env, 'write')
        print('Stage: signed upgrade and encrypted backup', flush=True)
        update = common.update_command(sys.executable, old, new, old_home, key, backups, backup_key)
        update[1] = str(checkout/'scripts/update_wizard.py')
        update = common.bootstrap_command(sys.executable, checkout, environment, 'update', update)
        output = run(update, 'SIGNED_UPDATE_FAILED')
        backup = parse_update(output, backups, backup_key)
        state = json.loads((old_home/'state.json').read_text())
        if (state.get('adopted_installer') is not True or state['current']['version'] != NEW_VERSION
                or state['previous']['version'] != OLD_VERSION or state['pending'] is not None):
            raise real.Failure('UPDATED_STATE_INVALID')
        metrics = real.metric(vllm_url)
        smoke_installed(old_home, backend, context, old_name, 18005)
        metrics = require_inference(metrics, vllm_url, 'UPDATED_INSTALLATION')
        audit_after = adopt_backup_ci.audit_and_redis(audit_command, env, 'check')
        if audit_before['first_sha256'] != audit_after['first_sha256']:
            raise real.Failure('UPDATED_AUDIT_MISMATCH')
        # The automatic update backup is from 0.1.5. Register the newly updated
        # runtime and create a separate 0.1.6 snapshot using the documented backup CLI.
        print('Stage: register and create encrypted backup of updated 0.1.6', flush=True)
        identity_dir = stage/'identity'
        identity_dir.mkdir(mode=0o700)
        identity = identity_dir/'runtime.json'
        backup_tool = new/'scripts/backup_installation.py'
        identity_args = ['--home', old_home, '--publisher-key', key, '--identity-file', identity,
                         '--expected-backend', backend, '--expected-name', old_name,
                         '--expected-context', context]
        run([sys.executable, backup_tool, 'register', *identity_args], 'BACKUP_REGISTRATION_FAILED')
        backup_output = run([sys.executable, backup_tool, 'backup', *identity_args,
                             '--backup-root', backups, '--backup-key', backup_key], 'CURRENT_BACKUP_FAILED')
        try:
            current_backup = json.loads(backup_output)
            current_path = Path(current_backup['backup'])
            if (current_backup['version'] != NEW_VERSION or not current_path.is_dir()
                    or not current_path.resolve().is_relative_to(backups.resolve()) or current_path == backup):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise real.Failure('CURRENT_BACKUP_INVALID') from None
        print('Stage: signed recovery of updated 0.1.6 into separate project', flush=True)
        (stage/'work').mkdir(mode=0o700, exist_ok=True)
        recovery.ROOT = stage
        if backend == 'kubernetes':
            recovery.CONTEXT = context
        metrics = real.metric(vllm_url)
        recovery.test(old_home, current_path, backup_key, key, audit_after, recovery_bundle=new)
        restored_state = json.loads((stage/'work'/('restored-'+backend+'-api')/'state.json').read_text())
        if restored_state.get('current', {}).get('version') != NEW_VERSION or restored_state.get('pending') is not None:
            raise real.Failure('RESTORED_VERSION_INVALID')
        require_inference(metrics, vllm_url, 'RECOVERY')
        print('Stage: real LLM update and recovery passed', flush=True)
    finally:
        recovery.ROOT = old_root
        if backend == 'kubernetes':
            recovery.CONTEXT = old_context
        if old_started and backend == 'compose' and old_manifest is not None:
            real.cleanup_compose(old_home, old_name, old_manifest)


def main():
    if os.environ.get('RELEASE_TAG') != 'deploy-2026.10.29-signed-4' or os.environ.get('RELEASE_VERSION') != NEW_VERSION:
        raise real.Failure('RELEASE_SELECTION_INVALID')
    if os.environ.get('LLM_MAX_TOKENS_SCENARIO') != '64':
        raise real.Failure('EXPLICIT_TEST_LLM_SETTING_REQUIRED')
    original = real.run_signed_wizard
    ran = []
    def after_install(argv, timeout=1800):
        vllm_url = 'http://127.0.0.1:' + str(real.llm.VLLM_PORT)
        before = real.metric(vllm_url)
        original(argv, timeout=timeout)
        require_inference(before, vllm_url, 'FRESH_INSTALL')
        old_install_and_recovery([str(value) for value in argv])
        ran.append(True)
    real.run_signed_wizard = after_install
    try:
        real.main()
        if ran != [True]:
            raise real.Failure('FULL_JOURNEY_INCOMPLETE')
        result = {'backend': os.environ['BACKEND'], 'release': NEW_VERSION,
                  'fresh_install_wizard': 'pass', 'old_release': OLD_VERSION,
                  'signed_upgrade': 'pass', 'automatic_pre_update_backup': 'pass',
                  'encrypted_backup_and_full_restore': 'pass', 'restored_backup_version': NEW_VERSION,
                  'synthetic_redis_and_audit': 'pass', 'llm_route': 'same isolated LiteLLM and CPU vLLM',
                  'llm_inference': 'verified with vLLM token counter after old install, update and recovery',
                  'fixture_max_tokens': 64, 'same_product_image_digests': True,
                  'arbitrary_data_migration': 'not verified'}
        output = ROOT/'work/full-user-journey-evidence.json'
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2)
        print(json.dumps(result))
    finally:
        real.run_signed_wizard = original


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        # Errors from network and runtime can include secrets; only fixed types are emitted.
        code = str(exc) if isinstance(exc, real.Failure) else 'JOURNEY_FAILED'
        print('Full user journey failed: ' + code, file=sys.stderr)
        raise SystemExit(1)
