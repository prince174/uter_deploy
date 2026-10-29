"""Exercise candidate scheduled backup and public-release recovery on isolated CI.

Only public signed Uter images are used. The upstream is a deterministic HTTP
fixture, not a real LLM. No scheduler is installed and no local daemon is used.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from urllib import error, request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uterctl
from scripts import backup_crypto, backup_store
from scripts.corporate_tls_ci import (NODE_IMAGE, PUBLISHER_FINGERPRINT, StageError, call,
                                      ci_only, cleanup, free_port, gateway_address, terminate)
from scripts.extract_release_inputs import extract as extract_inputs
from scripts.smoke_http import check as smoke


SOURCE_PORT = 18083
RECOVERY_PORT = 18084


def copy_verified_release(work, destination):
    public = work/'download/publisher-public.pem'
    if hashlib.sha256(public.read_bytes()).hexdigest() != PUBLISHER_FINGERPRINT:
        raise StageError('PUBLISHER_FINGERPRINT_MISMATCH')
    source = work/'signed'
    manifest = uterctl.verify(source, public)
    bundle = destination/'bundle'
    shutil.copytree(source, bundle)
    trusted = destination/'publisher-public.pem'
    trusted.write_bytes(public.read_bytes())
    trusted.chmod(0o600)
    if hashlib.sha256(trusted.read_bytes()).hexdigest() != PUBLISHER_FINGERPRINT:
        raise StageError('PUBLISHER_FINGERPRINT_MISMATCH')
    if uterctl.verify(bundle, trusted) != manifest:
        raise StageError('COPIED_RELEASE_INVALID')
    inputs = destination/'inputs'
    extract_inputs(work/'download/installation-inputs.tar.gz',
                   work/'download/installation-inputs.tar.gz.sha256', inputs,
                   bundle=bundle, key=trusted)
    if json.loads((inputs/'images.json').read_text()) != manifest['images']:
        raise StageError('SIGNED_IMAGE_MISMATCH')
    return bundle, trusted, inputs, manifest


def wait_fixture(base, process):
    opener = request.build_opener(request.ProxyHandler({}))
    for _ in range(60):
        if process.poll() is not None:
            raise StageError('FIXTURE_EXITED')
        try:
            with opener.open(base + '/health', timeout=2) as response:
                if response.status == 200:
                    return
        except error.HTTPError as exc:
            exc.close()
        except (error.URLError, TimeoutError, OSError):
            pass
        time.sleep(1)
    raise StageError('FIXTURE_NOT_READY')


def wait_ready(port):
    opener = request.build_opener(request.ProxyHandler({}))
    for _ in range(90):
        try:
            with opener.open('http://127.0.0.1:' + str(port) + '/ready', timeout=5) as response:
                value = json.load(response)
                if response.status == 200 and value.get('ready') is True and value.get('upstream') is True:
                    return
        except error.HTTPError as exc:
            exc.close()
        except (error.URLError, TimeoutError, OSError, ValueError):
            pass
        time.sleep(2)
    raise StageError('UTER_READY_TIMEOUT')


def source_smoke(backend, cluster, name, port, home, env):
    forward = None
    try:
        if backend == 'kubernetes':
            forward = subprocess.Popen(['kubectl', '--context', 'kind-' + cluster, '-n', name,
                'port-forward', 'service/' + name + '-guardrail', str(port) + ':8000', '--address', '127.0.0.1'],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_ready(port)
        credentials = json.loads((home/'credentials.json').read_text())
        smoke('http://127.0.0.1:' + str(port), 'admin', credentials['admin'])
    finally:
        terminate(forward)


def workload_ids(backend, name, cluster, env):
    if backend == 'compose':
        data = call(['docker', '--context', 'default', 'ps', '-q',
                     '--filter', 'label=com.docker.compose.project=' + name], 'WORKLOAD_QUERY_FAILED', env=env)
        ids = sorted(data.decode().splitlines())
        if len(ids) != 3:
            raise StageError('EXPECTED_THREE_RUNNING_CONTAINERS')
        return ids
    kube = ['kubectl', '--context', 'kind-' + cluster, '-n', name]
    result = []
    for service in ('guardrail', 'agent', 'redis'):
        raw = call(kube + ['get', 'deployment', name + '-' + service, '-o', 'json'],
                   'WORKLOAD_QUERY_FAILED', env=env)
        deployment = json.loads(raw)
        if deployment['spec'].get('replicas', 1) != 1 or deployment.get('status', {}).get('readyReplicas') != 1:
            raise StageError('EXPECTED_READY_DEPLOYMENT')
        result.append(deployment['metadata']['uid'])
    return result


def check_data(backend, name, cluster, env, action):
    if action not in ('write', 'verify'):
        raise ValueError('Invalid data check action')
    # Sent through stdin; secrets are read only inside Guardrail and never printed.
    code = '''import hashlib,json,os,redis\nfrom pathlib import Path\nfrom audit_logger import verify_audit_set\nmode=MODE\naudit=Path('/var/lib/uter/audit/audit.jsonl')\nkey_path=os.environ.get('AUDIT_LOG_HMAC_KEY_FILE')\nkey=Path(key_path).read_text().strip() if key_path else os.environ['AUDIT_LOG_HMAC_KEY']\nverify_audit_set(audit,hmac_key=key)\nlines=audit.read_bytes().splitlines()\nif not lines: raise ValueError('empty audit')\npassword_path=os.environ.get('REDIS_PASSWORD_FILE')\npassword=Path(password_path).read_text().strip() if password_path else os.environ['REDIS_PASSWORD']\nr=redis.Redis(host=os.environ['REDIS_HOST'],password=password,decode_responses=True)\nr1=redis.Redis(host=os.environ['REDIS_HOST'],password=password,decode_responses=True,db=1)\nif mode=='write':\n r.set('ci:scheduled:string','synthetic-value')\n r.hset('ci:scheduled:hash',mapping={'value':'preserved'})\n r.delete('ci:scheduled:list','ci:scheduled:set','ci:scheduled:zset')\n r.rpush('ci:scheduled:list','one','two')\n r.sadd('ci:scheduled:set','one','two')\n r.zadd('ci:scheduled:zset',{'one':1,'two':2})\n r.set('ci:scheduled:ttl','alive',ex=3600)\n r1.set('ci:scheduled:db1','preserved')\nassert r.get('ci:scheduled:string')=='synthetic-value'\nassert r.hgetall('ci:scheduled:hash')=={'value':'preserved'}\nassert r.lrange('ci:scheduled:list',0,-1)==['one','two']\nassert r.smembers('ci:scheduled:set')=={'one','two'}\nassert r.zrange('ci:scheduled:zset',0,-1,withscores=True)==[('one',1.0),('two',2.0)]\nassert r.get('ci:scheduled:ttl')=='alive' and 0<r.ttl('ci:scheduled:ttl')<=3600\nassert r1.get('ci:scheduled:db1')=='preserved'\nprint(json.dumps({'audit_first':hashlib.sha256(lines[0]).hexdigest(),'audit_lines':len(lines)}))\n'''.replace('MODE', repr(action)).encode()
    if backend == 'compose':
        command = ['docker', '--context', 'default', 'exec', '-i', name + '-guardrail-1', 'python', '-']
    else:
        command = ['kubectl', '--context', 'kind-' + cluster, '-n', name, 'exec', '-i',
                   'deployment/' + name + '-guardrail', '--', 'python', '-']
    return json.loads(call(command, 'SYNTHETIC_DATA_CHECK_FAILED', env=env, input_data=code))


def check_audit_continuity(before, after):
    if (before.get('audit_first') != after.get('audit_first') or
            not isinstance(after.get('audit_lines'), int) or after['audit_lines'] < before['audit_lines']):
        raise StageError('AUDIT_CONTINUITY_FAILED')


def rejected_backup(argv, env):
    try:
        result = subprocess.run([str(item) for item in argv], env=env, capture_output=True, timeout=60)
        payload = json.loads(result.stderr)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise StageError('BAD_IDENTITY_TEST_FAILED') from None
    if result.returncode == 0 or payload != {'result': 'failed', 'code': 'RUNTIME_IDENTITY_MISMATCH'}:
        raise StageError('BAD_IDENTITY_NOT_REJECTED')


def main():
    ci_only()
    backend = os.environ.get('BACKEND')
    if backend not in ('compose', 'kubernetes'):
        raise StageError('BACKEND_INVALID')
    work = Path(os.environ['TEST_WORKSPACE']).resolve(strict=True)
    python = work/'venv/bin/python'
    name = 'uter-bk-' + secrets.token_hex(6)
    recovered_name = name + '-restored'
    cluster = name + '-kind'
    fixture = None
    cluster_attempted = source_attempted = recovery_attempted = False
    with tempfile.TemporaryDirectory(prefix='uter-scheduled-backup-ci-', dir='/tmp') as temporary:
        temporary = Path(temporary)
        bundle, trusted, inputs, manifest = copy_verified_release(work, temporary)
        home, recovered = temporary/'home', temporary/'recovered'
        backups, keys = temporary/'backups', temporary/'keys'
        backups.mkdir(mode=0o700)
        keys.mkdir(mode=0o700)
        docker_config = temporary/'docker-config'
        docker_config.mkdir(mode=0o700)
        env = os.environ.copy()
        for key in list(env):
            if key.startswith('COMPOSE_') or key in ('DOCKER_HOST', 'DOCKER_CONTEXT') or key.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'):
                del env[key]
        env['DOCKER_CONFIG'] = str(docker_config)
        env['KUBECONFIG'] = str(temporary/'kubeconfig')
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        context = 'default' if backend == 'compose' else 'kind-' + cluster
        compose = ['docker', '--context', 'default', 'compose', '--project-name', name,
                   '--env-file', str(home/'empty.env'), '-f', str(home/'compose/compose.yaml')]
        recovered_compose = ['docker', '--context', 'default', 'compose', '--project-name', recovered_name,
                   '--env-file', str(recovered/'empty.env'), '-f', str(recovered/'compose/compose.yaml')]
        try:
            if backend == 'kubernetes':
                if cluster in call(['kind', 'get', 'clusters'], 'KIND_DISCOVERY_FAILED', env=env).decode().splitlines():
                    raise StageError('CLUSTER_NAME_ALREADY_EXISTS')
                cluster_attempted = True
                call(['kind', 'create', 'cluster', '--name', cluster, '--image', NODE_IMAGE,
                      '--kubeconfig', env['KUBECONFIG'], '--wait', '180s'], 'KIND_CREATE_FAILED', env=env)
            gateway = gateway_address(backend, cluster, env)
            port = free_port(gateway)
            fixture = subprocess.Popen([str(python), str(ROOT/'tests/fixtures/scheduled_backup_upstream.py'),
                                        '--host', gateway, '--port', str(port)], env=env,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            base = 'http://' + gateway + ':' + str(port)
            wait_fixture(base, fixture)
            keyfile = temporary/'llm-key'
            keyfile.write_bytes(b'')
            keyfile.chmod(0o600)
            installer = bundle/'scripts/install.py'
            prepare = [python, installer, 'prepare', '--home', home, '--backend', backend, '--name', name,
                '--inputs', inputs, '--llm-url', base + '/v1', '--llm-model', 'test-model',
                '--llm-key-file', keyfile, '--allow-http-llm', '--port', str(SOURCE_PORT), '--guardrail-cpus', '2']
            if backend == 'kubernetes':
                prepare += ['--context', context]
            call(prepare, 'PREPARE_FAILED', env=env)
            cfg = json.loads((home/'install.json').read_text())
            if cfg['images'] != manifest['images']:
                raise StageError('INSTALLED_IMAGE_MISMATCH')
            env.update({service.upper() + '_IMAGE': image for service, image in cfg['images'].items()})
            env.update(RUNTIME_DIR=str(home/'runtime'), GUARDRAIL_PORT=str(SOURCE_PORT), GUARDRAIL_CPUS='2')
            call([python, installer, 'check', '--home', home], 'CHECK_FAILED', env=env)
            source_attempted = True
            call([python, installer, 'install', '--home', home], 'INSTALL_FAILED', env=env)
            source_smoke(backend, cluster, name, SOURCE_PORT, home, env)
            before = check_data(backend, name, cluster, env, 'write')
            print('Stage: public signed installation and synthetic Redis/audit data ready', flush=True)

            # The installed release is signed; the scheduled-backup CLI under test
            # is the candidate checkout and is not claimed to be in that release.
            call([python, bundle/'scripts/adopt_managed.py', '--home', home,
                  '--bundle', bundle, '--publisher-key', trusted], 'ADOPTION_FAILED', env=env)
            identity = keys/'identity.json'
            backup_key = keys/'backup.key'
            backup_crypto.create_key(backup_key)
            cli = [python, ROOT/'scripts/backup_installation.py']
            common = ['--home', home, '--publisher-key', trusted, '--expected-backend', backend,
                      '--expected-name', name, '--expected-context', context]
            call(cli + ['register', *common, '--identity-file', identity], 'IDENTITY_REGISTRATION_FAILED', env=env)
            pinned = json.loads(identity.read_text())
            pinned['installation_fingerprint'] = 'invalid-fingerprint'
            bad_identity = keys/'identity-invalid.json'
            fd = os.open(bad_identity, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(pinned, stream)
            backup_args = ['--backup-root', backups, '--backup-key', backup_key]
            observed_before = workload_ids(backend, name, cluster, env)
            rejected_backup(cli + ['backup', *common, *backup_args, '--identity-file', bad_identity], env)
            if list(backups.iterdir()) or workload_ids(backend, name, cluster, env) != observed_before:
                raise StageError('BAD_IDENTITY_CHANGED_WORKLOADS')
            print('Stage: wrong identity rejected before workload changes', flush=True)
            previous_state = (home/'state.json').read_bytes()
            output = call(cli + ['backup', *common, *backup_args, '--identity-file', identity],
                          'SCHEDULED_BACKUP_FAILED', env=env, timeout=1200)
            result = json.loads(output)
            if result.get('result') != 'verified' or result.get('version') != manifest['version'] or result.get('smoke') != 'not_run':
                raise StageError('BACKUP_RESULT_INVALID')
            backup_path = Path(result['backup'])
            if backup_path.parent != backups or not backup_path.name.startswith('uter-'):
                raise StageError('BACKUP_PATH_INVALID')
            secret = backup_crypto.read_key(backup_key)
            metadata = backup_store.verify_set(backup_path, secret)
            if metadata['id'] != result['backup_id'] or metadata['version'] != manifest['version']:
                raise StageError('BACKUP_AUTHENTICATION_FAILED')
            wrong_key = bytes([secret[0] ^ 1]) + secret[1:]
            try:
                backup_store.verify_set(backup_path, wrong_key)
            except ValueError as exc:
                if str(exc) != 'Backup manifest authentication failed':
                    raise StageError('WRONG_KEY_TEST_FAILED') from None
            else:
                raise StageError('INCORRECT_BACKUP_KEY_ACCEPTED')
            if (home/'state.json').read_bytes() != previous_state:
                raise StageError('BACKUP_CHANGED_CONTROLLER_STATE')
            for label in ('runtime', 'redis', 'audit'):
                if b'synthetic-value' in (backup_path/(label + '.enc')).read_bytes():
                    raise StageError('BACKUP_CONTAINS_PLAINTEXT')
            source_smoke(backend, cluster, name, SOURCE_PORT, home, env)
            check_audit_continuity(before, check_data(backend, name, cluster, env, 'verify'))
            print('Stage: scheduled backup verified and source workloads resumed', flush=True)

            recovery = bundle/'scripts'/('recover_compose.py' if backend == 'compose' else 'recover_kubernetes.py')
            command = [python, recovery, '--source-home', home, '--backup', backup_path,
                       '--backup-key', backup_key, '--publisher-key', trusted, '--home', recovered,
                       '--name', recovered_name, '--port', str(RECOVERY_PORT)]
            if backend == 'kubernetes':
                command += ['--context', context]
            recovery_attempted = True
            call(command, 'RECOVERY_FAILED', env=env, timeout=1200)
            recovery_state = json.loads((recovered/'recovery-operation.json').read_text())
            if recovery_state.get('phase') != 'complete' or recovery_state.get('source_backup') != result['backup_id']:
                raise StageError('RECOVERY_STATE_INVALID')
            check_audit_continuity(before, check_data(backend, recovered_name, cluster, env, 'verify'))
            source_smoke(backend, cluster, recovered_name, RECOVERY_PORT, recovered, env)
            print(json.dumps({'backend': backend, 'register': 'pass', 'wrong_identity_rejected': 'pass',
                              'encrypted_backup': 'pass', 'wrong_key_rejected': 'pass',
                              'source_resume': 'pass', 'restore': 'pass',
                              'redis_types_ttl_db1': 'pass', 'audit_hmac': 'pass',
                              'candidate_cli': 'checkout; not part of published release',
                              'upstream': 'deterministic HTTP fixture; not a real LLM'}))
        finally:
            failed = False
            if backend == 'compose':
                if recovery_attempted and (recovered/'empty.env').exists():
                    recovered_env = dict(env, RUNTIME_DIR=str(recovered/'runtime'), GUARDRAIL_PORT=str(RECOVERY_PORT))
                    failed |= not cleanup(recovered_compose + ['down', '--volumes', '--remove-orphans'], recovered_env)
                if source_attempted:
                    failed |= not cleanup(compose + ['down', '--volumes', '--remove-orphans'], env)
            if cluster_attempted:
                failed |= not cleanup(['kind', 'delete', 'cluster', '--name', cluster,
                                      '--kubeconfig', env['KUBECONFIG']], env)
            try:
                terminate(fixture)
            except (OSError, subprocess.TimeoutExpired):
                failed = True
            if failed:
                raise StageError('CI_CLEANUP_FAILED')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        category = str(exc) if isinstance(exc, StageError) else 'SCHEDULED_BACKUP_VALIDATION_FAILED'
        print('Isolated backup test failed: ' + category + '; raw details withheld', file=sys.stderr)
        sys.exit(1)
