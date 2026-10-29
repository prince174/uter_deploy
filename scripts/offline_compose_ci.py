"""Exercise first-install Compose offline on a disposable GitHub-hosted runner only.

Published inputs and image references are verified before use. A deterministic
HTTP fixture stands in for LiteLLM; this is not a test of a real model. The
temporary firewall constrains root-originated host traffic, including dockerd,
and must be removed even if the test fails.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import uterctl
from scripts import extract_release_inputs, smoke_http

PUBLISHER_SHA256 = '65be6fd9613fa7e879735fe5b453bfcb8c0e38911cd7429c9aac9c9afba676a2'
REGISTRY = 'ghcr.io'
PRIVATE_V4 = ('127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
SERVICES = ('guardrail', 'agent', 'redis')


class StageError(Exception):
    """Only a short fixed category is allowed into workflow logs."""


def ci_only():
    if (os.name != 'posix' or os.geteuid() != 0 or
            os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or
            os.environ.get('GITHUB_REPOSITORY') != 'prince174/uter_deploy' or
            not re.fullmatch(r'[0-9]+', os.environ.get('GITHUB_RUN_ID', '')) or
            os.environ.get('DOCKER_HOST')):
        raise StageError('DISPOSABLE_GITHUB_HOSTED_RUNNER_REQUIRED')


def run(args, category, *, env=None, timeout=360, allow_failure=False):
    try:
        result = subprocess.run([str(x) for x in args], env=env, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise StageError(category) from None
    if result.returncode and not allow_failure:
        raise StageError(category)
    return result


def daemon_is_local_root(docker, env):
    raw = run([docker, '--context', 'default', 'context', 'inspect', 'default'],
              'DOCKER_CONTEXT_FAILED', env=env).stdout
    try:
        host = json.loads(raw)[0]['Endpoints']['docker']['Host']
        if not host.startswith('unix://'):
            raise ValueError
        pid = int(run(['systemctl', 'show', 'docker', '--property=MainPID', '--value'],
                      'DOCKER_DAEMON_UNVERIFIED', env=env).stdout.strip())
        if pid <= 1 or Path(f'/proc/{pid}').stat().st_uid != 0:
            raise ValueError
        exe = Path(f'/proc/{pid}/exe').resolve(strict=True)
        if exe.name != 'dockerd':
            raise ValueError
        values = Path(f'/proc/{pid}/environ').read_bytes().split(b'\0')
        proxies = {b'http_proxy', b'https_proxy', b'all_proxy'}
        if any(key.lower() in proxies and val for item in values if b'=' in item
               for key, val in [item.split(b'=', 1)]):
            raise ValueError
        info = json.loads(run([docker, '--context', 'default', 'info', '--format', '{{json .}}'],
                              'DOCKER_DAEMON_UNVERIFIED', env=env).stdout)
        if info.get('HTTPProxy') or info.get('HTTPSProxy') or (info.get('RegistryConfig') or {}).get('Mirrors'):
            raise ValueError
    except (ValueError, OSError, KeyError, IndexError, TypeError):
        raise StageError('DOCKER_DAEMON_UNVERIFIED') from None


def public_registry_ipv4():
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(REGISTRY, 443, socket.AF_INET, socket.SOCK_STREAM)}
        if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
            raise ValueError
        return sorted(addresses)
    except (OSError, ValueError):
        raise StageError('REGISTRY_ADDRESS_UNVERIFIED') from None


def socket_reachable(ip):
    try:
        with socket.create_connection((ip, 443), timeout=5):
            return True
    except OSError:
        return False


class Firewall:
    """Use uniquely named chains, without flushing or changing unrelated rules."""
    def __init__(self, name, env=None):
        if not re.fullmatch(r'UDOFF[0-9A-F]{12}', name):
            raise ValueError('Invalid test chain')
        self.name, self.env = name, env
        self.created = []
        self.attached = []

    def command(self, tool, *args, allow_failure=False):
        return run([tool, '-w', *args], 'FIREWALL_COMMAND_FAILED', env=self.env,
                   allow_failure=allow_failure)

    def __enter__(self):
        try:
            for tool, allowed in (('iptables', PRIVATE_V4), ('ip6tables', ('::1/128',))):
                self.command(tool, '-N', self.name)
                self.created.append(tool)
                for destination in allowed:
                    self.command(tool, '-A', self.name, '-d', destination, '-j', 'RETURN')
                self.command(tool, '-A', self.name, '-j', 'REJECT')
                self.command(tool, '-I', 'OUTPUT', '1', '-m', 'owner', '--uid-owner', '0', '-j', self.name)
                self.attached.append(tool)
            return self
        except BaseException:
            self.close()
            raise

    def reject_count(self):
        result = self.command('iptables', '-L', self.name, '-n', '-v', '-x').stdout.decode('ascii', 'replace')
        matches = [int(match.group(1)) for line in result.splitlines()
                   if (match := re.match(r'^\s*(\d+)\s+\d+\s+REJECT\b', line))]
        if len(matches) != 1:
            raise StageError('FIREWALL_COUNTER_UNAVAILABLE')
        return matches[0]

    def close(self):
        failed = False
        for tool in reversed(self.attached):
            try:
                result = self.command(tool, '-D', 'OUTPUT', '-m', 'owner', '--uid-owner', '0', '-j', self.name,
                                      allow_failure=True)
                failed |= result.returncode != 0
            except StageError:
                failed = True
        self.attached.clear()
        for tool in reversed(self.created):
            for operation in ('-F', '-X'):
                try:
                    result = self.command(tool, operation, self.name, allow_failure=True)
                    failed |= result.returncode != 0
                except StageError:
                    failed = True
        self.created.clear()
        if failed:
            raise StageError('FIREWALL_CLEANUP_FAILED')

    def __exit__(self, exc_type, exc, tb):
        self.close()


def classify_docker(args):
    if 'pull' in args:
        return 'PULL_COMMAND'
    if 'compose' in args and 'up' in args:
        try:
            index = args.index('--pull')
            return 'UP_PULL_NEVER' if args[index + 1] == 'never' else 'UP_OTHER'
        except (ValueError, IndexError):
            return 'UP_OTHER'
    return 'OTHER'


def check_trace(path):
    values = Path(path).read_text(encoding='ascii').splitlines()
    if 'PULL_COMMAND' in values or 'UP_OTHER' in values or 'UP_PULL_NEVER' not in values:
        raise StageError('UNEXPECTED_DOCKER_COMMAND')


def make_wrapper(directory, docker, trace):
    """Capture operation types only; never record command arguments or secrets."""
    wrapper = Path(directory)/'docker'
    script = '''#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
if 'pull' in args:
    op = 'PULL_COMMAND'
elif 'compose' in args and 'up' in args:
    try:
        i = args.index('--pull')
        op = 'UP_PULL_NEVER' if args[i + 1] == 'never' else 'UP_OTHER'
    except (ValueError, IndexError):
        op = 'UP_OTHER'
else:
    op = 'OTHER'
with open(TRACE, 'a', encoding='ascii') as f:
    f.write(op + '\\n')
if os.environ.get('UTER_CI_FORBID_UP') == '1' and op.startswith('UP_'):
    sys.exit(98)
os.execv(REAL_DOCKER, [REAL_DOCKER, *args])
'''
    wrapper.write_text('TRACE = '+repr(str(trace))+'\nREAL_DOCKER = '+repr(str(docker))+'\n'+script[script.index('import os, sys'):], encoding='utf-8')
    # The shebang must remain the first line.
    wrapper.write_text('#!/usr/bin/env python3\n'+wrapper.read_text(encoding='utf-8'), encoding='utf-8')
    wrapper.chmod(0o700)


class Fixture(BaseHTTPRequestHandler):
    def reply(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply({'status': 'ok', 'data': [{'id': 'fixture-model'}]})

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length < 0 or length > 65536:
            self.send_error(413)
            return
        self.rfile.read(length)
        self.reply({'id': 'fixture', 'object': 'chat.completion', 'model': 'fixture-model',
                    'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'Test response.'},
                                 'finish_reason': 'stop'}]})

    def log_message(self, *args):
        pass


def bridge_gateway(docker, env):
    raw = run([docker, '--context', 'default', 'network', 'inspect', 'bridge'],
              'BRIDGE_UNAVAILABLE', env=env).stdout
    try:
        gateway = json.loads(raw)[0]['IPAM']['Config'][0]['Gateway']
        address = ipaddress.ip_address(gateway)
        if address.version != 4 or not address.is_private:
            raise ValueError
        return str(address)
    except (KeyError, IndexError, ValueError, TypeError):
        raise StageError('BRIDGE_UNAVAILABLE') from None


def owned_resources(docker, project, env):
    found = {}
    for kind in ('container', 'network', 'volume'):
        flags = ['-a', '-q'] if kind == 'container' else ['-q']
        raw = run([docker, '--context', 'default', kind, 'ls', *flags, '--filter',
                   'label=com.docker.compose.project='+project], 'RESOURCE_INSPECTION_FAILED', env=env).stdout
        found[kind] = raw.decode('ascii').split()
    return found


def cleanup(docker, project, env):
    """Remove only expected resource names carrying this random project label."""
    if not re.fullmatch(r'uter-offline-ci-[0-9a-f]{12}', project):
        raise StageError('RESOURCE_CLEANUP_IDENTITY_INVALID')
    resources = owned_resources(docker, project, env)
    allowed = {
        'container': {project+'-'+service+'-1' for service in SERVICES},
        'network': {project+'_backend', project+'_outbound'},
        'volume': {project+'_redis-data', project+'_audit-data'},
    }
    # Fail closed before deleting anything if an unexpected resource uses this label.
    for kind, ids in resources.items():
        for item in ids:
            raw = run([docker, '--context', 'default', kind, 'inspect', item],
                      'RESOURCE_CLEANUP_INSPECTION_FAILED', env=env).stdout
            try:
                record = json.loads(raw)[0]
                labels = (record.get('Config') or {}).get('Labels') if kind == 'container' else record.get('Labels')
                name = record['Name'].lstrip('/')
                if (labels or {}).get('com.docker.compose.project') != project or name not in allowed[kind]:
                    raise ValueError
            except (ValueError, KeyError, IndexError, TypeError, AttributeError):
                raise StageError('RESOURCE_CLEANUP_OWNERSHIP_INVALID') from None
    for kind, command in (('container', 'rm'), ('network', 'rm'), ('volume', 'rm')):
        ids = resources[kind]
        if ids:
            args = [docker, '--context', 'default', kind, command]
            if kind == 'container':
                args.append('-f')
            run(args + ids, 'RESOURCE_CLEANUP_FAILED', env=env)


def verified_inputs(work, stage):
    import hashlib
    signed = work/'signed'
    key = work/'download/publisher-public.pem'
    if hashlib.sha256(key.read_bytes()).hexdigest() != PUBLISHER_SHA256:
        raise StageError('PUBLISHER_FINGERPRINT_MISMATCH')
    manifest = uterctl.verify(signed, key)
    inputs = stage/'inputs'
    extract_release_inputs.extract(work/'download/installation-inputs.tar.gz',
        work/'download/installation-inputs.tar.gz.sha256', inputs, bundle=signed, key=key)
    images = json.loads((inputs/'images.json').read_text())
    if images != manifest['images'] or set(images) != set(SERVICES):
        raise StageError('SIGNED_INPUT_MISMATCH')
    return inputs, images


def runtime_permissions(home):
    """Compare metadata without reading generated credentials or configuration."""
    root = Path(home)/'runtime'
    return {path.relative_to(root).as_posix(): (s.st_uid, s.st_gid, s.st_mode)
            for path in root.rglob('*') for s in [path.lstat()]}


def volume_probe(docker, image, volume, *, create, env):
    command = ('from pathlib import Path; Path("/data/uter-offline-sentinel").write_text("untouched")'
               if create else
               'from pathlib import Path; assert Path("/data/uter-offline-sentinel").read_text()=="untouched"')
    run([docker, '--context', 'default', 'run', '--rm', '--pull', 'never', '--network', 'none',
         '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '0:0',
         '--mount', 'type=volume,source='+volume+',target=/data', '--entrypoint', 'python', image, '-c', command],
        'TEST_VOLUME_PROBE_FAILED', env=env)


def main():
    ci_only()
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    work = Path(os.environ['TEST_WORKSPACE']).resolve(strict=True)
    if work == workspace or not work.is_relative_to(workspace):
        raise StageError('TEST_WORKSPACE_INVALID')
    docker = shutil.which('docker')
    if not docker or not shutil.which('iptables') or not shutil.which('ip6tables'):
        raise StageError('REQUIRED_TOOL_MISSING')
    project = 'uter-offline-ci-' + secrets.token_hex(6)
    chain = 'UDOFF' + secrets.token_hex(6).upper()
    with tempfile.TemporaryDirectory(prefix='offline-compose-', dir=work) as temp:
        stage = Path(temp)
        registry = stage/'registry';registry.mkdir(mode=0o700)
        env = os.environ.copy()
        for name in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_AUTH_CONFIG'):
            env.pop(name, None)
        env['DOCKER_CONFIG'] = str(registry)
        daemon_is_local_root(docker, env)
        inputs, images = verified_inputs(work, stage)
        if any(not ref.startswith(REGISTRY + '/') for ref in images.values()):
            raise StageError('UNEXPECTED_REGISTRY')
        if any(owned_resources(docker, project, env).values()):
            raise StageError('TEST_PROJECT_ALREADY_EXISTS')
        addresses = public_registry_ipv4()
        reachable = next((ip for ip in addresses if socket_reachable(ip)), None)
        if not reachable:
            raise StageError('REGISTRY_BASELINE_UNREACHABLE')
        gateway = bridge_gateway(docker, env)
        server = ThreadingHTTPServer((gateway, 0), Fixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        home = stage/'installation'
        key = stage/'llm-key';key.write_text('');key.chmod(0o600)
        wrapper_dir = stage/'bin';wrapper_dir.mkdir()
        trace = stage/'docker-operations';trace.write_text('');trace.chmod(0o600)
        make_wrapper(wrapper_dir, docker, trace)
        cli_env = env.copy();cli_env['PATH'] = str(wrapper_dir)+os.pathsep+env.get('PATH', '')
        cli_env['UTER_CI_FORBID_UP'] = '1'
        installer = ROOT/'scripts/install.py'
        executable = sys.executable
        volume = project+'_redis-data'
        test_volume_created = False
        try:
            # Verify a missing local image fails before any project resource exists.
            for role in ('guardrail', 'redis'):
                run([docker, '--context', 'default', 'pull', images[role]], 'ANONYMOUS_IMAGE_PULL_FAILED', env=env)
            missing = run([docker, '--context', 'default', 'image', 'inspect', images['agent']],
                          'IMAGE_INSPECT_FAILED', env=env, allow_failure=True)
            if missing.returncode == 0:
                raise StageError('EXPECTED_CLEAN_IMAGE_CACHE')
            run([executable, installer, 'prepare', '--home', home, '--backend', 'compose', '--name', project,
                 '--inputs', inputs, '--llm-url', f'http://{gateway}:{server.server_port}/v1',
                 '--llm-model', 'fixture-model', '--llm-key-file', key, '--allow-http-llm',
                 '--guardrail-cpus', '2'], 'PREPARE_FAILED', env=cli_env)
            run([executable, installer, 'check', '--home', home], 'CHECK_FAILED', env=cli_env)
            before_permissions = runtime_permissions(home)
            attempt = run([executable, installer, 'install', '--home', home, '--offline'],
                          'EXPECTED_MISSING_IMAGE', env=cli_env, allow_failure=True)
            if (attempt.returncode == 0 or b'docker command failed' not in attempt.stderr or
                    (home/'install-state.json').exists() or runtime_permissions(home) != before_permissions or
                    any(owned_resources(docker, project, env).values())):
                raise StageError('MISSING_IMAGE_NOT_REJECTED_SAFELY')
            print('Missing image rejected before workload creation', flush=True)
            run([docker, '--context', 'default', 'pull', images['agent']], 'ANONYMOUS_IMAGE_PULL_FAILED', env=env)

            # A foreign-named volume lacking the Compose project label must not be reused.
            all_volumes = run([docker, '--context', 'default', 'volume', 'ls', '--format', '{{.Name}}'],
                              'RESOURCE_INSPECTION_FAILED', env=env).stdout.decode('utf-8').splitlines()
            if volume in all_volumes:
                raise StageError('TEST_VOLUME_ALREADY_EXISTS')
            run([docker, '--context', 'default', 'volume', 'create', '--label', 'uter.offline.test='+project, volume],
                'TEST_VOLUME_CREATE_FAILED', env=env)
            test_volume_created = True
            volume_probe(docker, images['guardrail'], volume, create=True, env=env)
            attempt = run([executable, installer, 'install', '--home', home, '--offline'],
                          'EXPECTED_VOLUME_COLLISION', env=cli_env, allow_failure=True)
            if (attempt.returncode == 0 or b'Compose volume name already exists; refusing to reuse an existing resource' not in attempt.stderr or
                    (home/'install-state.json').exists() or runtime_permissions(home) != before_permissions or
                    any(owned_resources(docker, project, env).values())):
                raise StageError('UNLABELLED_VOLUME_NOT_REJECTED_SAFELY')
            volume_probe(docker, images['guardrail'], volume, create=False, env=env)
            info = json.loads(run([docker, '--context', 'default', 'volume', 'inspect', volume],
                                  'TEST_VOLUME_INSPECT_FAILED', env=env).stdout)[0]
            if (info.get('Labels') or {}).get('uter.offline.test') != project:
                raise StageError('TEST_VOLUME_OWNERSHIP_CHANGED')
            run([docker, '--context', 'default', 'volume', 'rm', volume], 'TEST_VOLUME_CLEANUP_FAILED', env=env)
            test_volume_created = False
            print('Unrelated volume collision rejected before workload creation', flush=True)

            # The exact root/IPv4 path used by dockerd must be demonstrably blocked.
            cli_env['UTER_CI_FORBID_UP'] = '0'
            with Firewall(chain, env) as firewall:
                initial = firewall.reject_count()
                if socket_reachable(reachable) or firewall.reject_count() <= initial:
                    raise StageError('FIREWALL_NOT_EFFECTIVE')
                before_pull = firewall.reject_count()
                blocked = run([docker, '--context', 'default', 'pull',
                               REGISTRY+'/prince174/uter-agent@sha256:'+'0'*64],
                              'BLOCKED_PULL_TEST_FAILED', env=env, timeout=90, allow_failure=True)
                if blocked.returncode == 0 or firewall.reject_count() <= before_pull:
                    raise StageError('DOCKER_REGISTRY_BLOCK_NOT_PROVEN')
                before_install = firewall.reject_count()
                run([executable, installer, 'install', '--home', home, '--offline'],
                    'OFFLINE_INSTALL_FAILED', env=cli_env, timeout=600)
                if firewall.reject_count() != before_install:
                    raise StageError('UNEXPECTED_DAEMON_EGRESS_ATTEMPT')
                check_trace(trace)
                credentials = json.loads((home/'credentials.json').read_text())
                result = smoke_http.check('http://127.0.0.1:18000', 'admin', credentials['admin'])
                if result.get('chat') != 'pass':
                    raise StageError('RUNTIME_SMOKE_FAILED')
                print('Offline install and deterministic LLM fixture smoke passed', flush=True)
        finally:
            try:
                if test_volume_created:
                    inspected = run([docker, '--context', 'default', 'volume', 'inspect', volume],
                                    'TEST_VOLUME_INSPECT_FAILED', env=env, allow_failure=True)
                    if inspected.returncode == 0:
                        info = json.loads(inspected.stdout)[0]
                        if (info.get('Labels') or {}).get('uter.offline.test') != project:
                            raise StageError('TEST_VOLUME_OWNERSHIP_CHANGED')
                        run([docker, '--context', 'default', 'volume', 'rm', volume], 'TEST_VOLUME_CLEANUP_FAILED', env=env)
            finally:
                try:
                    cleanup(docker, project, env)
                finally:
                    server.shutdown();server.server_close();thread.join(timeout=10)


if __name__ == '__main__':
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        print('Offline Compose CI failed:', str(exc) if isinstance(exc, StageError) else type(exc).__name__, file=sys.stderr)
        sys.exit(1)
