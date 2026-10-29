"""Exercise a published Compose upgrade with registry egress blocked, only in hosted CI.

The upstream is a deterministic HTTP fixture, not a real model. The selected
images and both release bundles are authenticated by release_upgrade_preflight_ci.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import uterctl
from scripts import offline_compose_ci as ci, backup_crypto, backup_store, restore_backup, smoke_http
from scripts.published_pair_ci import parse_update_output


def digest_tree(path):
    """Fingerprint installation contents without printing configuration or secrets."""
    digest = hashlib.sha256()
    for item in sorted(Path(path).rglob('*')):
        if item.is_symlink():
            raise ci.StageError('UNEXPECTED_INSTALLATION_SYMLINK')
        digest.update(str(item.relative_to(path)).encode() + b'\0')
        if item.is_file():
            digest.update(hashlib.sha256(item.read_bytes()).digest())
    return digest.digest()


def update_command(python, old, new, key, home, backup_root, backup_key):
    return [python, new/'scripts/update_installation.py', '--home', home, '--bundle', new,
            '--publisher-key', key, '--backup-root', backup_root, '--backup-key', backup_key,
            '--current-bundle', old, '--create-backup-key', '--offline']


def workload_identity(docker, resources, env):
    records = []
    for container in sorted(resources['container']):
        raw = ci.run([docker, '--context', 'default', 'inspect', '--format',
                      '{{.Id}} {{.Image}} {{.State.Running}} {{.State.StartedAt}} {{.RestartCount}}', container],
                     'WORKLOAD_INSPECTION_FAILED', env=env).stdout
        records.append(raw)
    return tuple(records)


def verified_outbound_subnet(docker, project, env):
    """Identify the isolated project's outbound bridge, without reading container env."""
    if not re.fullmatch(r'uter-offline-ci-[0-9a-f]{12}', project):
        raise ci.StageError('TEST_NETWORK_IDENTITY_INVALID')
    raw = ci.run([docker, '--context', 'default', 'network', 'inspect', '--format',
                  '{{json .}}', project+'_outbound'], 'TEST_NETWORK_INSPECTION_FAILED', env=env).stdout
    try:
        if len(raw) > 1024 * 1024:
            raise ValueError
        record = json.loads(raw)
        labels = record['Labels']
        if (not re.fullmatch(r'[0-9a-f]{64}', record['Id'])
                or record['Name'] != project+'_outbound' or record['Driver'] != 'bridge'
                or record['Internal'] is not False
                or labels.get('com.docker.compose.project') != project
                or labels.get('com.docker.compose.network') != 'outbound'):
            raise ValueError
        configs = record['IPAM']['Config']
        if len(configs) != 1:
            raise ValueError
        subnet = ipaddress.ip_network(configs[0]['Subnet'], strict=True)
        private = tuple(ipaddress.ip_network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
        if (subnet.version != 4 or not 16 <= subnet.prefixlen <= 30
                or not any(subnet.subnet_of(block) for block in private)):
            raise ValueError
        if ipaddress.ip_address(configs[0]['Gateway']) not in subnet:
            raise ValueError
        members = record['Containers']
        if not isinstance(members, dict) or len(members) != 2:
            raise ValueError
        found = set()
        for container_id, member in members.items():
            if not re.fullmatch(r'[0-9a-f]{64}', container_id):
                raise ValueError
            address = ipaddress.ip_interface(member['IPv4Address'])
            if address.version != 4 or address.network != subnet:
                raise ValueError
            info = ci.run([docker, '--context', 'default', 'inspect', '--format',
                           '{{json .Id}} {{json .Name}} {{json .Config.Labels}}', container_id],
                          'TEST_CONTAINER_INSPECTION_FAILED', env=env).stdout
            if len(info) > 65536:
                raise ValueError
            # Decode the first two JSON strings and then the labels object, without inspecting environment.
            text = info.decode('utf-8').lstrip(); decoder = json.JSONDecoder()
            identity, offset = decoder.raw_decode(text)
            text = text[offset:].lstrip()
            name, offset = decoder.raw_decode(text)
            metadata = json.loads(text[offset:].strip())
            role = metadata.get('com.docker.compose.service')
            if (identity != container_id or role not in ('guardrail', 'agent')
                    or name != '/'+project+'-'+role+'-1'
                    or metadata.get('com.docker.compose.project') != project
                    or member['Name'] != project+'-'+role+'-1' or role in found):
                raise ValueError
            found.add(role)
        if found != {'guardrail', 'agent'}:
            raise ValueError
        return str(subnet), record['Id']
    except (ValueError, KeyError, TypeError, UnicodeError, AttributeError):
        raise ci.StageError('TEST_NETWORK_IDENTITY_INVALID') from None


def allow_fixture_responses(firewall, gateway, subnet, port):
    """Permit only established fixture replies to this project's verified bridge."""
    firewall.command('iptables', '-I', firewall.name, '1', '-s', gateway+'/32', '-d', subnet,
                     '-p', 'tcp', '--sport', str(port), '-m', 'conntrack',
                     '--ctstate', 'ESTABLISHED', '-j', 'RETURN')


def guardrail_addresses(docker, project, env):
    """Read project bridge metadata for diagnostic counters; do not inspect env."""
    if not re.fullmatch(r'uter-offline-ci-[0-9a-f]{12}', project):
        raise ci.StageError('TEST_NETWORK_IDENTITY_INVALID')
    addresses = {}
    try:
        for network in ('backend', 'outbound'):
            raw = ci.run([docker, '--context', 'default', 'network', 'inspect', '--format',
                          '{{json .}}', project+'_'+network], 'TEST_NETWORK_INSPECTION_FAILED', env=env).stdout
            if len(raw) > 1024*1024:
                raise ValueError
            data = json.loads(raw)
            if (data['Name'] != project+'_'+network or data['Driver'] != 'bridge'
                    or data['Labels'].get('com.docker.compose.project') != project
                    or data['Labels'].get('com.docker.compose.network') != network):
                raise ValueError
            matches = [(key, value) for key, value in data['Containers'].items()
                       if value.get('Name') == project+'-guardrail-1']
            if len(matches) != 1 or not re.fullmatch(r'[0-9a-f]{64}', matches[0][0]):
                raise ValueError
            identity, member = matches[0]
            labels = json.loads(ci.run([docker, '--context', 'default', 'inspect', '--format',
                '{{json .Config.Labels}}', identity], 'TEST_CONTAINER_INSPECTION_FAILED', env=env).stdout)
            if labels.get('com.docker.compose.project') != project or labels.get('com.docker.compose.service') != 'guardrail':
                raise ValueError
            configs = data['IPAM']['Config']
            if len(configs) != 1:
                raise ValueError
            subnet = ipaddress.ip_network(configs[0]['Subnet'], strict=True)
            private = tuple(ipaddress.ip_network(v) for v in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
            address = ipaddress.ip_interface(member['IPv4Address'])
            if (subnet.version != 4 or not 16 <= subnet.prefixlen <= 30
                    or not any(subnet.subnet_of(block) for block in private) or address.network != subnet):
                raise ValueError
            addresses[network] = str(address.ip)
        return addresses
    except (ValueError, KeyError, TypeError, UnicodeError, AttributeError):
        raise ci.StageError('TEST_NETWORK_IDENTITY_INVALID') from None


def add_smoke_counters(firewall, addresses):
    # A rule with no target counts packets and continues to the existing reject.
    for network in ('backend', 'outbound'):
        firewall.command('iptables', '-I', firewall.name, '1', '-d', addresses[network]+'/32',
                         '-p', 'tcp', '--dport', '8000', '-m', 'comment', '--comment',
                         'uter-smoke-'+network)


def smoke_counter_values(firewall):
    text = firewall.command('iptables', '-L', firewall.name, '-n', '-v', '-x').stdout.decode('ascii', 'replace')
    values = {}
    for network in ('backend', 'outbound'):
        rows = [line for line in text.splitlines() if '/* uter-smoke-'+network+' */' in line]
        if len(rows) != 1:
            raise ci.StageError('SMOKE_COUNTER_UNAVAILABLE')
        match = re.match(r'^\s*(\d+)\s+\d+\s', rows[0])
        if not match:
            raise ci.StageError('SMOKE_COUNTER_UNAVAILABLE')
        values[network] = int(match.group(1))
    return values


def failure_categories(stderr, home, trace):
    """Fixed diagnostics only: never emit command output, paths or secrets."""
    markers = {
        'adoption_smoke_failed': b'Pre-adoption smoke failed',
        'adoption_assets_mismatch': b'Installation deployment assets do not match signed bundle',
        'signed_image_mismatch': b'does not match the signed image',
        'offline_preflight_failed': b'Offline image preflight failed',
        'backup_command_failed': b'backup operation failed; details withheld',
        'backup_redis_invalid': b'Redis snapshot failed structural validation',
        'backup_recovery_failed': b'Backup recovery failed',
        'apply_or_smoke_failed': b'Update incomplete. State retained',
        'managed_smoke_error': b'uter_managed_smoke.py',
        'network_error': any(value in stderr.lower() for value in
            (b'connection refused', b'network is unreachable', b'no route to host',
             b'i/o timeout', b'context deadline exceeded', b'connection reset by peer',
             b'server misbehaving', b'temporary failure in name resolution')),
    }
    result = {key: (value if isinstance(value, bool) else value in stderr) for key, value in markers.items()}
    try:
        state = json.loads((home/'state.json').read_bytes())
        result['state'] = ('pending' if state.get('pending') is not None else 'adopted')
    except FileNotFoundError:
        result['state'] = 'not_adopted'
    except (OSError, ValueError, TypeError, AttributeError):
        result['state'] = 'unreadable'
    try:
        journal = json.loads((home/'backup-operation.json').read_bytes())
        phase = journal.get('phase')
        result['backup_journal'] = phase if phase in ('quiescing', 'quiesced') else 'other'
    except FileNotFoundError:
        result['backup_journal'] = 'absent'
    except (OSError, ValueError, TypeError, AttributeError):
        result['backup_journal'] = 'unreadable'
    try:
        operations = set(trace.read_text(encoding='ascii').splitlines())
        result['compose_up_observed'] = 'UP_PULL_NEVER' in operations or 'UP_OTHER' in operations
        result['pull_observed'] = 'PULL_COMMAND' in operations
    except (OSError, UnicodeError):
        result['compose_up_observed'] = result['pull_observed'] = None
    return result


def main():
    ci.ci_only()
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    if workspace != ROOT or os.environ.get('RUNNER_OS') != 'Linux':
        raise ci.StageError('DISPOSABLE_GITHUB_HOSTED_RUNNER_REQUIRED')
    work = workspace/'work'
    old, new = work/'pair/old/bundle', work/'pair/new/bundle'
    public = work/'pair/old/publisher-public.pem'
    manifests = [uterctl.verify(bundle, public) for bundle in (old, new)]
    if [m['version'] for m in manifests] != ['0.1.4', '0.1.5']:
        raise ci.StageError('UNEXPECTED_RELEASE_PAIR')
    docker = shutil.which('docker')
    if not docker or not shutil.which('iptables') or not shutil.which('ip6tables'):
        raise ci.StageError('REQUIRED_TOOL_MISSING')
    project = 'uter-offline-ci-' + secrets.token_hex(6)
    chain = 'UDOFF' + secrets.token_hex(6).upper()
    with tempfile.TemporaryDirectory(prefix='offline-upgrade-', dir=work) as tmp:
        stage = Path(tmp); registry = stage/'registry'; registry.mkdir(mode=0o700)
        env = os.environ.copy()
        for name in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_AUTH_CONFIG'):
            env.pop(name, None)
        env['DOCKER_CONFIG'] = str(registry)
        ci.daemon_is_local_root(docker, env)
        if any(ci.owned_resources(docker, project, env).values()):
            raise ci.StageError('TEST_PROJECT_ALREADY_EXISTS')
        addresses = ci.public_registry_ipv4()
        reachable = next((ip for ip in addresses if ci.socket_reachable(ip)), None)
        if not reachable:
            raise ci.StageError('REGISTRY_BASELINE_UNREACHABLE')
        gateway = ci.bridge_gateway(docker, env)
        fixture = ThreadingHTTPServer((gateway, 0), ci.Fixture)
        thread = threading.Thread(target=fixture.serve_forever, daemon=True); thread.start()
        home = stage/'installation'; key = stage/'empty-key'; key.write_text(''); key.chmod(0o600)
        backup_root = stage/'backups'; backup_root.mkdir(mode=0o700)
        backup_key = stage/'backup.key'
        wrapper_dir = stage/'bin'; wrapper_dir.mkdir()
        trace = stage/'docker-operations'; trace.write_text(''); trace.chmod(0o600)
        ci.make_wrapper(wrapper_dir, docker, trace)
        cli_env = env.copy(); cli_env['PATH'] = str(wrapper_dir)+os.pathsep+env.get('PATH', '')
        installer = old/'scripts/install.py'
        updater = update_command(sys.executable, old, new, public, home, backup_root, backup_key)
        try:
            for ref in sorted({r for m in manifests for r in m['images'].values()}):
                ci.run([docker, '--context', 'default', 'pull', ref], 'ANONYMOUS_IMAGE_PULL_FAILED', env=env)
            ci.run([sys.executable, installer, 'prepare', '--home', home, '--backend', 'compose', '--name', project,
                    '--inputs', work/'input/published-old', '--llm-url', f'http://{gateway}:{fixture.server_port}/v1',
                    '--llm-model', 'fixture-model', '--llm-key-file', key, '--allow-http-llm', '--guardrail-cpus', '2'],
                   'PREPARE_FAILED', env=cli_env)
            ci.run([sys.executable, installer, 'check', '--home', home], 'CHECK_FAILED', env=cli_env)
            # The old published installer predates --offline; the network block
            # applies to the subsequent update, after the initial installation.
            ci.run([sys.executable, installer, 'install', '--home', home], 'INSTALL_FAILED', env=cli_env, timeout=600)
            credentials = json.loads((home/'credentials.json').read_text())
            if smoke_http.check('http://127.0.0.1:18000', 'admin', credentials['admin']).get('chat') != 'pass':
                raise ci.StageError('INITIAL_SMOKE_FAILED')

            # Remove one reference only on the disposable runner. If a running
            # container keeps it resolvable, fail rather than fake the condition.
            missing = manifests[1]['images']['agent']
            ci.run([docker, '--context', 'default', 'image', 'rm', '-f', missing], 'IMAGE_REMOVE_FAILED', env=env)
            if ci.run([docker, '--context', 'default', 'image', 'inspect', missing], 'IMAGE_INSPECT_FAILED',
                      env=env, allow_failure=True).returncode == 0:
                raise ci.StageError('IMAGE_STILL_RESOLVABLE')
            before = digest_tree(home); resources = ci.owned_resources(docker, project, env)
            identity = workload_identity(docker, resources, env)
            attempt = ci.run(updater, 'MISSING_IMAGE_CHECK_FAILED', env=cli_env, allow_failure=True, timeout=180)
            if (attempt.returncode == 0 or b'Offline image preflight failed' not in attempt.stderr
                    or digest_tree(home) != before or ci.owned_resources(docker, project, env) != resources
                    or workload_identity(docker, resources, env) != identity
                    or backup_key.exists() or any(backup_root.iterdir())):
                raise ci.StageError('MISSING_IMAGE_NOT_REJECTED_SAFELY')
            ci.run([docker, '--context', 'default', 'pull', missing], 'ANONYMOUS_IMAGE_PULL_FAILED', env=env)
            print('Missing local image rejected before installation changes', flush=True)

            outbound_subnet, outbound_id = verified_outbound_subnet(docker, project, env)
            guard_addresses = guardrail_addresses(docker, project, env)
            # The fixture is on one exact bridge address, never an RFC1918 wildcard.
            ci.PRIVATE_V4 = ('127.0.0.0/8', gateway+'/32')
            with ci.Firewall(chain, env, addresses) as firewall:
                allow_fixture_responses(firewall, gateway, outbound_subnet, fixture.server_port)
                add_smoke_counters(firewall, guard_addresses)
                before = firewall.reject_counts()
                if ci.socket_reachable(reachable) or firewall.reject_counts()['v4-registry-ipv4'] <= before['v4-registry-ipv4']:
                    raise ci.StageError('FIREWALL_NOT_EFFECTIVE')
                blocked = ci.run([docker, '--context', 'default', 'pull', missing], 'BLOCKED_PULL_TEST_FAILED',
                                 env=env, timeout=90, allow_failure=True)
                if not ci.network_failure(blocked):
                    raise ci.StageError('DOCKER_REGISTRY_BLOCK_NOT_PROVEN')
                trace.write_text('')
                counts_before_upgrade = firewall.reject_counts()
                smoke_before_upgrade = smoke_counter_values(firewall)
                result = ci.run(updater, 'OFFLINE_UPGRADE_FAILED', env=cli_env, timeout=900, allow_failure=True)
                if result.returncode:
                    print('Offline upgrade diagnostic: '+json.dumps(failure_categories(result.stderr, home, trace), sort_keys=True), flush=True)
                    ci.report_firewall_delta(counts_before_upgrade, firewall.reject_counts())
                    smoke_after_upgrade = smoke_counter_values(firewall)
                    print('Pre-reject Guardrail TCP:8000 packets: '+json.dumps(
                        {name: smoke_after_upgrade[name]-smoke_before_upgrade[name] for name in smoke_before_upgrade}, sort_keys=True), flush=True)
                    raise ci.StageError('OFFLINE_UPGRADE_FAILED')
                updated = parse_update_output(result.stdout)
                if updated.get('version') != '0.1.5':
                    raise ci.StageError('UPGRADE_VERSION_MISMATCH')
                ci.check_trace(trace)
                state = uterctl.read(home/'state.json')
                if state.get('current') != manifests[1] or state.get('pending') is not None:
                    raise ci.StageError('UPGRADE_STATE_MISMATCH')
                backup = Path(updated['backup'])
                metadata = backup_store.verify_set(backup, backup_crypto.read_key(backup_key), home=home,
                                                   site=uterctl.site_config(home), version='0.1.4')
                if metadata['id'] != updated['backup_id']:
                    raise ci.StageError('BACKUP_ID_MISMATCH')
                restore_backup.export(backup, backup_key, stage/'export')
                ci.run([docker, '--context', 'default', 'run', '--rm', '--pull', 'never', '--network', 'none',
                        '--user', '0:0', '--mount', 'type=bind,source='+str(stage/'export/redis.rdb')+',target=/snapshot.rdb,readonly',
                        '--entrypoint', 'redis-check-rdb', manifests[0]['images']['redis'], '/snapshot.rdb'],
                       'BACKUP_REDIS_INVALID', env=env)
                if smoke_http.check('http://127.0.0.1:18000', 'admin', credentials['admin']).get('chat') != 'pass':
                    raise ci.StageError('UPGRADE_SMOKE_FAILED')
                if verified_outbound_subnet(docker, project, env) != (outbound_subnet, outbound_id):
                    raise ci.StageError('TEST_NETWORK_IDENTITY_CHANGED')
                print('Signed offline upgrade, authenticated backup export and fixture smoke passed', flush=True)
        finally:
            try:
                ci.cleanup(docker, project, env)
            finally:
                fixture.shutdown(); fixture.server_close(); thread.join(timeout=10)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        print('Offline upgrade CI failed:', str(exc) if isinstance(exc, ci.StageError) else type(exc).__name__, file=sys.stderr)
        sys.exit(1)
