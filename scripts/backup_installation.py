#!/usr/bin/env python3
"""Create one verified encrypted backup of an already-adopted installation.

No scheduler is installed. Capturing the snapshot briefly stops application
writers; external writers must be quiesced by the operator. The operation holds
uterctl's lock and does not update controller state or rotate the backup key.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import backup_crypto, backup_snapshot, backup_store, install_recovery

MAX_JSON = 1024 * 1024
SNAPSHOT_NAMES = ('runtime', 'install.json', 'install-state.json', 'credentials.json',
                  'empty.env', 'values.yaml', 'resources.yaml', 'state.json', 'releases')


class BackupError(Exception):
    """Fixed category only: never attach external command output or secrets."""


def checked_existing_path(path):
    """Reject symlinked/untrusted ancestors before passing paths to older APIs."""
    path = Path(path)
    if '..' in path.parts:
        raise BackupError('PATH_INVALID')
    path = path.absolute()
    parts = path.parts
    current = Path(parts[0])
    for index, part in enumerate(parts[1:], 1):
        current = current / part
        try:
            info = current.lstat()
        except OSError:
            raise BackupError('PATH_INVALID') from None
        if stat.S_ISLNK(info.st_mode):
            raise BackupError('PATH_INVALID')
        if index != len(parts) - 1:
            # Root-owned sticky directories such as /tmp are permitted; their
            # entries cannot be renamed by unrelated users.
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or (info.st_mode & 0o022 and not sticky_root)):
                raise BackupError('PATH_ANCESTOR_UNSAFE')
    return path


def private_directory(path):
    path = checked_existing_path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise BackupError('PRIVATE_DIRECTORY_REQUIRED')
    return path


def safe_file(path, *, private=False, limit=MAX_JSON):
    """Read a bounded owner-controlled file without following symlinks/FIFOs."""
    path = checked_existing_path(path)
    try:
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022
                    or (private and (info.st_uid != os.geteuid() or info.st_mode & 0o077))):
                raise BackupError('FILE_UNSAFE')
            value = source.read(limit + 1)
        if len(value) > limit:
            raise BackupError('FILE_TOO_LARGE')
        return value
    except BackupError:
        raise
    except OSError:
        raise BackupError('FILE_UNREADABLE') from None


def safe_json(path, *, private=False):
    try:
        value = json.loads(safe_file(path, private=private))
        if not isinstance(value, dict):
            raise BackupError('STATE_INVALID')
        return value
    except BackupError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise BackupError('STATE_INVALID') from None


def present(path):
    # lstat also catches dangling symlinks rather than treating them as absent.
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def verify_tree(path):
    """A signed current bundle must contain no links or special filesystem nodes."""
    path = checked_existing_path(path)
    bundle_info = path.lstat()
    if (not stat.S_ISDIR(bundle_info.st_mode) or bundle_info.st_uid not in (0, os.geteuid())
            or bundle_info.st_mode & 0o022):
        raise BackupError('BUNDLE_INVALID')
    count = 0
    def fail(error):
        raise error
    try:
        for root, dirs, files in os.walk(path, followlinks=False, onerror=fail):
            for name in dirs + files:
                item = Path(root) / name
                info = item.lstat()
                count += 1
                if count > 10000:
                    raise BackupError('BUNDLE_INVALID')
                if stat.S_ISDIR(info.st_mode):
                    if info.st_uid not in (0, os.geteuid()):
                        raise BackupError('BUNDLE_INVALID')
                elif (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                      or info.st_uid not in (0, os.geteuid())):
                    raise BackupError('BUNDLE_INVALID')
    except BackupError:
        raise
    except OSError:
        raise BackupError('BUNDLE_INVALID') from None


def validate_snapshot_sources(home):
    """Reject linked or special files in every path the snapshot will archive."""
    count = 0
    def check(path):
        nonlocal count
        info = path.lstat()
        count += 1
        if count > 100000:
            raise BackupError('SNAPSHOT_SOURCE_UNSAFE')
        if stat.S_ISDIR(info.st_mode):
            return True
        if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            return False
        raise BackupError('SNAPSHOT_SOURCE_UNSAFE')
    def fail(error):
        raise error
    try:
        for name in SNAPSHOT_NAMES:
            root = home / name
            if not present(root):
                continue
            if check(root):
                for current, dirs, files in os.walk(root, followlinks=False, onerror=fail):
                    for child in dirs + files:
                        check(Path(current) / child)
    except BackupError:
        raise
    except OSError:
        raise BackupError('SNAPSHOT_SOURCE_UNSAFE') from None


def installation_metadata(home):
    state = safe_json(home / 'state.json')
    config = safe_json(home / 'install.json')
    initial = safe_json(home / 'install-state.json')
    runtime = home / 'runtime'
    if not stat.S_ISDIR(checked_existing_path(runtime).lstat().st_mode):
        raise BackupError('RUNTIME_INVALID')
    site = safe_json(runtime / 'site.json')
    if initial.get('status') != 'ready' or state.get('adopted_installer') is not True:
        raise BackupError('INSTALLATION_NOT_ADOPTED_AND_READY')
    if 'pending' not in state or state['pending'] is not None:
        raise BackupError('CONTROLLER_OPERATION_PENDING')
    if present(home / 'backup-operation.json'):
        raise BackupError('PREVIOUS_BACKUP_REQUIRES_INSPECTION')
    if present(home / 'redis-fence-operation.json'):
        raise BackupError('REDIS_FENCE_REQUIRES_INSPECTION')
    recovery = home / 'recovery-operation.json'
    if present(recovery) and safe_json(recovery).get('phase') != 'complete':
        raise BackupError('RECOVERY_OPERATION_PENDING')
    current = state.get('current')
    if not isinstance(current, dict) or not isinstance(current.get('version'), str) or not uterctl.VERSION.fullmatch(current['version']):
        raise BackupError('STATE_INVALID')
    if site.get('backend') not in ('compose', 'helm'):
        raise BackupError('INSTALLATION_IDENTITY_MISMATCH')
    expected_backend = 'compose' if site['backend'] == 'compose' else 'kubernetes'
    name, context = site.get('name'), site.get('context')
    if (not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,38}[a-z0-9]', name)
            or site.get('namespace') != name or config.get('name') != name
            or config.get('backend') != expected_backend or config.get('context') != context
            or not isinstance(context, str) or not context or context.startswith('-')
            or any(ord(c) < 32 or ord(c) == 127 for c in context)
            or (expected_backend == 'compose' and context != 'default')
            or type(site.get('port')) is not int or not 1024 <= site['port'] <= 65535
            or config.get('port') != site['port']
            or type(site.get('guardrail_cpus')) not in (int, float)
            or not 1 <= site['guardrail_cpus'] <= 64
            or config.get('guardrail_cpus', 4) != site['guardrail_cpus']):
        raise BackupError('INSTALLATION_IDENTITY_MISMATCH')
    smoke = site.get('smoke_command')
    if not isinstance(smoke, list) or not smoke or any(not isinstance(x, str) or not x for x in smoke):
        raise BackupError('STATE_INVALID')
    return config, site, current


def verify_current_bundle(home, current, publisher_key):
    bundle = home / 'releases' / current['version']
    verify_tree(bundle)
    try:
        verified = uterctl.verify(bundle, publisher_key)
    except Exception:
        raise BackupError('CURRENT_BUNDLE_VERIFICATION_FAILED') from None
    if verified != current:
        raise BackupError('CURRENT_BUNDLE_STATE_MISMATCH')


def expected_identity(config, site, backend, name, context):
    expected_backend = 'compose' if site['backend'] == 'compose' else 'kubernetes'
    if (backend, name, context) != (expected_backend, site['name'], site['context']):
        raise BackupError('EXPECTED_IDENTITY_MISMATCH')
    if config['backend'] != backend:
        raise BackupError('EXPECTED_IDENTITY_MISMATCH')


def observe_runtime(site):
    """Return immutable-ish identifiers using bounded, read-only API queries."""
    try:
        if site['backend'] == 'compose':
            if os.environ.get('DOCKER_HOST'):
                raise BackupError('DOCKER_HOST_UNSUPPORTED')
            output = install_recovery.run_readonly(['docker', 'context', 'inspect', 'default',
                                                     '--format', '{{json .Endpoints.docker.Host}}'])
            host = json.loads(output)
            if not isinstance(host, str) or not host.startswith('unix://'):
                raise BackupError('LOCAL_DEFAULT_UNIX_CONTEXT_REQUIRED')
            engine = install_recovery.run_readonly(['docker', '--context', 'default', 'info', '--format', '{{.ID}}']).strip()
            if not re.fullmatch(r'[A-Za-z0-9:._-]{6,128}', engine):
                raise BackupError('RUNTIME_IDENTITY_INVALID')
            docker = ['docker', '--context', 'default']
            containers = {}
            for service in ('guardrail', 'agent', 'redis'):
                result = install_recovery.run_readonly(docker + ['container', 'ls', '--quiet',
                    '--filter', 'label=com.docker.compose.project=' + site['name'],
                    '--filter', 'label=com.docker.compose.service=' + service,
                    '--filter', 'status=running']).splitlines()
                if len(result) != 1 or not re.fullmatch(r'[0-9a-f]{12,64}', result[0]):
                    raise BackupError('RUNTIME_IDENTITY_INVALID')
                full_id = install_recovery.run_readonly(docker + ['container', 'inspect', '--format', '{{.Id}}', result[0]]).strip()
                if not re.fullmatch(r'[0-9a-f]{64}', full_id) or not full_id.startswith(result[0]):
                    raise BackupError('RUNTIME_IDENTITY_INVALID')
                containers[service] = full_id
            if len(set(containers.values())) != 3:
                raise BackupError('RUNTIME_IDENTITY_INVALID')
            def volume(service, destination, logical_name):
                template = '{{range .Mounts}}{{if eq .Destination "' + destination + '"}}{{.Type}}:{{.Name}};{{end}}{{end}}'
                output = install_recovery.run_readonly(docker + ['container', 'inspect', '--format', template,
                                                                  containers[service]]).strip()
                match = re.fullmatch(r'volume:([A-Za-z0-9][A-Za-z0-9_.-]{0,254});', output)
                if not match or match.group(1) != site['name'] + '_' + logical_name:
                    raise BackupError('RUNTIME_IDENTITY_INVALID')
                name = match.group(1)
                labels = ('{"project":{{json (index .Labels "com.docker.compose.project")}},'
                          '"volume":{{json (index .Labels "com.docker.compose.volume")}}}')
                metadata = json.loads(install_recovery.run_readonly(docker + ['volume', 'inspect', '--format', labels, name]))
                if not isinstance(metadata, dict) or metadata != {'project': site['name'], 'volume': logical_name}:
                    raise BackupError('RUNTIME_IDENTITY_INVALID')
                return name
            volumes = {'redis': volume('redis', '/data', 'redis-data'),
                       'audit': volume('guardrail', '/var/lib/uter/audit', 'audit-data')}
            if volumes['redis'] == volumes['audit']:
                raise BackupError('RUNTIME_IDENTITY_INVALID')
            return {'docker_daemon_id': engine, 'container_ids': containers, 'volumes': volumes}
        kube = ['kubectl', '--context', site['context']]
        def namespace_uid(name):
            value = install_recovery.run_readonly(kube + ['get', 'namespace', name,
                                                           '-o', 'jsonpath={.metadata.uid}']).strip()
            if not re.fullmatch(r'[A-Za-z0-9:._-]{1,128}', value):
                raise BackupError('RUNTIME_IDENTITY_INVALID')
            return value
        cluster_uid = namespace_uid('kube-system')
        namespace = namespace_uid(site['namespace'])
        if cluster_uid == namespace:
            raise BackupError('RUNTIME_IDENTITY_INVALID')
        def resource_uid(kind, name):
            value = install_recovery.run_readonly(kube + ['-n', site['namespace'], 'get', kind, name,
                                                           '-o', 'jsonpath={.metadata.uid}']).strip()
            if not re.fullmatch(r'[A-Za-z0-9:._-]{1,128}', value):
                raise BackupError('RUNTIME_IDENTITY_INVALID')
            return value
        deployments = {service: resource_uid('deployment', site['name'] + '-' + service)
                       for service in ('guardrail', 'agent', 'redis')}
        # Pin only the published chart layout: the running deployment's first
        # container must mount its data volume and that volume must point at
        # the expected PVC. Other layouts fail closed until separately verified.
        for service, mount_path in (('guardrail', '/var/lib/uter/audit'), ('redis', '/data')):
            deploy = site['name'] + '-' + service
            def deployment_field(expression):
                return install_recovery.run_readonly(kube + ['-n', site['namespace'], 'get', 'deployment', deploy,
                                                               '-o', 'jsonpath=' + expression]).strip()
            name = deployment_field('{.spec.template.spec.containers[0].name}')
            mount = deployment_field('{.spec.template.spec.containers[0].volumeMounts[?(@.mountPath=="'
                                     + mount_path + '")].name}')
            claim = deployment_field('{.spec.template.spec.volumes[?(@.name=="data")].persistentVolumeClaim.claimName}')
            if name != service or mount != 'data' or claim != deploy:
                raise BackupError('RUNTIME_IDENTITY_INVALID')
        pvcs = {service: resource_uid('pvc', site['name'] + '-' + service)
                for service in ('guardrail', 'redis')}
        values = [cluster_uid, namespace, *deployments.values(), *pvcs.values()]
        if len(set(values)) != len(values):
            raise BackupError('RUNTIME_IDENTITY_INVALID')
        return {'kube_system_uid': cluster_uid, 'namespace_uid': namespace,
                'deployment_uids': deployments, 'pvc_uids': pvcs}
    except BackupError:
        raise
    except (install_recovery.DiagnosticError, ValueError, TypeError, KeyError, IndexError):
        raise BackupError('RUNTIME_IDENTITY_QUERY_FAILED') from None


def identity_record(home, site, observed):
    return {'schema': 1, 'installation_fingerprint': backup_store.installation_fingerprint(home, site),
            'backend': site['backend'], 'name': site['name'], 'context': site['context'],
            'runtime': observed}


def identity_destination(home, identity_file):
    path = Path(identity_file)
    if not path.name or path.name in ('.', '..') or '..' in path.parts:
        raise BackupError('PATH_INVALID')
    parent = private_directory(path.absolute().parent)
    path = parent / path.name
    if path.is_relative_to(home):
        raise BackupError('IDENTITY_PATH_NOT_SEPARATE')
    return path


def create_key(home, backup_root, backup_key):
    """Create a new key outside the installation and backup directories."""
    if os.name != 'posix':
        raise BackupError('POSIX_REQUIRED')
    home = private_directory(home)
    backup_root = private_directory(backup_root)
    path = Path(backup_key)
    if not path.name or path.name in ('.', '..') or '..' in path.parts:
        raise BackupError('PATH_INVALID')
    parent = private_directory(path.absolute().parent)
    path = parent / path.name
    if (home == backup_root or home.is_relative_to(backup_root) or backup_root.is_relative_to(home)
            or path.is_relative_to(home) or path.is_relative_to(backup_root)):
        raise BackupError('BACKUP_PATHS_NOT_SEPARATE')
    if present(path):
        raise BackupError('BACKUP_KEY_ALREADY_EXISTS')
    try:
        backup_crypto.create_key(path)
    except FileExistsError:
        raise BackupError('BACKUP_KEY_ALREADY_EXISTS') from None
    except Exception:
        raise BackupError('BACKUP_KEY_CREATION_FAILED') from None
    # The process umask must not have removed owner access; do not silently
    # declare success for a key that the scheduler cannot read.
    if stat.S_IMODE(path.lstat().st_mode) != 0o600 or len(safe_file(path, private=True, limit=32)) != 32:
        raise BackupError('BACKUP_KEY_CREATION_FAILED')
    return {'result': 'created', 'backup_key': str(path)}


def write_identity_once(path, value):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError:
        raise BackupError('IDENTITY_ALREADY_EXISTS') from None
    except OSError:
        # Do not delete a partially written identity; require inspection.
        raise BackupError('IDENTITY_REGISTRATION_FAILED') from None


def register(home, identity_file, publisher_key, backend, name, context):
    """Pin selected, currently healthy workloads; never overwrite a pin."""
    if os.name != 'posix':
        raise BackupError('POSIX_REQUIRED')
    home = private_directory(home)
    identity_file = identity_destination(home, identity_file)
    publisher_key = checked_existing_path(publisher_key)
    safe_file(publisher_key, limit=65536)
    if present(identity_file):
        raise BackupError('IDENTITY_ALREADY_EXISTS')
    with uterctl.locked(home):
        config, site, current = installation_metadata(home)
        expected_identity(config, site, backend, name, context)
        verify_current_bundle(home, current, publisher_key)
        before = observe_runtime(site)
        try:
            # Pin only the already-adopted installation with matching running
            # images; no rollout, restart or changes to those workloads.
            backup_snapshot.adopt_installation.verify_live(home, dict(config, images=current['images']), current)
        except Exception:
            raise BackupError('LIVE_INSTALLATION_VERIFICATION_FAILED') from None
        observed = observe_runtime(site)
        if observed != before:
            raise BackupError('RUNTIME_IDENTITY_CHANGED_DURING_REGISTRATION')
        write_identity_once(identity_file, identity_record(home, site, observed))
    return {'result': 'registered', 'identity_file': str(identity_file),
            'trust_model': 'administrator_controls_runtime_and_identity_file'}


def backup(home, backup_root, backup_key, publisher_key, identity_file, backend, name, context):
    if os.name != 'posix':
        raise BackupError('POSIX_REQUIRED')
    home = private_directory(home)
    backup_root = private_directory(backup_root)
    backup_key = checked_existing_path(backup_key)
    key_parent = private_directory(backup_key.parent)
    publisher_key = checked_existing_path(publisher_key)
    identity_file = checked_existing_path(identity_file)
    private_directory(identity_file.parent)
    if (home == backup_root or home.is_relative_to(backup_root) or backup_root.is_relative_to(home)
            or backup_key.is_relative_to(home) or backup_key.is_relative_to(backup_root)
            or key_parent == home or key_parent == backup_root
            or identity_file.is_relative_to(home) or identity_file.is_relative_to(backup_root)
            or identity_file in (backup_key, publisher_key)):
        raise BackupError('BACKUP_PATHS_NOT_SEPARATE')
    key = safe_file(backup_key, private=True, limit=32)
    if len(key) != 32:
        raise BackupError('BACKUP_KEY_INVALID')
    # Validate public-key path and bounded regular-file properties before verify.
    safe_file(publisher_key, limit=65536)
    with uterctl.locked(home):
        # Read every state/identity value after acquiring the operation lock.
        config, site, current = installation_metadata(home)
        expected_identity(config, site, backend, name, context)
        verify_current_bundle(home, current, publisher_key)
        pinned = safe_json(identity_file, private=True)
        if pinned != identity_record(home, site, observe_runtime(site)):
            raise BackupError('RUNTIME_IDENTITY_MISMATCH')
        validate_snapshot_sources(home)
        label = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(16)
        destination = backup_root / ('uter-' + label)
        if present(destination):
            raise BackupError('BACKUP_DESTINATION_EXISTS')
        # capture itself validates the live images, stops writers and resumes
        # them in a finally block. It retains its journal if resumption fails.
        try:
            metadata = backup_snapshot.capture(home, config, site, current, destination, key, leave_stopped=False)
            checked = backup_store.verify_set(destination, key, home=home, site=site, version=current['version'])
        except Exception:
            raise BackupError('BACKUP_FAILED_INSPECT_JOURNAL_AND_WORKLOADS') from None
        if checked != metadata:
            raise BackupError('BACKUP_VERIFICATION_FAILED')
        # The capture has resumed the writers. A recreated container or changed
        # deployment/PVC requires explicit re-registration before another run.
        if pinned != identity_record(home, site, observe_runtime(site)):
            raise BackupError('RUNTIME_IDENTITY_CHANGED_AFTER_BACKUP')
        return {'version': current['version'], 'backup': str(destination),
                'backup_id': metadata['id'], 'smoke': 'not_run'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('create-key', 'register', 'backup'))
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--backup-root', type=Path)
    parser.add_argument('--backup-key', type=Path)
    parser.add_argument('--publisher-key', type=Path)
    parser.add_argument('--identity-file', type=Path)
    parser.add_argument('--expected-backend', choices=('compose', 'kubernetes'))
    parser.add_argument('--expected-name')
    parser.add_argument('--expected-context')
    args = parser.parse_args(argv)
    try:
        if args.command == 'create-key':
            if not args.backup_root or not args.backup_key:
                raise BackupError('BACKUP_ARGUMENTS_REQUIRED')
            if any((args.publisher_key, args.identity_file, args.expected_backend, args.expected_name, args.expected_context)):
                raise BackupError('KEY_CREATION_ARGUMENTS_INVALID')
            result = create_key(args.home, args.backup_root, args.backup_key)
        elif args.command == 'register':
            if args.backup_root or args.backup_key:
                raise BackupError('REGISTRATION_BACKUP_ARGUMENTS_INVALID')
            if not all((args.publisher_key, args.identity_file, args.expected_backend, args.expected_name, args.expected_context)):
                raise BackupError('IDENTITY_ARGUMENTS_REQUIRED')
            result = register(args.home, args.identity_file, args.publisher_key, args.expected_backend,
                              args.expected_name, args.expected_context)
        else:
            if not args.backup_root or not args.backup_key:
                raise BackupError('BACKUP_ARGUMENTS_REQUIRED')
            if not all((args.publisher_key, args.identity_file, args.expected_backend, args.expected_name, args.expected_context)):
                raise BackupError('IDENTITY_ARGUMENTS_REQUIRED')
            result = {'result': 'verified', **backup(args.home, args.backup_root, args.backup_key,
                      args.publisher_key, args.identity_file, args.expected_backend, args.expected_name,
                      args.expected_context)}
    except BackupError as exc:
        print(json.dumps({'result': 'failed', 'code': str(exc)}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({'result': 'failed', 'code': 'BACKUP_FAILED_INSPECT_STATE'}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
