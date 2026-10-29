#!/usr/bin/env python3
"""Render, but never install or enable, a Compose backup timer on Linux."""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import backup_installation as backup

PATH_CHARS = re.compile(r'/[A-Za-z0-9_./-]+\Z')
NAME = re.compile(r'[a-z][a-z0-9-]{0,38}[a-z0-9]\Z')
TIME = re.compile(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]\Z')
FINGERPRINT = re.compile(r'[0-9a-f]{64}\Z')


class RenderError(Exception):
    pass


def simple_path(value):
    value = str(value)
    if not PATH_CHARS.fullmatch(value) or any(part in ('.', '..', '') for part in value[1:].split('/')):
        raise RenderError('UNSAFE_PATH')
    return Path(value)


def checked_file(path, *, private=False, executable=False):
    path = backup.checked_existing_path(simple_path(path))
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
            or info.st_mode & 0o022 or (private and info.st_mode & 0o077)
            or (executable and not info.st_mode & 0o100)):
        raise RenderError('FILE_UNSAFE')
    return path


def secure_bundle(bundle, publisher_key, fingerprint):
    bundle = backup.checked_existing_path(simple_path(bundle))
    if not FINGERPRINT.fullmatch(fingerprint):
        raise RenderError('PUBLISHER_FINGERPRINT_INVALID')
    public = backup.safe_file(checked_file(publisher_key), limit=65536)
    if hashlib.sha256(public).hexdigest() != fingerprint:
        raise RenderError('PUBLISHER_FINGERPRINT_MISMATCH')
    backup.verify_tree(bundle)
    for root, dirs, files in os.walk(bundle, followlinks=False):
        for item in [Path(root), *(Path(root)/name for name in dirs+files)]:
            info = item.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise RenderError('BUNDLE_UNSAFE')
    try:
        manifest = uterctl.verify(bundle, publisher_key)
    except Exception:
        raise RenderError('BUNDLE_SIGNATURE_INVALID') from None
    tool = bundle/'scripts/backup_installation.py'
    checked_file(tool)
    return manifest, tool


def render_service(name, python, tool, home, backup_root, backup_key, identity_file, publisher_key):
    command = [python, '-I', tool, 'backup', '--home', home, '--backup-root', backup_root,
               '--backup-key', backup_key, '--identity-file', identity_file, '--publisher-key', publisher_key,
               '--expected-backend', 'compose', '--expected-name', name, '--expected-context', 'default']
    return ('[Unit]\nDescription=Uter encrypted backup (' + name + ')\n\n'
            '[Service]\nType=oneshot\nUser=root\n'
            'Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
            'UnsetEnvironment=DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG PYTHONPATH PYTHONHOME\n'
            'TimeoutStartSec=infinity\nExecStart=' + ' '.join(map(str, command)) + '\n')


def render_timer(name, clock):
    if not NAME.fullmatch(name) or not TIME.fullmatch(clock):
        raise RenderError('SCHEDULE_INVALID')
    return ('[Unit]\nDescription=Uter backup schedule (' + name + ')\n\n'
            '[Timer]\nOnCalendar=*-*-* ' + clock + ':00 UTC\nPersistent=false\n'
            'RandomizedDelaySec=5m\nUnit=uter-backup-' + name + '.service\n\n'
            '[Install]\nWantedBy=timers.target\n')


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def publish_no_replace(stage, destination):
    """Linux renameat2 is atomic and refuses an existing target, including symlinks."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, 'renameat2', None)
    if renameat2 is None:
        raise RenderError('ATOMIC_PUBLISH_UNSUPPORTED')
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(-100, os.fsencode(stage), -100, os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno()
        raise RenderError('OUTPUT_EXISTS' if code == errno.EEXIST else 'ATOMIC_PUBLISH_FAILED')


def generate(*, home, backup_root, backup_key, identity_file, publisher_key,
             publisher_sha256, bundle, python, name, schedule, output):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RenderError('LINUX_ROOT_REQUIRED')
    if not NAME.fullmatch(name) or not TIME.fullmatch(schedule):
        raise RenderError('NAME_OR_SCHEDULE_INVALID')
    home = backup.private_directory(simple_path(home))
    backup_root = backup.private_directory(simple_path(backup_root))
    identity_file = checked_file(identity_file, private=True)
    backup.private_directory(identity_file.parent)
    backup_key = checked_file(backup_key, private=True)
    backup.private_directory(backup_key.parent)
    if (backup_key.stat().st_size != 32 or home == backup_root
            or home.is_relative_to(backup_root) or backup_root.is_relative_to(home)
            or backup_key.is_relative_to(home) or backup_key.is_relative_to(backup_root)
            or identity_file.is_relative_to(home) or identity_file.is_relative_to(backup_root)
            or identity_file == backup_key):
        raise RenderError('BACKUP_PATHS_OR_KEY_INVALID')
    publisher_key = checked_file(publisher_key)
    if identity_file == publisher_key or backup_key == publisher_key:
        raise RenderError('BACKUP_PATHS_OR_KEY_INVALID')
    python = checked_file(python, executable=True)
    bundle_manifest, tool = secure_bundle(bundle, publisher_key, publisher_sha256)
    output = simple_path(output)
    parent = backup.private_directory(output.parent)
    output = parent/output.name
    if any(output == path or output.is_relative_to(path) or path.is_relative_to(output)
           for path in (home, backup_root, backup_key.parent, identity_file.parent, Path(bundle))):
        raise RenderError('OUTPUT_PATH_NOT_SEPARATE')
    if os.path.lexists(output):
        raise RenderError('OUTPUT_EXISTS')
    config, site, current = backup.installation_metadata(home)
    backup.expected_identity(config, site, 'compose', name, 'default')
    backup.verify_current_bundle(home, current, publisher_key)
    pinned = backup.safe_json(identity_file, private=True)
    if pinned != backup.identity_record(home, site, pinned.get('runtime')):
        raise RenderError('IDENTITY_MISMATCH')
    if not isinstance(pinned.get('runtime'), dict) or not pinned['runtime'].get('docker_daemon_id'):
        raise RenderError('IDENTITY_INVALID')
    # The command will validate key bytes, full identity and live workloads at run time.
    service = render_service(name, python, tool, home, backup_root, backup_key, identity_file, publisher_key)
    timer = render_timer(name, schedule)
    stage = Path(tempfile.mkdtemp(prefix='.uter-systemd-incomplete-', dir=parent))
    os.chmod(stage, 0o700)
    # If interrupted, the incomplete directory remains private and never installed.
    write_new(stage/'INCOMPLETE', 'Generation is incomplete. Do not install these files.\n')
    write_new(stage/('uter-backup-'+name+'.service'), service)
    write_new(stage/('uter-backup-'+name+'.timer'), timer)
    fsync_directory(stage)
    (stage/'INCOMPLETE').unlink()
    fsync_directory(stage)
    publish_no_replace(stage, output)
    fsync_directory(parent)
    return {'result': 'rendered', 'directory': str(output), 'tool_version': bundle_manifest['version'],
            'schedule_timezone': 'UTC', 'enabled': False, 'runtime_checked': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('home','backup-root','backup-key','identity-file','publisher-key','publisher-sha256',
                'bundle','python','name','schedule','output'):
        parser.add_argument('--'+arg, required=True)
    args = vars(parser.parse_args(argv))
    try:
        result = generate(**{k.replace('-', '_'): v for k, v in args.items()})
    except (RenderError, backup.BackupError) as exc:
        print(json.dumps({'result':'failed','code':str(exc)}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({'result':'failed','code':'RENDER_FAILED'}), file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    sys.exit(main())
