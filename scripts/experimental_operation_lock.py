"""Experimental PID-sentinel ownership; not used by uterctl.

Linux local filesystem only. Trust the host, its administrators, the private
installation directory and every ancestor, and assume a complete host PID/proc
namespace and local filesystem semantics. Comparing the controller's namespace
to /proc/1 does not prove it is the initial host namespace; this module does not
establish the filesystem's local nature. Older O_EXCL users do not take the gate, but cannot create a lock
while the sentinel exists. Unknown or legacy sentinel ownership is never
reclaimed. This protects controller exclusion only; it does not prove a Docker
or Kubernetes request has completed, nor authorise Redis recovery or updates.
Already submitted daemon/API requests may continue after controller death.

New owners and reclaimers must hold the same permanent flock gate throughout
their operation. A raw fork inherits it; an exec closes it. No code may unlink
or replace the gate. This module must not be mixed with other new lock managers.
After any call to release(), including a failed one, the caller must treat the
lease as lost: the sentinel may have been removed and acquired by an old user.
"""
import errno
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat

from scripts import backup_crypto

SENTINEL = 'operation.lock'
OWNER = 'operation-lock-owner.json'
GATE = '.operation-lock-gate'
MAX_BYTES = 4096


class LockError(ValueError):
    pass


def _identity(pid):
    text = Path('/proc').joinpath(str(pid), 'stat').read_text(encoding='ascii')
    end = text.rfind(')')
    parts = text[end + 2:].split()
    if end < 0 or len(parts) < 20 or not parts[19].isdigit():
        raise LockError('LOCK_PROCESS_UNVERIFIED')
    return int(parts[19])


def _boot():
    value = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value):
        raise LockError('LOCK_BOOT_UNVERIFIED')
    return value


def _host_pid_namespace():
    first, second = os.stat('/proc/self/ns/pid'), os.stat('/proc/1/ns/pid')
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _key(key):
    if not isinstance(key, bytes) or len(key) != 32:
        raise LockError('LOCK_KEY_INVALID')
    return backup_crypto.derive_key(key, b'experimental-operation-lock-owner')


def _canonical(record):
    return json.dumps(record, sort_keys=True, separators=(',', ':')).encode('ascii')


def _seal(record, key):
    return _canonical({'record': record, 'mac': hmac.new(_key(key), _canonical(record), hashlib.sha256).hexdigest()}) + b'\n'


def _write_all(fd, content):
    view = memoryview(content)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise LockError('LOCK_WRITE_FAILED')
        view = view[written:]


def _regular(fd):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise LockError('LOCK_FILE_UNSAFE')
    return info


def _open_read(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        info = _regular(fd)
        raw = os.read(fd, MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise LockError('LOCK_FILE_UNSAFE')
        return info, raw
    finally:
        os.close(fd)


def _read_owner(directory, key):
    info, raw = _open_read(directory, OWNER)
    if info.st_nlink != 1:
        raise LockError('LOCK_METADATA_UNSAFE')
    try:
        outer = json.loads(raw)
        if not isinstance(outer, dict) or set(outer) != {'record', 'mac'}:
            raise ValueError
        record, mac = outer['record'], outer['mac']
        fields = {'schema', 'operation', 'pid', 'start', 'boot', 'dev', 'ino', 'nonce', 'anchor'}
        if (not isinstance(record, dict) or set(record) != fields or type(record['schema']) is not int
                or record['schema'] != 1 or type(record['pid']) is not int or record['pid'] <= 1
                or type(record['start']) is not int or record['start'] < 0
                or type(record['dev']) is not int or record['dev'] < 0
                or type(record['ino']) is not int or record['ino'] <= 0
                or not isinstance(record['operation'], str) or not re.fullmatch(r'[0-9a-f]{32}', record['operation'])
                or not isinstance(record['nonce'], str) or not re.fullmatch(r'[0-9a-f]{32}', record['nonce'])
                or record['anchor'] != '.operation-owner-' + record['nonce'] + '.anchor'
                or not isinstance(record['boot'], str) or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', record['boot'])
                or not isinstance(mac, str) or not re.fullmatch(r'[0-9a-f]{64}', mac)
                or not hmac.compare_digest(mac, hmac.new(_key(key), _canonical(record), hashlib.sha256).hexdigest())):
            raise ValueError
        return record
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        raise LockError('LOCK_METADATA_INVALID') from None


def _assert_owner(directory, record):
    sentinel, raw = _open_read(directory, SENTINEL)
    anchor, anchored = _open_read(directory, record['anchor'])
    expected = (record['dev'], record['ino'])
    if ((sentinel.st_dev, sentinel.st_ino) != expected or (anchor.st_dev, anchor.st_ino) != expected
            or sentinel.st_nlink != 2 or anchor.st_nlink != 2
            or raw != str(record['pid']).encode('ascii') or anchored != raw):
        raise LockError('LOCK_OWNER_UNVERIFIED')


def _make(directory, operation, key):
    nonce = secrets.token_hex(16)
    temp = '.operation-owner-' + nonce + '.tmp'
    anchor = '.operation-owner-' + nonce + '.anchor'
    pid = os.getpid()
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        _write_all(fd, str(pid).encode('ascii'))
        os.fsync(fd)
        info = _regular(fd)
        record = {'schema': 1, 'operation': operation, 'pid': pid, 'start': _identity(pid), 'boot': _boot(),
                  'dev': info.st_dev, 'ino': info.st_ino, 'nonce': nonce, 'anchor': anchor}
    finally:
        os.close(fd)
    os.link(temp, anchor, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
    os.fsync(directory)
    meta = '.operation-owner-' + nonce + '.json.tmp'
    fd = os.open(meta, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        _write_all(fd, _seal(record, key))
        os.fsync(fd)
    finally:
        os.close(fd)
    return temp, meta, record


class Lease:
    """Explicit lifetime; close preserves the sentinel and all recovery evidence."""
    def __init__(self, home, key, operation):
        _key(key)
        if not isinstance(operation, str) or not re.fullmatch(r'[0-9a-f]{32}', operation):
            raise LockError('LOCK_OPERATION_INVALID')
        self.directory = None
        self.gate = None
        self.key = key
        self.operation = operation
        self.record = None
        try:
            if not _host_pid_namespace():
                raise LockError('LOCK_PID_NAMESPACE_UNSUPPORTED')
            self.directory = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(self.directory)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise LockError('LOCK_DIRECTORY_UNSAFE')
            self.gate = os.open(GATE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.directory)
            gate_info = _regular(self.gate)
            path_info = os.stat(GATE, dir_fd=self.directory, follow_symlinks=False)
            if gate_info.st_nlink != 1 or (gate_info.st_dev, gate_info.st_ino) != (path_info.st_dev, path_info.st_ino):
                raise LockError('LOCK_GATE_UNSAFE')
            try:
                fcntl.flock(self.gate, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LockError('LOCK_GATE_BUSY') from None
        except BaseException:
            self.close()
            raise

    def acquire(self):
        if self.record is not None:
            raise LockError('LOCK_ALREADY_OWNED')
        try:
            # Do not replace a prior metadata file or an old O_EXCL sentinel.
            for name in (OWNER, SENTINEL):
                try:
                    os.stat(name, dir_fd=self.directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise LockError('LOCK_ALREADY_PRESENT')
            temp, meta, record = _make(self.directory, self.operation, self.key)
            os.link(temp, SENTINEL, src_dir_fd=self.directory, dst_dir_fd=self.directory, follow_symlinks=False)
            os.unlink(temp, dir_fd=self.directory)
            os.fsync(self.directory)
            os.link(meta, OWNER, src_dir_fd=self.directory, dst_dir_fd=self.directory, follow_symlinks=False)
            os.unlink(meta, dir_fd=self.directory)
            os.fsync(self.directory)
            _assert_owner(self.directory, record)
            self.record = record
        except LockError:
            raise
        except Exception:
            # Partial files remain as evidence. Never blindly unlink a sentinel.
            raise LockError('LOCK_ACQUIRE_UNCERTAIN') from None

    def reclaim(self):
        if self.record is not None:
            raise LockError('LOCK_ALREADY_OWNED')
        try:
            old = _read_owner(self.directory, self.key)
            if old['operation'] != self.operation or old['boot'] != _boot():
                raise LockError('LOCK_OWNER_UNVERIFIED')
            _assert_owner(self.directory, old)
            try:
                os.kill(old['pid'], 0)
            except ProcessLookupError:
                pass
            except PermissionError:
                raise LockError('LOCK_OWNER_LIVE_OR_UNKNOWN') from None
            else:
                # Even a different start time could be PID reuse. Refuse.
                raise LockError('LOCK_OWNER_LIVE_OR_UNKNOWN')
            temp, meta, record = _make(self.directory, self.operation, self.key)
            # Recheck under the gate immediately before the atomic replacement.
            _assert_owner(self.directory, old)
            os.replace(temp, SENTINEL, src_dir_fd=self.directory, dst_dir_fd=self.directory)
            os.fsync(self.directory)
            os.replace(meta, OWNER, src_dir_fd=self.directory, dst_dir_fd=self.directory)
            os.fsync(self.directory)
            _assert_owner(self.directory, record)
            self.record = record
        except LockError:
            raise
        except Exception:
            # If replaced but metadata not yet switched, the mismatch is a
            # deliberate unrecoverable automatic state. Keep both anchors.
            raise LockError('LOCK_RECLAIM_UNCERTAIN') from None

    def release(self):
        record = self.record
        # Release is one-way even on an exception: unlink may have succeeded.
        self.record = None
        if record is None:
            raise LockError('LOCK_NOT_OWNED')
        if record['pid'] != os.getpid() or record['start'] != _identity(os.getpid()):
            raise LockError('LOCK_OWNER_UNVERIFIED')
        if _read_owner(self.directory, self.key) != record:
            raise LockError('LOCK_OWNER_UNVERIFIED')
        _assert_owner(self.directory, record)
        # Afterwards old O_EXCL users may acquire immediately. Never touch the
        # sentinel again; remove only the matching old metadata and anchor.
        os.unlink(SENTINEL, dir_fd=self.directory)
        os.fsync(self.directory)
        os.unlink(OWNER, dir_fd=self.directory)
        os.unlink(record['anchor'], dir_fd=self.directory)
        os.fsync(self.directory)

    def close(self):
        if self.gate is not None:
            os.close(self.gate)
            self.gate = None
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None
