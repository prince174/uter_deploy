"""Durable state record for a future Redis fence, not a fencing mechanism.

The caller must hold the installation controller's exclusive operation lock for
the entire transaction. This file records no credentials or session contents.
A journal entry is never evidence that a network fence actually exists.
"""
import json
import os
from pathlib import Path
import re
import secrets
import stat

NAME = 'redis-fence-operation.json'
PHASES = ('prepared', 'isolating', 'isolated', 'capturing', 'captured', 'snapshot_releasing', 'releasing', 'aborting', 'pre_capture_aborting', 'redis_released', 'writers_resuming', 'writers_resumed', 'finalizing', 'restored')
TRANSITIONS = {
    'prepared': frozenset(('isolating', 'aborting', 'pre_capture_aborting')),
    'isolating': frozenset(('isolated', 'aborting', 'pre_capture_aborting')),
    'isolated': frozenset(('capturing', 'aborting', 'pre_capture_aborting')),
    'capturing': frozenset(('captured', 'aborting')),
    'captured': frozenset(('snapshot_releasing', 'releasing', 'aborting')),
    'snapshot_releasing': frozenset(('redis_released',)),
    'releasing': frozenset(('restored', 'aborting')),
    'aborting': frozenset(('restored', 'redis_released')),
    'pre_capture_aborting': frozenset(('redis_released',)),
    'redis_released': frozenset(('restored', 'writers_resuming')),
    'writers_resuming': frozenset(('writers_resumed',)),
    'writers_resumed': frozenset(('finalizing',)),
    'finalizing': frozenset(),
    'restored': frozenset(),
}
FIELDS = frozenset(('schema', 'operation', 'backend', 'site', 'resource', 'plan_sha256', 'phase'))
MAX_BYTES = 4096


class FenceJournalError(ValueError):
    pass


def _validate(record):
    if (not isinstance(record, dict) or set(record) != FIELDS or type(record['schema']) is not int
            or record['schema'] != 1 or record['backend'] not in ('compose', 'kubernetes')
            or not isinstance(record['operation'], str) or not re.fullmatch(r'[0-9a-f]{32}', record['operation'])
            or not isinstance(record['site'], str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', record['site'])
            or not isinstance(record['resource'], str)
            or not re.fullmatch(r'[0-9a-f]{64}' if record['backend'] == 'compose'
                                else r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', record['resource'])
            or not isinstance(record['plan_sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', record['plan_sha256'])
            or record['phase'] not in PHASES):
        raise FenceJournalError('FENCE_JOURNAL_INVALID')
    return record


def _directory(path):
    if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
        raise FenceJournalError('FENCE_JOURNAL_PLATFORM_UNSUPPORTED')
    fd = os.open(Path(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        os.close(fd)
        raise FenceJournalError('FENCE_JOURNAL_DIRECTORY_UNSAFE')
    return fd


def _read(fd):
    try:
        handle = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(handle, 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > MAX_BYTES):
                raise FenceJournalError('FENCE_JOURNAL_FILE_UNSAFE')
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise FenceJournalError('FENCE_JOURNAL_INVALID')
        return _validate(json.loads(raw))
    except FenceJournalError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError):
        raise FenceJournalError('FENCE_JOURNAL_UNREADABLE') from None


def read(directory):
    fd = _directory(directory)
    try:
        return _read(fd)
    finally:
        os.close(fd)


def _write(fd, record, *, create):
    raw = (json.dumps(_validate(record), sort_keys=True, separators=(',', ':')) + '\n').encode()
    name = '.redis-fence-' + secrets.token_hex(16) + '.tmp'
    tmp = None
    try:
        tmp = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(tmp, 'wb') as output:
            tmp = None
            os.fchmod(output.fileno(), 0o600)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        if create:
            os.link(name, NAME, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.unlink(name, dir_fd=fd)
        else:
            os.replace(name, NAME, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    except OSError:
        raise FenceJournalError('FENCE_JOURNAL_WRITE_FAILED') from None
    finally:
        if tmp is not None:
            os.close(tmp)
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass


def create(directory, *, backend, site, resource, plan_sha256, operation=None):
    if operation is None:
        operation = secrets.token_hex(16)
    record = {'schema': 1, 'operation': operation, 'backend': backend,
              'site': site, 'resource': resource, 'plan_sha256': plan_sha256, 'phase': 'prepared'}
    _validate(record)
    fd = _directory(directory)
    try:
        _write(fd, record, create=True)
    finally:
        os.close(fd)
    return record


def advance(directory, *, operation, expected, next_phase):
    """Record one transition; this does not perform or verify its side effects."""
    fd = _directory(directory)
    try:
        current = _read(fd)
        if (current['operation'] != operation or current['phase'] != expected
                or next_phase not in TRANSITIONS.get(expected, frozenset())):
            raise FenceJournalError('FENCE_JOURNAL_TRANSITION_REJECTED')
        updated = dict(current, phase=next_phase)
        _write(fd, updated, create=False)
        return updated
    finally:
        os.close(fd)
