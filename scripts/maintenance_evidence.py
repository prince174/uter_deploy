"""Experimental write-once maintenance evidence bound to a fence journal.

This module does not block mutations by itself, hold a lock, inspect a workload,
or authorize backup/update. A production adapter must retain the blocking
journal throughout and establish a tested cleanup/recovery protocol.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat

from scripts import backup_crypto, maintenance_receipt, redis_fence_journal as journal

_BOOT = re.compile(r'[0-9a-f]{32}\Z')
_LIMIT = 32768


class EvidenceError(ValueError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError
        result[key] = value
    return result


class Recorder:
    """Write evidence once while the caller holds and proves its operation lock."""
    def __init__(self, home, key, *, operation, backend, plan_sha256, lock_guard):
        if (not isinstance(key, bytes) or len(key) != 32 or backend not in ('compose', 'kubernetes')
                or not isinstance(operation, str) or not re.fullmatch(r'[0-9a-f]{32}', operation)
                or not isinstance(plan_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', plan_sha256)
                or not callable(lock_guard)):
            raise EvidenceError('MAINTENANCE_EVIDENCE_ARGUMENT_INVALID')
        self.home = Path(home)
        self.key = backup_crypto.derive_key(key, b'maintenance-evidence-v1')
        self.operation, self.backend, self.plan = operation, backend, plan_sha256
        self.lock_guard = lock_guard
        self._guard()

    def _guard(self):
        try:
            if self.lock_guard() is not True:
                raise ValueError
            state = journal.read(self.home)
            if (state['operation'] != self.operation or state['backend'] != self.backend
                    or state['plan_sha256'] != self.plan or state['phase'] != 'prepared'):
                raise ValueError
        except Exception:
            raise EvidenceError('MAINTENANCE_EVIDENCE_SCOPE_UNVERIFIED') from None

    def _identity(self, service, instance, boot):
        if (service not in ('agent', 'guardrail') or not isinstance(instance, str)
                or not instance or len(instance) > 256 or not isinstance(boot, str) or not _BOOT.fullmatch(boot)):
            raise EvidenceError('MAINTENANCE_EVIDENCE_ARGUMENT_INVALID')
        identity = hashlib.sha256(instance.encode('utf-8')).hexdigest()
        return {'schema': 1, 'operation': self.operation, 'backend': self.backend,
                'plan_sha256': self.plan, 'service': service, 'instance_sha256': identity, 'boot_id': boot}

    def _name(self, kind, identity):
        return 'maintenance-' + kind + '-' + identity['instance_sha256'] + '.json'

    def _write(self, name, value):
        self._guard()
        raw = _canonical({'record': value, 'mac': hmac.new(self.key, _canonical(value), hashlib.sha256).hexdigest()}) + b'\n'
        if len(raw) > _LIMIT:
            raise EvidenceError('MAINTENANCE_EVIDENCE_INVALID')
        directory = journal._directory(self.home)
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as out:
                os.fchmod(out.fileno(), 0o600); out.write(raw); out.flush(); os.fsync(out.fileno())
            os.fsync(directory)
        except OSError:
            raise EvidenceError('MAINTENANCE_EVIDENCE_WRITE_UNCERTAIN') from None
        finally:
            os.close(directory)
        self._guard()
        if self._read(name) != value:
            raise EvidenceError('MAINTENANCE_EVIDENCE_UNVERIFIED')

    def _read(self, name):
        self._guard()
        directory = journal._directory(self.home)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                        or info.st_mode & 0o077 or info.st_size > _LIMIT):
                    raise ValueError
                raw = stream.read(_LIMIT+1)
            if len(raw) > _LIMIT:
                raise ValueError
            envelope = json.loads(raw, object_pairs_hook=_pairs)
            if not isinstance(envelope, dict) or set(envelope) != {'record', 'mac'} or not isinstance(envelope['record'], dict):
                raise ValueError
            expected = hmac.new(self.key, _canonical(envelope['record']), hashlib.sha256).hexdigest()
            if not isinstance(envelope['mac'], str) or not hmac.compare_digest(envelope['mac'], expected):
                raise ValueError
            return envelope['record']
        except (OSError, ValueError, TypeError, UnicodeDecodeError):
            raise EvidenceError('MAINTENANCE_EVIDENCE_UNVERIFIED') from None
        finally:
            os.close(directory)

    def intent(self, service, instance, boot):
        identity = self._identity(service, instance, boot)
        self._write(self._name('intent', identity), identity)
        return True

    def receipt(self, service, instance, boot, value):
        identity = self._identity(service, instance, boot)
        if self._read(self._name('intent', identity)) != identity:
            raise EvidenceError('MAINTENANCE_EVIDENCE_INTENT_UNVERIFIED')
        try:
            checked = maintenance_receipt.validate(_canonical(value), service=service, expected_boot=boot)
        except maintenance_receipt.ReceiptError:
            raise EvidenceError('MAINTENANCE_EVIDENCE_RECEIPT_UNVERIFIED') from None
        self._write(self._name('receipt', identity), {'identity': identity, 'receipt': checked})
        return True
