"""Experimental write-once statements for a future snapshot-only workflow.

No Redis, Docker, Kubernetes, backup or update operations are performed here.
A valid HMAC shows only that a holder of the key wrote the statement: it is not
proof that a fence was continuous, that a snapshot is genuine, or that writes
did not happen. The caller must hold an independently verified exclusive lock,
establish these facts before issuing a receipt, and ensure EVERY data-changing
path requires a durable mutation decision. Old controllers do not do so.

Trust: installation owner, secret key, every parent of the private directory,
host/kernel and local storage with the tested link/fsync semantics. A mutation
decision must be durably published before sending any mutation request. A release
decision and a mutation decision are mutually exclusive for this operation.
There is no production integration or automatic recovery in this module.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat

from scripts import backup_crypto

DESCRIPTOR='snapshot-only-transaction.json'
RECEIPT='snapshot-only-receipt.json'
DECISION='snapshot-only-decision.json'
LIMIT=8192
_FIELDS={
    'descriptor':frozenset(('schema','operation','backend','site','resource','release_version',
                            'bundle_sha256','fence_checkpoint_sha256','identity_sha256',
                            'backup_id','backup_location_sha256','executor_sha256')),
    'receipt':frozenset(('schema','operation','descriptor_sha256','backup_id','manifest_sha256')),
    'decision':frozenset(('schema','operation','descriptor_sha256','receipt_sha256','action')),
}
_FILES={'descriptor':DESCRIPTOR,'receipt':RECEIPT,'decision':DECISION}


class SnapshotRecordError(ValueError): pass


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def _derived_key(key):
    if not isinstance(key,bytes) or len(key)!=32:raise SnapshotRecordError('SNAPSHOT_RECORD_KEY')
    return backup_crypto.derive_key(key,b'snapshot-only-records-v1')


def _mac(kind, data, key):
    return hmac.new(_derived_key(key),kind.encode('ascii')+b'\x00'+_canonical(data),hashlib.sha256).hexdigest()


def _valid_hex(value,length):
    return isinstance(value,str) and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is not None


def _validate(kind,value):
    try:
        if (kind not in _FIELDS or not isinstance(value,dict) or set(value)!=_FIELDS[kind]
                or type(value['schema']) is not int or value['schema']!=1
                or not _valid_hex(value['operation'],32)):
            raise ValueError
        if kind=='descriptor':
            if (value['backend'] not in ('compose','kubernetes')
                    or not isinstance(value['site'],str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,40}',value['site'])
                    or not isinstance(value['resource'],str)
                    or not re.fullmatch(r'[0-9a-f]{64}' if value['backend']=='compose'
                                        else r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['resource'])
                    or not isinstance(value['release_version'],str)
                    or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?',value['release_version'])
                    or not _valid_hex(value['backup_id'],32)
                    or any(not _valid_hex(value[name],64) for name in ('bundle_sha256','fence_checkpoint_sha256',
                                                                      'identity_sha256','backup_location_sha256','executor_sha256'))):
                raise ValueError
        if kind=='receipt':
            if (not _valid_hex(value['descriptor_sha256'],64) or not _valid_hex(value['backup_id'],32)
                    or not _valid_hex(value['manifest_sha256'],64)):
                raise ValueError
        if kind=='decision':
            if (not _valid_hex(value['descriptor_sha256'],64) or not _valid_hex(value['receipt_sha256'],64)
                    or value['action'] not in ('release','mutation')):
                raise ValueError
        return value
    except (ValueError,TypeError,KeyError):raise SnapshotRecordError('SNAPSHOT_RECORD_INVALID') from None


def _directory(home):
    if os.name!='posix' or not hasattr(os,'O_DIRECTORY') or not hasattr(os,'O_NOFOLLOW'):
        raise SnapshotRecordError('SNAPSHOT_RECORD_PLATFORM')
    fd=None
    try:
        fd=os.open(Path(home),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        info=os.fstat(fd)
        if info.st_uid!=os.geteuid() or info.st_mode & 0o077:raise ValueError
        return fd
    except (OSError,ValueError):
        if fd is not None:os.close(fd)
        raise SnapshotRecordError('SNAPSHOT_RECORD_DIRECTORY') from None


def _json_no_duplicates(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs)


def _read(directory,kind,key):
    try:
        fd=os.open(_FILES[kind],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        with os.fdopen(fd,'rb') as source:
            info=os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077
                    or info.st_nlink!=1 or info.st_size>LIMIT):raise ValueError
            raw=source.read(LIMIT+1)
        if len(raw)>LIMIT:raise ValueError
        envelope=_json_no_duplicates(raw)
        if not isinstance(envelope,dict) or set(envelope)!={'kind','record','mac'} or envelope['kind']!=kind:
            raise ValueError
        record=_validate(kind,envelope['record']);mac=envelope['mac']
        if not _valid_hex(mac,64) or not hmac.compare_digest(mac,_mac(kind,record,key)):raise ValueError
        return record,hashlib.sha256(raw).hexdigest()
    except SnapshotRecordError:raise
    except (OSError,ValueError,TypeError,UnicodeError):raise SnapshotRecordError('SNAPSHOT_RECORD_UNREADABLE') from None


def _write(directory,kind,record,key):
    """Create without replacing; an uncertain result is NEVER silently undone."""
    record=_validate(kind,record)
    raw=_canonical({'kind':kind,'record':record,'mac':_mac(kind,record,key)})+b'\n'
    if len(raw)>LIMIT:raise SnapshotRecordError('SNAPSHOT_RECORD_INVALID')
    name='.snapshot-record-'+secrets.token_hex(16)+'.tmp';fd=None
    try:
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
        with os.fdopen(fd,'wb') as output:
            fd=None;os.fchmod(output.fileno(),0o600);output.write(raw);output.flush();os.fsync(output.fileno())
        os.link(name,_FILES[kind],src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
        os.fsync(directory)
        os.unlink(name,dir_fd=directory)
        os.fsync(directory)
        return hashlib.sha256(raw).hexdigest()
    except OSError:raise SnapshotRecordError('SNAPSHOT_RECORD_WRITE_UNCERTAIN') from None
    finally:
        if fd is not None:os.close(fd)
        # Temporary files are intentionally preserved after uncertainty. A
        # final name with two links is rejected on read, never auto-repaired.


def write_descriptor(home,key,record):
    directory=_directory(home)
    try:return _write(directory,'descriptor',record,key)
    finally:os.close(directory)


def read_descriptor(home,key):
    directory=_directory(home)
    try:return _read(directory,'descriptor',key)
    finally:os.close(directory)


def _linked_receipt(directory,key):
    descriptor,desc_hash=_read(directory,'descriptor',key)
    receipt,receipt_hash=_read(directory,'receipt',key)
    if (receipt['descriptor_sha256']!=desc_hash or receipt['operation']!=descriptor['operation']
            or receipt['backup_id']!=descriptor['backup_id']):
        raise SnapshotRecordError('SNAPSHOT_RECORD_BINDING')
    return descriptor,desc_hash,receipt,receipt_hash


def write_receipt(home,key,record):
    """Record the caller's assertion; this does not validate any backup."""
    directory=_directory(home)
    try:
        descriptor,digest=_read(directory,'descriptor',key)
        _validate('receipt',record)
        if (record['descriptor_sha256']!=digest or record['operation']!=descriptor['operation']
                or record['backup_id']!=descriptor['backup_id']):
            raise SnapshotRecordError('SNAPSHOT_RECORD_BINDING')
        return _write(directory,'receipt',record,key)
    finally:os.close(directory)


def read_receipt(home,key):
    directory=_directory(home)
    try:
        _,_,receipt,digest=_linked_receipt(directory,key)
        return receipt,digest
    finally:os.close(directory)


def write_decision(home,key,action):
    """Durably choose exactly one branch. Does not perform or authorize it."""
    directory=_directory(home)
    try:
        descriptor,desc_hash,_,receipt_hash=_linked_receipt(directory,key)
        record={'schema':1,'operation':descriptor['operation'],'descriptor_sha256':desc_hash,
                'receipt_sha256':receipt_hash,'action':action}
        return _write(directory,'decision',record,key)
    finally:os.close(directory)


def read_decision(home,key):
    directory=_directory(home)
    try:
        descriptor,desc_hash,_,receipt_hash=_linked_receipt(directory,key)
        decision,digest=_read(directory,'decision',key)
        if (decision['operation']!=descriptor['operation'] or decision['descriptor_sha256']!=desc_hash
                or decision['receipt_sha256']!=receipt_hash):raise SnapshotRecordError('SNAPSHOT_RECORD_BINDING')
        return decision,digest
    finally:os.close(directory)
