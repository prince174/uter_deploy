"""Authenticated, write-once observation for experimental Compose recovery.

This is not a fence and says nothing about data writes after capture. The host,
operation lock and installation directory must be trusted. This file deliberately
contains no Redis contents, passwords or arbitrary firewall rules.
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

NAME='compose-ns-checkpoint.json'
FIELDS=frozenset(('schema','operation','site','resource','plan_sha256','boot_id',
                  'pid','pid_start','net_dev','net_ino','firewall_sha256'))
LIMIT=4096


class CheckpointError(ValueError): pass


def _encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


def _key(key):
    if not isinstance(key,bytes) or len(key)!=32:raise CheckpointError('NS_CHECKPOINT_KEY')
    return backup_crypto.derive_key(key,b'compose-namespace-recovery')


def validate(value,record):
    try:
        if not isinstance(value,dict) or set(value)!=FIELDS or type(value['schema']) is not int or value['schema']!=1:
            raise ValueError
        if any(value[k]!=record[k] for k in ('operation','site','resource','plan_sha256')):raise ValueError
        if (not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value['boot_id'])
                or not re.fullmatch(r'[0-9a-f]{64}',value['firewall_sha256'])
                or any(type(value[k]) is not int or value[k]<=0 for k in ('pid','pid_start','net_dev','net_ino'))):
            raise ValueError
        return value
    except (KeyError,TypeError,ValueError):raise CheckpointError('NS_CHECKPOINT_INVALID') from None


def _directory(path):
    if os.name!='posix' or not hasattr(os,'O_NOFOLLOW') or not hasattr(os,'O_DIRECTORY'):
        raise CheckpointError('NS_CHECKPOINT_PLATFORM')
    try:
        fd=os.open(Path(path),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        info=os.fstat(fd)
        if info.st_uid!=os.geteuid() or info.st_mode & 0o077:
            os.close(fd);raise CheckpointError('NS_CHECKPOINT_DIRECTORY')
        return fd
    except CheckpointError:raise
    except OSError:raise CheckpointError('NS_CHECKPOINT_DIRECTORY') from None


def create(directory,record,value,key):
    """Fsync data and directory before the journal permits any mutation."""
    validate(value,record)
    envelope={'data':value,'mac':hmac.new(_key(key),_encoded(value),hashlib.sha256).hexdigest()}
    raw=_encoded(envelope)+b'\n'
    if len(raw)>LIMIT:raise CheckpointError('NS_CHECKPOINT_INVALID')
    dirfd=_directory(directory);name='.ns-checkpoint-'+secrets.token_hex(16)+'.tmp';fd=None
    try:
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dirfd)
        with os.fdopen(fd,'wb') as output:
            fd=None;os.fchmod(output.fileno(),0o600);output.write(raw);output.flush();os.fsync(output.fileno())
        os.link(name,NAME,src_dir_fd=dirfd,dst_dir_fd=dirfd,follow_symlinks=False)
        os.unlink(name,dir_fd=dirfd);os.fsync(dirfd)
    except OSError:raise CheckpointError('NS_CHECKPOINT_WRITE') from None
    finally:
        if fd is not None:os.close(fd)
        try:os.unlink(name,dir_fd=dirfd)
        except FileNotFoundError:pass
        finally:os.close(dirfd)


def read(directory,record,key):
    """Authenticate the full record before trusting observed resource IDs."""
    dirfd=_directory(directory)
    try:
        fd=os.open(NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=dirfd)
        with os.fdopen(fd,'rb') as source:
            info=os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
                    or info.st_mode & 0o077 or info.st_size>LIMIT):raise CheckpointError('NS_CHECKPOINT_FILE')
            raw=source.read(LIMIT+1)
        if len(raw)>LIMIT:raise ValueError
        value=json.loads(raw)
        if not isinstance(value,dict) or set(value)!={'data','mac'}:raise ValueError
        data=validate(value['data'],record);mac=value['mac']
        expected=hmac.new(_key(key),_encoded(data),hashlib.sha256).hexdigest()
        if not isinstance(mac,str) or not hmac.compare_digest(mac,expected):raise ValueError
        return data
    except CheckpointError:raise
    except (OSError,ValueError,TypeError,UnicodeError):raise CheckpointError('NS_CHECKPOINT_UNREADABLE') from None
    finally:os.close(dirfd)


def process_start(pid):
    try:
        value=(Path('/proc')/str(pid)/'stat').read_text(encoding='utf-8')
        before,separator,after=value.rpartition(') ')
        fields=after.split()
        if not separator or not before.startswith(str(pid)+' (') or len(fields)<20 or not fields[19].isdigit():raise ValueError
        return int(fields[19])
    except (OSError,UnicodeError,ValueError):raise CheckpointError('NS_CHECKPOINT_PROCESS') from None


def boot_id():
    try:
        value=Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
        if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value):raise ValueError
        return value
    except (OSError,UnicodeError,ValueError):raise CheckpointError('NS_CHECKPOINT_BOOT') from None
