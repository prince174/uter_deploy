"""Authenticated release origin for experimental Compose fence operations.

The write-once record distinguishes a pre-capture release from a release after
a verified snapshot. It must be persisted before the actual firewall release.
It does not itself prove continuous fencing, valid backup or trusted executor.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat

from scripts import backup_crypto, redis_fence_journal as journal

NAME='compose-fence-release-origin.json'
FIELDS={'schema','operation','site','resource','plan_sha256','origin','receipt_sha256'}


class OriginError(ValueError): pass


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def _mac(key,value):
    if not isinstance(key,bytes) or len(key)!=32:raise OriginError('FENCE_ORIGIN_KEY_INVALID')
    return hmac.new(backup_crypto.derive_key(key,b'compose-fence-release-origin-v1'),_canonical(value),hashlib.sha256).hexdigest()


def _validate(value,record):
    try:
        if (not isinstance(value,dict) or set(value)!=FIELDS or type(value['schema']) is not int or value['schema']!=1
                or value['origin'] not in ('pre_capture','snapshot')
                or any(value[k]!=record[k] for k in ('operation','site','resource','plan_sha256'))
                or not isinstance(value['receipt_sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',value['receipt_sha256'])
                or (value['origin']=='pre_capture' and value['receipt_sha256']!='0'*64)
                or (value['origin']=='snapshot' and value['receipt_sha256']=='0'*64)):
            raise ValueError
        return value
    except (KeyError,TypeError,ValueError):raise OriginError('FENCE_ORIGIN_INVALID') from None


def read(home,key,record):
    directory=journal._directory(home)
    try:
        try:
            fd=os.open(NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            with os.fdopen(fd,'rb') as source:
                info=os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077
                        or info.st_nlink!=1 or info.st_size>4096):raise ValueError
                raw=source.read(4097)
            if len(raw)>4096:raise ValueError
            def pairs(items):
                result={}
                for name,value in items:
                    if name in result:raise ValueError
                    result[name]=value
                return result
            envelope=json.loads(raw,object_pairs_hook=pairs)
            if not isinstance(envelope,dict) or set(envelope)!={'origin','mac'}:raise ValueError
            value=_validate(envelope['origin'],record);mac=envelope['mac']
            if (not isinstance(mac,str) or not re.fullmatch(r'[0-9a-f]{64}',mac)
                    or not hmac.compare_digest(mac,_mac(key,value))):raise ValueError
            return value
        except (OSError,ValueError,TypeError,UnicodeError):
            raise OriginError('FENCE_ORIGIN_UNVERIFIED') from None
    finally:os.close(directory)


def ensure(home,key,record,kind,receipt_hash='0'*64):
    """Durably create/verify one origin before touching the firewall."""
    if (kind=='pre_capture' and record.get('phase')!='pre_capture_aborting') or \
       (kind=='snapshot' and record.get('phase')!='snapshot_releasing'):
        raise OriginError('FENCE_ORIGIN_PHASE_INVALID')
    value=_validate({'schema':1,'operation':record['operation'],'site':record['site'],
                     'resource':record['resource'],'plan_sha256':record['plan_sha256'],
                     'origin':kind,'receipt_sha256':receipt_hash},record)
    if os.path.lexists(Path(home)/NAME):
        if read(home,key,record)!=value:raise OriginError('FENCE_ORIGIN_CONFLICT')
        return value
    raw=_canonical({'origin':value,'mac':_mac(key,value)})+b'\n'
    directory=journal._directory(home)
    try:
        try:
            fd=os.open(NAME,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as target:
                os.fchmod(target.fileno(),0o600);target.write(raw);target.flush();os.fsync(target.fileno())
            os.fsync(directory)
        except OSError:raise OriginError('FENCE_ORIGIN_WRITE_UNCERTAIN') from None
    finally:os.close(directory)
    if read(home,key,record)!=value:raise OriginError('FENCE_ORIGIN_UNVERIFIED')
    return value
