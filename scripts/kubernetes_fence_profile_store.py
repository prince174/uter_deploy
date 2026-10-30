"""Immutable, authenticated operator-supplied pins for a strict Kube profile.

An HMAC detects changes to an already supplied profile; it does not prove the
operator's original values were independently verified. The API server and
nodes, admission/RBAC controllers, CNI/CSI and privileged administrators must be
trusted; absence of competing writers is never inferred from this file. No
data, credential, migration or update permission is contained in this record.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re

from scripts import backup_crypto, backup_installation, kubernetes_fence_pin as pin
from scripts import kubernetes_redis_identity as identity
from scripts import snapshot_only_receipts as records

LIMIT=16384
FIELDS=frozenset(('schema','site','api','writer_uids','release_version','inventory_sha256','publisher_sha256'))
FIELDS_V2=FIELDS|{'audit_pvc_uid','kubectl_sha256'}


class ProfileError(ValueError):pass


def _canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def _key(key):
    if not isinstance(key,bytes) or len(key)!=32:raise ProfileError('KUBE_PROFILE_KEY_INVALID')
    return backup_crypto.derive_key(key,b'kubernetes-operator-profile-v1')


def _validate(record):
    try:
        if (not isinstance(record,dict) or type(record.get('schema')) is not int
                or (record['schema']==1 and set(record)!=FIELDS)
                or (record['schema']==2 and set(record)!=FIELDS_V2)
                or record['schema'] not in (1,2)
                or not isinstance(record['site'],str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,40}',record['site'])
                or not isinstance(record['release_version'],str)
                or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?',record['release_version'])
                or any(not isinstance(record[x],str) or not re.fullmatch(r'[0-9a-f]{64}',record[x])
                       for x in ('inventory_sha256','publisher_sha256'))):raise ValueError
        pin._profile(record['api'])
        writers=record['writer_uids']
        if (not isinstance(writers,dict) or set(writers)!={'guardrail','agent'}
                or any(not isinstance(x,str) or not identity.UUID.fullmatch(x) for x in writers.values())):raise ValueError
        ids=[record['api'][key] for key in ('kube_system_uid','namespace_uid','redis_pvc_uid','redis_deployment_uid')]
        if len(set(ids+list(writers.values())))!=6:raise ValueError
        if record['schema']==2:
            uid=record['audit_pvc_uid']
            binary=record['kubectl_sha256']
            if (not isinstance(uid,str) or not identity.UUID.fullmatch(uid) or uid in ids+list(writers.values())
                    or not isinstance(binary,str) or not re.fullmatch(r'[0-9a-f]{64}',binary)):raise ValueError
        return record
    except (ValueError,KeyError,TypeError):raise ProfileError('KUBE_PROFILE_INVALID') from None


def _path(path):
    value=Path(path)
    if not value.name or value.name in ('.','..') or '..' in value.parts:raise ProfileError('KUBE_PROFILE_PATH_INVALID')
    try:return backup_installation.private_directory(value.absolute().parent)/value.name
    except Exception:raise ProfileError('KUBE_PROFILE_PATH_INVALID') from None


def create(path,key,record):
    """Create once from independently verified operator inputs; never overwrite."""
    value=_validate(record);path=_path(path)
    envelope={'record':value,'mac':hmac.new(_key(key),_canonical(value),hashlib.sha256).hexdigest()}
    raw=_canonical(envelope)+b'\n'
    if len(raw)>LIMIT:raise ProfileError('KUBE_PROFILE_INVALID')
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as output:
            os.fchmod(output.fileno(),0o600);output.write(raw);output.flush();os.fsync(output.fileno())
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
    except OSError:raise ProfileError('KUBE_PROFILE_CREATE_UNCERTAIN') from None
    return hashlib.sha256(raw).hexdigest()


def read(path,key):
    """Authenticate the immutable profile without revealing path or contents."""
    try:
        path=_path(path)
        raw=backup_installation.safe_file(path,private=True,limit=LIMIT)
        envelope=records._json_no_duplicates(raw)
        if not isinstance(envelope,dict) or set(envelope)!={'record','mac'}:raise ValueError
        value=_validate(envelope['record']);mac=envelope['mac']
        if (not isinstance(mac,str) or not re.fullmatch(r'[0-9a-f]{64}',mac)
                or not hmac.compare_digest(mac,hmac.new(_key(key),_canonical(value),hashlib.sha256).hexdigest())):
            raise ValueError
        return value,hashlib.sha256(raw).hexdigest()
    except ProfileError:raise
    except Exception:raise ProfileError('KUBE_PROFILE_UNVERIFIED') from None
