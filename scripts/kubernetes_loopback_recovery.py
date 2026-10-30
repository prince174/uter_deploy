"""Experimental one-shot return from a Redis loopback Deployment.

This records one API intent and observes its outcome. It is NOT a fence,
does not resume writers or release finalizers, and cannot authorize an update.
The caller must own the controller lock and prove cluster, signed release, data,
writer quiescence and termination of all preceding operations independently.
Timeouts never justify retrying a possibly in-flight request.
"""
import json
import os
import stat

from scripts import kubernetes_loopback_intent as forward
from scripts import redis_fence_journal as journal

NAME = 'redis-loopback-recovery.json'
ATTEMPT_NAME = 'redis-loopback-recovery-attempt.json'
MAX_BYTES = 4096
FIELDS = frozenset(('schema', 'operation', 'context', 'namespace', 'deployment',
                    'uid', 'resource_version', 'original_hash', 'loopback_hash'))


class RecoveryError(ValueError): pass


def _read(directory, name):
    fd=journal._directory(directory)
    try:
        try:
            handle=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            with os.fdopen(handle,'rb') as source:
                info=os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                        or info.st_nlink!=1 or info.st_mode&0o077 or info.st_size>MAX_BYTES):
                    raise ValueError
                raw=source.read(MAX_BYTES+1)
            if len(raw)>MAX_BYTES:raise ValueError
            return json.loads(raw)
        except (OSError,ValueError,UnicodeError,TypeError):
            raise RecoveryError('KUBE_RECOVERY_RECORD_UNREADABLE') from None
    finally:os.close(fd)


def _write_once(directory, name, value):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    if len(raw)>MAX_BYTES:raise RecoveryError('KUBE_RECOVERY_RECORD_INVALID')
    fd=journal._directory(directory)
    try:
        try:
            handle=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(handle,'wb') as target:
                os.fchmod(target.fileno(),0o600);target.write(raw);target.flush();os.fsync(target.fileno())
            os.fsync(fd)
        except OSError:raise RecoveryError('KUBE_RECOVERY_WRITE_UNCERTAIN') from None
    finally:os.close(fd)


def _bound(directory, plan, operation, api):
    try:
        forward._bound(directory,plan,operation,api)
        orig=forward._read(directory)
        if (orig['operation']!=operation or orig['context']!=api.context
                or orig['namespace']!=api.namespace):raise ValueError
        return orig
    except Exception:raise RecoveryError('KUBE_RECOVERY_CONTEXT_CHANGED') from None


def _record(directory, plan, operation, api):
    orig=_bound(directory,plan,operation,api)
    value=_read(directory,NAME)
    try:
        if not isinstance(value,dict) or set(value)!=FIELDS or type(value['schema']) is not int or value['schema']!=1:
            raise ValueError
        for field in ('operation','context','namespace','deployment','uid','original_hash','loopback_hash'):
            if value[field]!=orig[field]:raise ValueError
        if (not isinstance(value['resource_version'],str) or not value['resource_version'].isdigit()
                or len(value['resource_version'])>32):raise ValueError
        return value,orig
    except (KeyError,ValueError,TypeError):raise RecoveryError('KUBE_RECOVERY_RECORD_INVALID') from None


def prepare(directory,plan,operation,api):
    """Record current loopback spec and exact UID/RV before a reverse patch."""
    orig=_bound(directory,plan,operation,api)
    try:
        deployment=api.get_deployment(orig['deployment'])
        meta,spec,container=forward._deployment(orig,deployment)
        if forward._hash(spec)!=orig['loopback_hash'] or container.get('args')!=[forward.LOOPBACK]:raise ValueError
        record={'schema':1,'operation':operation,'context':orig['context'],'namespace':orig['namespace'],
                'deployment':orig['deployment'],'uid':orig['uid'],'resource_version':meta['resourceVersion'],
                'original_hash':orig['original_hash'],'loopback_hash':orig['loopback_hash']}
        _write_once(directory,NAME,record)
        return record
    except RecoveryError:raise
    except Exception:raise RecoveryError('KUBE_RECOVERY_PREPARE_UNCERTAIN') from None


def classify(directory,plan,operation,api):
    """Read current spec only; no outcome proves Redis is healthy or isolated."""
    record,orig=_record(directory,plan,operation,api)
    try:
        meta,spec,_=forward._deployment(orig,api.get_deployment(record['deployment']))
        observed=forward._hash(spec)
        if observed==record['loopback_hash'] and meta['resourceVersion']==record['resource_version']:
            state='loopback_observed'
        elif observed==record['original_hash']:
            state='original_spec_observed'
        else:raise ValueError
        return {'state':state,'redis_healthy':False,'safe_to_resume':False}
    except Exception:raise RecoveryError('KUBE_RECOVERY_RESULT_UNCERTAIN') from None


def request(directory,plan,operation,api):
    """Submit at most one UID/RV/args-guarded reverse PATCH."""
    record,_=_record(directory,plan,operation,api)
    try:
        if os.path.lexists(os.path.join(directory,ATTEMPT_NAME)):raise ValueError
        if classify(directory,plan,operation,api)['state']!='loopback_observed':raise ValueError
        _write_once(directory,ATTEMPT_NAME,{'operation':operation,'intent_sha256':forward._hash(record)})
        ops=[{'op':'test','path':'/metadata/uid','value':record['uid']},
             {'op':'test','path':'/metadata/resourceVersion','value':record['resource_version']},
             {'op':'test','path':'/spec/template/spec/containers/0/args','value':[forward.LOOPBACK]},
             {'op':'replace','path':'/spec/template/spec/containers/0/args','value':[forward.identity.COMMAND]}]
        api.patch_deployment(record['deployment'],ops)
        if classify(directory,plan,operation,api)['state']!='original_spec_observed':raise ValueError
    except Exception:raise RecoveryError('KUBE_RECOVERY_REQUEST_UNCERTAIN') from None
    return {'state':'original_spec_observed','redis_healthy':False,'safe_to_resume':False}
