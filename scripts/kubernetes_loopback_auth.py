"""Authenticate loopback intent before its one-shot mutation."""
from scripts import (backup_installation, kubernetes_fence_finalizer as finalizer,
                     kubernetes_loopback_intent as forward, kubernetes_loopback_recovery as reverse,
                     kubernetes_writer_quiesce as storage)


class IntentAuthError(ValueError):pass


def _value(session,operation,key,direction):
    if session._executor is None or session._record['schema']!=2:raise ValueError
    if backup_installation.safe_file(session._key_path,private=True,limit=32)!=key:raise ValueError
    plan=finalizer.read_plan(session.home)
    forward._bound(session.home,plan,operation,session.api)
    if direction=='forward':record=forward._read(session.home)
    elif direction=='reverse':record,_=reverse._record(session.home,plan,operation,session.api)
    else:raise ValueError
    if record['operation']!=operation:raise ValueError
    binding=storage._read(session.home,'kubernetes-fence-recovery-auth.json',key)
    return {'operation':operation,'intent_sha256':forward._hash(record),'binding_sha256':storage._hash(binding)}


def seal(session,operation,key,direction):
    try:
        value=_value(session,operation,key,direction)
        storage._write(session.home,'kubernetes-loopback-'+direction+'-auth.json',value,key)
    except Exception:raise IntentAuthError('KUBE_LOOPBACK_AUTH_UNVERIFIED') from None


def verify(session,operation,key,direction):
    try:
        expected=_value(session,operation,key,direction)
        if storage._read(session.home,'kubernetes-loopback-'+direction+'-auth.json',key)!=expected:raise ValueError
    except Exception:raise IntentAuthError('KUBE_LOOPBACK_AUTH_UNVERIFIED') from None
