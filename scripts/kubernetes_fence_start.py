"""Experimental stop and loopback sequence; not an update or backup command.

The trusted operator must provision and enforce the independently pinned
profile, control plane, nodes, admission/RBAC, CNI, CSI and exclusive writers.
This sequence deliberately stops before backup, health and writer resumption.
Do not expose as a user command until the complete recovery path is proven.
"""
import time

from scripts import (backup_installation, kubernetes_audit_reader_plan as audit_plan,
                     kubernetes_audit_writer_guard as audit_guard,
                     kubernetes_config_snapshot as config_snapshot,
                     kubernetes_fence_finalizer as finalizer, kubernetes_fence_recovery_session as recovery,
                     kubernetes_loopback_auth as loopback_auth,
                     kubernetes_loopback_intent as loopback, kubernetes_redis_finalizer_release as redis_release,
                     kubernetes_redis_shutdown as shutdown, kubernetes_writer_finalizer as writer_finalizer,
                     kubernetes_writer_quiesce as writers)


class StartError(ValueError):pass


def _wait(check,timeout):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:return check()
        except Exception:time.sleep(.5)
    raise StartError('KUBE_START_OBSERVATION_UNCERTAIN')


def start(session,operation,*,timeout=180):
    """Submit each guarded mutation at most once and retain evidence on error."""
    try:
        if session._executor is None or session._record['schema']!=2 or type(timeout) is not int or not 1<=timeout<=180:
            raise ValueError
        home=session.home
        key=backup_installation.safe_file(session._key_path,private=True,limit=32)
        if len(key)!=32:raise ValueError
        plan=finalizer.read_plan(home)
        finalizer._check_journal(home,plan,operation,'prepared')
        session.reverify()
        writers.prepare(home,session,operation,session.writer_uids,key)
        for service in writers.SERVICES:writer_finalizer.prepare(home,session,operation,service,key)
        recovery.seal_before_mutation(session,operation,key)
        config_snapshot.prepare(session,operation,key)
        audit_plan.prepare(session,operation,key)
        for service in writers.SERVICES:writer_finalizer.hold(home,session,operation,service,key)
        for service in writers.SERVICES:writers.stop(home,session,operation,service,key)
        for service in writers.SERVICES:
            _wait(lambda:writer_finalizer.observe(home,session,operation,service,key),timeout)
            writer_finalizer.release(home,session,operation,service,key)
        _wait(lambda:writers.observe_stopped(home,session,operation,key),timeout)
        audit_guard.seal(session,operation,key)
        finalizer.hold(home,plan,operation,session.api)
        loopback.prepare(home,plan,operation,session.api)
        loopback_auth.seal(session,operation,key,'forward')
        loopback.request(home,plan,operation,session.api)
        _wait(lambda:shutdown.observe(home,plan,operation,session.api),timeout)
        redis_release.release(home,session,operation,key)
        return {'redis_finalizer_release_requested':True,'complete_backup':False,
                'redis_isolated':False,'safe_to_backup':False,'safe_to_update':False}
    except Exception:raise StartError('KUBE_START_UNCERTAIN_INSPECTION_REQUIRED') from None
