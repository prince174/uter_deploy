"""Experimental one-shot reverse Redis rollout; writers remain stopped."""
import time

from scripts import (backup_installation, kubernetes_backup_coordinator as backup,
                     kubernetes_fence_finalizer as original, kubernetes_loopback_auth as auth,
                     kubernetes_loopback_recovery as reverse, kubernetes_redis_reverse_finalizer as pod)
from scripts import kubernetes_reverse_network_guard as network_guard


class RedisReverseError(ValueError):pass


def request(session,operation,destination,*,timeout=180):
    """Hold exact Pod, submit reverse once, observe exit and release once."""
    try:
        if session._executor is None or session._record['schema']!=2 or type(timeout) is not int or not 1<=timeout<=180:
            raise ValueError
        # The reverse Deployment can become network reachable before any
        # later data check; do not issue it without continuous exclusion.
        network_guard.assert_external_exclusion(session,operation)
        key=backup_installation.safe_file(session._key_path,private=True,limit=32)
        if len(key)!=32:raise ValueError
        record=pod._record(session,operation,key)
        backup.verify_receipt(session,operation,record['pod'],record['uid'],destination)
        pod.hold(session,operation,key)
        plan=original.read_plan(session.home)
        reverse.prepare(session.home,plan,operation,session.api)
        auth.seal(session,operation,key,'reverse')
        reverse.request(session.home,plan,operation,session.api)
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            try:
                if pod.observe(session,operation,key)['termination_observed'] is True:break
            except Exception:time.sleep(.5)
        else:raise ValueError
        pod.release(session,operation,key)
        return {'original_spec_observed':True,'loopback_pod_finalizer_release_requested':True,
                'writes_may_have_started':True,'data_verified':False,'safe_to_resume':False}
    except Exception:raise RedisReverseError('KUBE_REDIS_REVERSE_UNCERTAIN_INSPECTION_REQUIRED') from None
