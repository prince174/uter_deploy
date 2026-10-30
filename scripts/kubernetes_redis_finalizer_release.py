"""One-shot release after observing the exact old Redis process terminate.

This is not proof of unforced deletion, AOF/CSI durability or isolation. The
caller must hold the lock and use an authenticated, restricted session. An
uncertain patch is never retried and remains for operator investigation.
"""
from scripts import (kubernetes_fence_finalizer as finalizer,
                     kubernetes_loopback_intent as loopback,
                     kubernetes_redis_shutdown as shutdown,
                     kubernetes_writer_quiesce as storage)

MARKER='kubernetes-redis-finalizer-release-attempt.json'


class RedisReleaseError(ValueError):pass


def release(home,session,operation,key):
    try:
        plan=finalizer.read_plan(home)
        finalizer._check_journal(home,plan,operation,'isolating')
        session._scope()
        if loopback.classify(home,plan,operation,session.api)['state']!='loopback_spec_observed':raise ValueError
        class Observation:
            context=session.api.context
            namespace=session.api.namespace
            pod=None
            def get(self,name):
                self.pod=session.api.get(name)
                return self.pod
        observation=Observation()
        shutdown.observe(home,plan,operation,observation)
        rv=observation.pod['metadata']['resourceVersion']
        record={'operation':operation,'pod_plan_sha256':finalizer.plan_hash(plan),'resource_version':rv}
        storage._write(home,MARKER,record,key)
        token=finalizer._token(operation)
        ops=[{'op':'test','path':'/metadata/uid','value':plan['uid']},
             {'op':'test','path':'/metadata/resourceVersion','value':rv},
             {'op':'test','path':'/metadata/finalizers','value':[token]},
             {'op':'remove','path':'/metadata/finalizers/0'}]
        session.api.patch(plan['pod'],ops)
        return {'result':'redis_finalizer_release_requested','safe_to_backup':False,'safe_to_update':False}
    except Exception:raise RedisReleaseError('KUBE_REDIS_FINALIZER_RELEASE_UNCERTAIN') from None
