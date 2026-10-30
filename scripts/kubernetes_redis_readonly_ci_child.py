"""Disposable signed-executor child for real Redis read-only transport CI."""
import sys
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import uterctl
from scripts import (kubernetes_fence_coordinator, kubernetes_fence_finalizer,
                     kubernetes_redis_readonly_transport, redis_acl_operation_inspection)


def main():
    if not sys.flags.isolated or len(sys.argv)!=11: raise ValueError
    home,bundle,publisher,config,profile,key,kubectl,operation,admin_key,run_id=sys.argv[1:]
    home=Path(home);bundle=Path(bundle);publisher=Path(publisher)
    with uterctl.locked(home):
        with kubernetes_fence_coordinator.checked_session(home,bundle,publisher,Path(config),Path(profile),Path(key),
                executor_bundle=ROOT,executor_key=publisher,kubectl_path=Path(kubectl)) as session:
            plan=kubernetes_fence_finalizer.read_plan(home)
            kubernetes_fence_finalizer._check_journal(home,plan,operation,'prepared')
            try:
                redis_acl_operation_inspection._verify_plan_pod(session,plan)
            except Exception:
                selector='app.kubernetes.io/instance='+session.site+',app.kubernetes.io/name=redis'
                pods=session._query(['get','pods','-l',selector])['items']
                if not isinstance(pods,list) or len(pods)!=1: raise ValueError
                pod=pods[0];statuses=pod.get('status',{}).get('containerStatuses')
                uid=pod.get('metadata',{}).get('uid')
                if (not isinstance(uid,str) or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',uid)
                        or uid==plan['uid']
                        or pod.get('status',{}).get('phase')!='Running'
                        or not isinstance(statuses,list) or len(statuses)!=1 or statuses[0].get('ready') is not True):
                    raise ValueError
                print('READONLY_TRANSPORT_REFUSED_POD')
                return 2
            with kubernetes_redis_readonly_transport.connect(session,operation,'uter-maint-test',Path(admin_key),run_id) as redis:
                if not isinstance(redis.execute('INFO','SERVER'),str): raise ValueError
                if redis.execute('CLIENT','ID')!=int(redis.client_id): raise ValueError
                if sorted(redis.execute('ACL','USERS'))!=['default','uter-maint-test']: raise ValueError
    print('READONLY_TRANSPORT_VERIFIED')
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception:
        print('READONLY_TRANSPORT_REFUSED')
        raise SystemExit(1)
