"""CI-only synthetic signed executor child; never target a real cluster."""
import os
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import uterctl
from scripts import (kubernetes_fence_coordinator as coordinator,
                     kubernetes_fence_finalizer as finalizer, kubernetes_fence_recovery_session as recovery,
                     kubernetes_fence_start as start, kubernetes_backup_coordinator as backup,
                     kubernetes_loopback_snapshot as redis, redis_fence_journal as journal)


def main():
    stage='GUARD'
    try:
        if (os.name!='posix' or os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true'
                or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('RUNNER_OS')!='Linux'
                or os.environ.get('UTER_CI_STRICT_RUNNER')!='true'
                or os.environ.get('UTER_CI_VERIFY_KUBE_LOOPBACK')!='true' or os.environ.get('BACKEND')!='kubernetes'):
            raise ValueError
        mode,home,bundle,publisher,config,profile,key,exec_key,kubectl,destination=sys.argv[1:]
        work=Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)/'work'
        if not ROOT.is_relative_to(work) or any(not Path(p).resolve().is_relative_to(work)
                for p in (home,bundle,publisher,config,profile,key,exec_key,destination)):raise ValueError
        if kubectl!='/usr/bin/uter-ci-kubectl':raise ValueError
        home=Path(home);bundle=Path(bundle);publisher=Path(publisher)
        with uterctl.locked(home):
            if mode=='start':
                stage='PREFLIGHT'
                with coordinator.checked_session(home,bundle,publisher,config,profile,key,
                        executor_bundle=ROOT,executor_key=exec_key,kubectl_path=kubectl) as session:
                    stage='REDIS_PLAN'
                    labels='app.kubernetes.io/instance='+session.site+',app.kubernetes.io/name=redis'
                    pods=session._query(['get','pods','-l',labels])['items']
                    if len(pods)!=1:raise ValueError
                    pod=pods[0];plan=finalizer.plan_from_pod(session.api.context,session.site,pod['metadata']['name'],pod)
                    finalizer.persist_plan(home,plan)
                    state=journal.create(home,backend='kubernetes',site=session.site,resource=plan['uid'],
                                         plan_sha256=finalizer.plan_hash(plan))
                    stage='START'
                    if start.start(session,state['operation'])['safe_to_update'] is not False:raise ValueError
                    # CI parent confirms SIGKILL and reaps this exact child before
                    # deleting this synthetic runner's stale lock. Production
                    # stale-lock recovery remains deliberately unsupported.
                    print('CI_ISOLATION_STAGE_DONE',flush=True)
                    os.kill(os.getpid(),9)
            elif mode=='resume':
                stage='RECOVERY_SESSION'
                with recovery.checked_recovery_session(home,bundle,publisher,config,profile,key,
                        executor_bundle=ROOT,executor_key=exec_key,kubectl_path=kubectl) as session:
                    state=journal.read(home);operation=state['operation'];old_uid=state['resource']
                    labels='app.kubernetes.io/instance='+session.site+',app.kubernetes.io/name=redis'
                    stage='NEW_REDIS'
                    deadline=time.monotonic()+180
                    while time.monotonic()<deadline:
                        try:
                            pods=session._query(['get','pods','-l',labels])['items']
                            if len(pods)!=1 or pods[0]['metadata']['uid']==old_uid:raise ValueError
                            pod=pods[0];name=pod['metadata']['name'];uid=pod['metadata']['uid']
                            redis.assert_loopback(session,operation,name,uid)
                            break
                        except Exception:time.sleep(.5)
                    else:raise ValueError
                    stage='BACKUP'
                    result=backup.capture(session,operation,name,uid,destination)
                    if result.get('backup_set_verified') is not True or result.get('safe_to_update') is not False:raise ValueError
                    stage='RECEIPT'
                    result=backup.verify_receipt(session,operation,name,uid,destination)
                    if result!={'backup_receipt_verified':True,'audit_integrity':'structure_only','safe_to_update':False}:raise ValueError
                    print('CI_BACKUP_RECEIPT_VERIFIED_STRUCTURE_ONLY',flush=True)
            else:raise ValueError
    except Exception:
        print('KUBE_COORDINATOR_CI_'+stage,file=sys.stderr,flush=True)
        raise SystemExit(1)


if __name__=='__main__':main()
