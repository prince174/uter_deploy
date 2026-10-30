"""Write-once authenticated audit reader plan; creates no Kubernetes object."""
from scripts import (backup_installation, kubernetes_fence_finalizer as finalizer,
                     kubernetes_writer_finalizer as writer_finalizer,
                     kubernetes_writer_quiesce as storage)

NAME='kubernetes-audit-reader-plan.json'


class AuditPlanError(ValueError):pass


def prepare(session,operation,key):
    """Bind helper to the pinned audit PVC and exact currently running writer."""
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        if backup_installation.safe_file(session._key_path,private=True,limit=32)!=key:raise ValueError
        session.reverify();session._scope()
        record,_=writer_finalizer._record(session.home,session,operation,'guardrail',key)
        writer_finalizer._pod(session,record,[],deleting=False,original_rv=True)
        pod=session.api.get(record['pod']);spec=pod['spec'];meta=pod['metadata']
        if (meta.get('uid')!=record['uid'] or meta.get('resourceVersion')!=record['rv']
                or finalizer._digest(spec)!=record['spec_sha256']):raise ValueError
        container=spec['containers'][0]
        mounts=[x for x in container.get('volumeMounts',[]) if x.get('mountPath')=='/var/lib/uter/audit']
        if len(mounts)!=1 or mounts[0].get('subPath') or mounts[0].get('subPathExpr'):raise ValueError
        volumes=[x for x in spec.get('volumes',[]) if x.get('name')==mounts[0].get('name')]
        if len(volumes)!=1 or volumes[0].get('persistentVolumeClaim',{}).get('claimName')!=session.site+'-guardrail':raise ValueError
        if container.get('image')!=session.manifest['images']['guardrail']:raise ValueError
        # This plan is not a Pod and cannot be submitted without a separate
        # audited one-shot create, live admission verification and UID cleanup.
        value={'schema':1,'operation':operation,'site':session.site,'audit_pvc_uid':session._record['audit_pvc_uid'],
               'audit_pvc_name':session.site+'-guardrail','guardrail_pod_uid':record['uid'],
               'guardrail_pod_sha256':record['spec_sha256'],'reader_image':container['image'],
               'reader_name':session.site+'-audit-reader-'+operation[:12],
               'recovery_binding_sha256':storage._hash(storage._read(session.home,'kubernetes-fence-recovery-auth.json',key))}
        storage._write(session.home,NAME,value,key)
        session._scope()
        return {'audit_reader_plan_saved':True,'reader_created':False,'safe_to_backup':False}
    except Exception:raise AuditPlanError('KUBE_AUDIT_PLAN_UNVERIFIED') from None
