"""Strict snapshot identity checks for a potential Kubernetes Redis fence.

This is a read-only building block, not an API client, fence, or authorization.
The caller must verify the signature of ``manifest``, bind every observation to
the same trusted API server and hold the installation's lock. Objects are point
in time snapshots and can change immediately after validation.
"""
import re


class KubernetesRedisIdentityError(ValueError):
    """Fixed diagnostic; no Kubernetes objects or secrets in error messages."""


UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
IMAGE = re.compile(r'[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}\Z')
COMMAND = 'exec redis-server --appendonly yes --dir /data --maxmemory 256mb --maxmemory-policy noeviction --requirepass "$REDIS_PASSWORD"'


def _uid(value):
    return isinstance(value, str) and UUID.fullmatch(value) is not None


def _meta(obj, kind, name, namespace):
    if not isinstance(obj, dict) or obj.get('kind') != kind:
        raise ValueError
    meta = obj['metadata']
    if (not isinstance(meta, dict) or meta.get('name') != name or meta.get('namespace') != namespace
            or not _uid(meta.get('uid')) or meta.get('deletionTimestamp')):
        raise ValueError
    return meta


def _controlled_by(meta, kind, name, uid):
    refs = meta.get('ownerReferences')
    if not isinstance(refs, list):
        raise ValueError
    controllers = [ref for ref in refs if isinstance(ref,dict) and ref.get('controller') is True]
    if len(controllers) != 1:
        raise ValueError
    owner = controllers[0]
    if owner.get('kind') != kind or owner.get('name') != name or owner.get('uid') != uid:
        raise ValueError


def _pod_spec(spec, name, image):
    if (not isinstance(spec,dict) or spec.get('hostNetwork',False) is not False
            or spec.get('hostPID',False) is not False or spec.get('hostIPC',False) is not False
            or spec.get('automountServiceAccountToken') is not False
            or spec.get('initContainers') not in (None,[]) or spec.get('ephemeralContainers') not in (None,[])):
        raise ValueError
    containers = spec['containers']
    if not isinstance(containers,list) or len(containers) != 1:
        raise ValueError
    container = containers[0]
    if (container.get('name') != 'redis' or container.get('image') != image
            or container.get('command') != ['sh','-ec'] or container.get('args') != [COMMAND]
            or container.get('envFrom') not in (None,[])):
        raise ValueError
    env = container.get('env')
    if env != [{'name':'REDIS_PASSWORD', 'valueFrom':{'secretKeyRef':{'name':name+'-redis-secret','key':'password'}}}]:
        raise ValueError
    security = container.get('securityContext',{})
    if (security.get('allowPrivilegeEscalation') is not False or security.get('readOnlyRootFilesystem') is not True
            or security.get('privileged',False) is not False
            or security.get('capabilities',{}).get('drop') != ['ALL']
            or security.get('capabilities',{}).get('add') not in (None,[])):
        raise ValueError
    volumes = spec.get('volumes')
    mounts = container.get('volumeMounts')
    if (not isinstance(volumes,list) or len(volumes)!=2 or not isinstance(mounts,list) or len(mounts)!=2):
        raise ValueError
    byname={x.get('name'):x for x in volumes if isinstance(x,dict)}
    mount_byname={x.get('name'):x for x in mounts if isinstance(x,dict)}
    if set(byname)!={'tmp','data'} or set(mount_byname)!={'tmp','data'}:
        raise ValueError
    if (not isinstance(byname['tmp'].get('emptyDir'),dict)
            or byname['data'].get('persistentVolumeClaim',{}).get('claimName') != name+'-redis'
            or mount_byname['tmp'].get('mountPath') != '/tmp'
            or mount_byname['data'].get('mountPath') != '/data'
            or any(x.get('subPath') or x.get('subPathExpr') for x in mounts)):
        raise ValueError


def verify_snapshot(*, site, manifest, cluster_uid, expected_cluster_uid, expected_pvc_uid, deployment, replicaset, pod, pvc):
    """Check strict identity and configuration, never assert isolation.

    ``manifest`` must already be signature-verified and the trusted cluster UID
    provisioned independently. This function doesn't fetch the objects, prove
    their consistency across time, verify RBAC/admission/GitOps, exclude other
    Pods with PVC access, authenticate the API endpoint, or inspect Redis AOF.
    """
    try:
        if (not isinstance(site,str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,40}',site)
                or not _uid(cluster_uid) or not _uid(expected_cluster_uid) or cluster_uid != expected_cluster_uid
                or not _uid(expected_pvc_uid)):
            raise ValueError
        image = manifest['images']['redis']
        if not isinstance(image,str) or not IMAGE.fullmatch(image):
            raise ValueError
        deploy_name=site+'-redis'
        dmeta=_meta(deployment,'Deployment',deploy_name,site)
        dspec=deployment['spec']
        if type(dspec.get('replicas')) is not int or dspec['replicas']!=1 or dspec.get('strategy',{}).get('type')!='Recreate':
            raise ValueError
        if (type(dmeta.get('generation')) is not int
                or deployment.get('status',{}).get('observedGeneration')!=dmeta['generation']):
            raise ValueError
        _pod_spec(dspec['template']['spec'],site,image)
        labels={'app.kubernetes.io/instance':site,'app.kubernetes.io/name':'redis'}
        if any(dspec['template'].get('metadata',{}).get('labels',{}).get(k)!=v for k,v in labels.items()):
            raise ValueError
        rsmeta=replicaset['metadata']
        rsname=rsmeta['name']
        if not isinstance(rsname,str) or not rsname.startswith(deploy_name+'-'):
            raise ValueError
        _meta(replicaset,'ReplicaSet',rsname,site)
        _controlled_by(rsmeta,'Deployment',deploy_name,dmeta['uid'])
        if type(replicaset['spec'].get('replicas')) is not int or replicaset['spec']['replicas']!=1:
            raise ValueError
        _pod_spec(replicaset['spec']['template']['spec'],site,image)
        pmeta=pod['metadata']; pname=pmeta['name']
        if not isinstance(pname,str) or not pname.startswith(rsname+'-'):
            raise ValueError
        _meta(pod,'Pod',pname,site)
        _controlled_by(pmeta,'ReplicaSet',rsname,rsmeta['uid'])
        if any(pmeta.get('labels',{}).get(k)!=v for k,v in labels.items()):
            raise ValueError
        _pod_spec(pod['spec'],site,image)
        statuses=pod['status']['containerStatuses']
        if (pod['status'].get('phase')!='Running' or not isinstance(statuses,list) or len(statuses)!=1):
            raise ValueError
        status=statuses[0]
        image_ids={image.rsplit('@',1)[1]}
        if 'image_config_ids' in manifest:
            image_ids.add(manifest['image_config_ids']['redis'])
        if (status.get('name')!='redis' or status.get('ready') is not True
                or type(status.get('restartCount')) is not int or status['restartCount']!=0
                or not isinstance(status.get('state',{}).get('running'),dict)
                or not isinstance(status.get('imageID'),str)
                or not any(status['imageID'].endswith(x) for x in image_ids)):
            raise ValueError
        pvc_meta=_meta(pvc,'PersistentVolumeClaim',deploy_name,site)
        if pvc_meta['uid']!=expected_pvc_uid or pvc.get('status',{}).get('phase')!='Bound':
            raise ValueError
    except (KeyError,ValueError,TypeError,AttributeError):
        raise KubernetesRedisIdentityError('KUBE_REDIS_IDENTITY_UNVERIFIED') from None
    return {'result':'matching_snapshot_observed','redis_isolated':False,
            'cluster_authenticated':False,'writers_excluded':False,'safe_to_upgrade':False}
