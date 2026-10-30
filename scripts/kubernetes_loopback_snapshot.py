"""Bounded encrypted Redis component capture, not a complete backup or fence.

The caller must separately verify continuous writer exclusion, storage and the
complete backup set. Capture uses only the sealed Kubernetes config FD and an
exact Pod name/UID; any changed identity invalidates the captured component.
"""
import copy
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import threading

from scripts import (backup_snapshot, kubernetes_fence_finalizer as finalizer,
                     kubernetes_loopback_intent as loopback, kubernetes_redis_identity as identity,
                     kubernetes_sealed_config as sealed)


class SnapshotError(ValueError):pass


def _trusted_binary(path,expected):
    """Open a root-owned binary through protected, non-symlink parents."""
    value=Path(path)
    if not value.is_absolute() or '..' in value.parts or not re.fullmatch(r'[0-9a-f]{64}',expected):raise ValueError
    for item in (value,*value.parents):
        info=item.lstat()
        if info.st_uid!=0 or info.st_mode&0o022 or stat.S_ISLNK(info.st_mode):raise ValueError
        if item!=value and not stat.S_ISDIR(info.st_mode):raise ValueError
    fd=os.open(value,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022
                or info.st_nlink!=1 or not info.st_mode&0o111 or not 0<info.st_size<=128*1024*1024):raise ValueError
        digest=hashlib.sha256()
        while True:
            data=os.read(fd,1024*1024)
            if not data:break
            digest.update(data)
        if digest.hexdigest()!=expected:raise ValueError
        os.lseek(fd,0,os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd);raise


class _LimitedStream:
    def __init__(self,source):self.source=source;self.total=0
    def read(self,size):
        data=self.source.read(size);self.total+=len(data)
        if self.total>backup_snapshot.RDB_MAX_BYTES:raise ValueError
        return data


def _observe(session,operation,pod_name,pod_uid):
    session._scope()
    plan=finalizer.read_plan(session.home)
    if loopback.classify(session.home,plan,operation,session.api)['state']!='loopback_spec_observed':raise ValueError
    if not re.fullmatch(re.escape(session.site)+r'-redis-[a-z0-9-]{1,64}',pod_name):raise ValueError
    if not identity.UUID.fullmatch(pod_uid) or pod_uid==plan['uid']:raise ValueError
    deployment=session._query(['get','deployment',session.site+'-redis'])
    pod=session._query(['get','pod',pod_name])
    owner=[x for x in pod['metadata']['ownerReferences'] if x.get('kind')=='ReplicaSet' and x.get('controller') is True]
    if len(owner)!=1 or not re.fullmatch(re.escape(session.site)+r'-redis-[a-z0-9]{1,32}',owner[0]['name']):raise ValueError
    rs=session._query(['get','replicaset',owner[0]['name']])
    pvc=session._query(['get','pvc',session.site+'-redis'])
    system=session._query(['get','namespace','kube-system'])
    if pod['metadata']['uid']!=pod_uid:raise ValueError
    # Identity verifier expects the signed original args. First require the
    # exact intended loopback args in each live object, then normalize copies.
    objects=copy.deepcopy((deployment,rs,pod))
    for spec in (objects[0]['spec']['template']['spec'],objects[1]['spec']['template']['spec'],objects[2]['spec']):
        container=spec['containers'][0]
        if container.get('args')!=[loopback.LOOPBACK]:raise ValueError
        container['args']=[identity.COMMAND]
    identity.verify_snapshot(site=session.site,manifest=session.manifest,
        cluster_uid=system['metadata']['uid'],expected_cluster_uid=session.profile['kube_system_uid'],
        expected_pvc_uid=session.profile['redis_pvc_uid'],deployment=objects[0],replicaset=objects[1],pod=objects[2],pvc=pvc)
    status=pod['status']['containerStatuses'][0]
    if not re.fullmatch(r'(?:containerd|cri-o|docker)://[0-9a-f]{64}',status['containerID']):raise ValueError
    session._scope()
    return {'uid':pod_uid,'container_id':status['containerID'],'pod_spec_sha256':finalizer._digest(pod['spec']),
            'replicaset_uid':rs['metadata']['uid']}


def capture_component(session,operation,pod_name,pod_uid,writer,*,kubectl_path):
    """Stream one RDB through encrypted writer; never finalize a backup set."""
    process=None;timer=None;accepted=False;binary_fd=None
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        before=_observe(session,operation,pod_name,pod_uid)
        fd=session._inner.config_fd
        sealed.verify_sealed(fd,session.config_sha256)
        binary_fd=_trusted_binary(kubectl_path,session._record['kubectl_sha256'])
        command=['/proc/self/fd/'+str(binary_fd),'--kubeconfig=/proc/self/fd/'+str(fd),'--context='+session.api.context,
                 '--namespace='+session.site,'--request-timeout=20s','exec','pod/'+pod_name,'-c','redis','--',
                 'sh','-ec','export REDISCLI_AUTH="$REDIS_PASSWORD"; exec redis-cli --rdb -']
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                 pass_fds=(fd,binary_fd),start_new_session=True,
                                 env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','LC_ALL':'C'})
        timer=threading.Timer(300,lambda:process.kill() if process.poll() is None else None);timer.start()
        first=process.stdout.read(5)
        if first!=b'REDIS':raise ValueError
        writer.put('redis',_LimitedStream(backup_snapshot.PrefixStream(process.stdout,first)))
        timer.cancel();timer.join();timer=None
        if process.wait(timeout=120)!=0:raise ValueError
        if _observe(session,operation,pod_name,pod_uid)!=before:raise ValueError
        accepted=True
        return {'redis_component_captured':True,'complete_backup':False,'safe_to_update':False}
    except Exception:raise SnapshotError('KUBE_LOOPBACK_SNAPSHOT_UNVERIFIED') from None
    finally:
        cleanup_error=False
        try:
            if timer is not None:timer.cancel();timer.join(timeout=10)
            if timer is not None and timer.is_alive():cleanup_error=True
            if process is not None:
                if process.poll() is None:process.kill()
                process.wait(timeout=10)
                if process.stdout is not None:process.stdout.close()
        except (OSError,subprocess.SubprocessError):cleanup_error=True
        if binary_fd is not None:
            try:os.close(binary_fd)
            except OSError:cleanup_error=True
        if not accepted or cleanup_error:
            manifest=getattr(writer,'manifest',None)
            if isinstance(manifest,dict) and isinstance(manifest.get('files'),dict):manifest['files'].pop('redis',None)
        if cleanup_error and accepted:raise SnapshotError('KUBE_LOOPBACK_SNAPSHOT_CLEANUP_UNVERIFIED') from None
