"""Capture an encrypted baseline while application writers are quiesced.

Callers must hold uterctl's operation lock. This module never restores data.
"""
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tarfile
import threading
import time

from scripts import adopt_installation, backup_crypto, backup_store, restore_backup

RDB_MAX_BYTES = 100 * 1024 * 1024
RDB_STREAM_TIMEOUT = 300
RDB_EXIT_TIMEOUT = 120


class BoundedSnapshotSink:
    """Limit bytes actually sent to the checker, even with forged metadata."""
    def __init__(self, stream, limit):
        self.stream = stream
        self.limit = limit
        self.written = 0

    def write(self, data):
        if len(data) > self.limit - self.written:
            raise ValueError('Redis snapshot exceeds the 100 MiB validation limit')
        view = memoryview(data)
        total = 0
        while total < len(view):
            count = self.stream.write(view[total:])
            if type(count) is not int or count <= 0 or count > len(view) - total:
                raise OSError('Redis snapshot checker rejected the stream')
            total += count
            self.written += count
        return total


class PrefixStream:
    def __init__(self, stream, prefix): self.stream=stream; self.prefix=prefix
    def read(self, size):
        if self.prefix:
            part=self.prefix[:size];self.prefix=self.prefix[size:];return part
        return self.stream.read(size)


def process_component(writer, label, command, *, env=None, prefix=None):
    process=subprocess.Popen([str(x) for x in command],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    timer=threading.Timer(300,lambda: process.kill() if process.poll() is None else None)
    timer.start()
    try:
        source=process.stdout
        if prefix is not None:
            first=source.read(len(prefix))
            if first != prefix: raise ValueError(f'Invalid {label} snapshot header')
            source=PrefixStream(source,first)
        writer.put(label,source)
        if process.wait(timeout=120) != 0: raise ValueError(f'{label} snapshot command failed')
    finally:
        timer.cancel()
        if process.poll() is None: process.kill();process.wait()
        process.stdout.close()


def verify_encrypted_tar(writer, label):
    """Validate the actual encrypted tar without writing plaintext to disk."""
    read_fd,write_fd=os.pipe()
    errors=[]
    def decrypt():
        try:
            with os.fdopen(write_fd,'wb') as sink:
                backup_crypto.decrypt_verify(writer.path/(label+'.enc'),writer.key,
                    backup_store.aad(writer.manifest['id'],label),writer.manifest['files'][label],sink)
        except BaseException as exc:
            errors.append(exc)
    thread=threading.Thread(target=decrypt,daemon=True)
    thread.start()
    try:
        with os.fdopen(read_fd,'rb') as source:
            with tarfile.open(fileobj=source,mode='r|*') as archive:
                restore_backup.check_tar_members(archive)
            while source.read(1024*1024): pass
    finally:
        thread.join(timeout=300)
    if thread.is_alive(): raise RuntimeError('Timed out verifying encrypted archive')
    if errors: raise ValueError('Encrypted archive authentication failed') from errors[0]


def verify_redis_snapshot(writer, command, *, env=None):
    """Stream the encrypted snapshot through redis-check-rdb without a plaintext file."""
    metadata=writer.manifest['files']['redis']
    if metadata['plaintext_bytes'] > RDB_MAX_BYTES:
        raise ValueError('Redis snapshot exceeds the 100 MiB validation limit')
    process=subprocess.Popen([str(x) for x in command],env=env,stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def stop_checker():
        try:
            if process.poll() is None: process.kill()
        except ProcessLookupError:
            pass
    timer=threading.Timer(RDB_STREAM_TIMEOUT,stop_checker)
    timer.start()
    try:
        backup_crypto.decrypt_verify(writer.path/'redis.enc',writer.key,
            backup_store.aad(writer.manifest['id'],'redis'),metadata,
            BoundedSnapshotSink(process.stdin, RDB_MAX_BYTES))
        process.stdin.close()
        # The timer callback may call poll() and reap the child. Join it before
        # wait() can reap the same child and permit its PID to be reused.
        timer.cancel()
        timer.join()
        if process.wait(timeout=RDB_EXIT_TIMEOUT) != 0: raise ValueError('Redis snapshot failed structural validation')
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Redis snapshot validation failed or timed out') from None
    finally:
        timer.cancel()
        # Wait for an already-running timeout callback before reaping the child,
        # so it cannot signal a later process after PID reuse.
        timer.join()
        try:
            stop_checker()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                raise RuntimeError('Redis snapshot checker could not be stopped') from None
        finally:
            if not process.stdin.closed:
                try: process.stdin.close()
                except OSError: pass


def archive_runtime(home, writer):
    home=Path(home)
    names=['runtime','install.json','install-state.json','credentials.json','empty.env','values.yaml','resources.yaml','state.json','releases']
    def add_tar(out):
        with tarfile.open(fileobj=out,mode='w|') as tar:
            for name in names:
                path=home/name
                if not path.exists(): continue
                if path.is_symlink(): raise ValueError('Runtime symlinks are unsupported')
                for current, dirs, files in os.walk(path) if path.is_dir() else []:
                    for child in dirs+files:
                        p=Path(current)/child
                        if p.is_symlink() or not (p.is_file() or p.is_dir()):
                            raise ValueError('Runtime contains a symlink or special file')
                tar.add(path,arcname=name,recursive=True)
    writer.put_generated('runtime',add_tar)


def kube_objects(home, site):
    import yaml
    values=yaml.safe_load((Path(home)/'runtime/values.yaml').read_text())
    names=[('secret',values.get(k)) for k in ('guardrailSecret','agentSecret','redisSecret')]
    names += [('configmap',values.get(k)) for k in ('policyConfigMap','profileConfigMap')]
    names += [('secret',v.get('name')) for v in values.get('imagePullSecrets',[])]
    names += [('pvc',site['name']+'-'+s) for s in ('guardrail','redis')]
    if not values.get('useEmbeddedModels'):
        raise ValueError('External model PVC requires a separately verified backup; unsupported by baseline snapshot')
    for kind,name in names:
        if not isinstance(name,str) or not re.fullmatch(r'[a-z0-9]([-a-z0-9.]*[a-z0-9])?',name):
            raise ValueError('Invalid Kubernetes resource name')
    return [kind+'/'+name for kind,name in names]


def checked(command, *, env=None, input=None):
    result=subprocess.run([str(x) for x in command],env=env,input=input,capture_output=True,timeout=360)
    if result.returncode:
        raise RuntimeError(f'{command[0]} backup operation failed; details withheld to protect secrets')
    return result.stdout


def wait_no_pods(kube, site, timeout=180):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        pods=json.loads(checked(kube+['get','pods','-l','app.kubernetes.io/instance='+site['name'],'-o','json']))['items']
        if not any(p['metadata'].get('labels',{}).get('app.kubernetes.io/name') in ('guardrail','agent') for p in pods): return
        time.sleep(2)
    raise RuntimeError('Timed out waiting for application writers to stop')


def audit_pod(kube, site, manifest, guardrail_pod):
    container=next(c for c in guardrail_pod['spec']['containers'] if c['name']=='guardrail')
    mount=next((m for m in container.get('volumeMounts',[]) if m.get('mountPath')=='/var/lib/uter/audit'),None)
    volume=next((v for v in guardrail_pod['spec']['volumes'] if mount and v['name']==mount['name']),None)
    if not volume or not volume.get('persistentVolumeClaim'): raise ValueError('Guardrail audit PVC not found')
    podname=site['name']+'-backup-'+secrets.token_hex(4)
    spec={'apiVersion':'v1','kind':'Pod','metadata':{'name':podname,'namespace':site['namespace'],
            'labels':{'uter.io/temporary-backup':'true'}},
          'spec':{'restartPolicy':'Never','automountServiceAccountToken':False,
            'activeDeadlineSeconds':600,
            'nodeName':guardrail_pod['spec']['nodeName'],
            'securityContext':{'runAsNonRoot':True,'runAsUser':10001,'runAsGroup':10001,'fsGroup':10001,
                               'seccompProfile':{'type':'RuntimeDefault'}},
            'imagePullSecrets':guardrail_pod['spec'].get('imagePullSecrets',[]),
            'containers':[{'name':'reader','image':manifest['images']['guardrail'],
                'command':['python','-c','import time;time.sleep(600)'],
                'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
                'volumeMounts':[{'name':'audit','mountPath':'/snapshot','readOnly':True}]}],
            'volumes':[{'name':'audit','persistentVolumeClaim':{'claimName':volume['persistentVolumeClaim']['claimName'],'readOnly':True}}]}}
    checked(kube+['create','-f','-'],input=json.dumps(spec).encode())
    return podname


def _require_legacy_operation_lock(home):
    """Check the current PID sentinel; caller must still hold the operation lock.

    This is a fail-closed sanity check under the trusted installation-directory
    boundary, not a kernel proof against hostile same-UID processes. Hardlinked
    experimental Lease sentinels require a separate authenticated contract.
    """
    if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'geteuid'):
        raise ValueError('BACKUP_LOCK_UNVERIFIED')
    path=Path(home)/'operation.lock'
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as source:
            info=os.fstat(source.fileno())
            raw=source.read(33)
            observed=os.stat(path,follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                    or info.st_mode&0o077 or info.st_nlink!=1
                    or raw!=str(os.getpid()).encode('ascii') or info.st_size!=len(raw)
                    or (info.st_dev,info.st_ino)!=(observed.st_dev,observed.st_ino)):
                raise ValueError
    except (OSError,ValueError):
        raise ValueError('BACKUP_LOCK_UNVERIFIED') from None


def resume_writers(home, cfg, site, current):
    # Do not restart writers while a Redis isolation operation is unresolved.
    # The caller must hold the same controller lock as fence operations.
    if os.path.lexists(Path(home)/'redis-fence-operation.json') or os.path.lexists(Path(home)/'compose-fence-finalize-anchor.json'):
        raise ValueError('REDIS_FENCE_REQUIRES_INSPECTION')
    _require_legacy_operation_lock(home)
    from scripts import install as installer
    cfg=dict(cfg,images=current['images'])
    cmd,env=installer.commands(home,cfg)
    if site['backend']=='compose':
        cmd[cmd.index('-f')+1]=str(Path(home)/'releases'/current['version']/'compose/compose.yaml')
        _require_legacy_operation_lock(home)
        checked(cmd+['up','-d','--no-build','--pull','never','--wait','--wait-timeout','300','redis','agent','guardrail'],env=env)
    else:
        kube=['kubectl','--context',cfg['context'],'-n',site['namespace']]
        _require_legacy_operation_lock(home)
        checked(kube+['scale','deployment/'+site['name']+'-guardrail','deployment/'+site['name']+'-agent','--replicas=1'])
        for svc in ('agent','guardrail'):
            _require_legacy_operation_lock(home)
            checked(kube+['rollout','status','deployment/'+site['name']+'-'+svc,'--timeout=300s'])


def capture(home, cfg, site, current, destination, key, *, leave_stopped=False):
    """Capture while Uter writers are stopped; caller must already hold controller lock.

    If leave_stopped is true, caller owns restarting the workloads after success.
    """
    from scripts import install as installer
    import uterctl
    home=Path(home);journal=home/'backup-operation.json'
    if os.path.lexists(home/'redis-fence-operation.json') or os.path.lexists(home/'compose-fence-finalize-anchor.json'):
        raise ValueError('REDIS_FENCE_REQUIRES_INSPECTION')
    _require_legacy_operation_lock(home)
    if journal.exists(): raise ValueError('Previous backup operation requires inspection')
    cfg = dict(cfg, images=current['images'])
    adopt_installation.verify_live(home,cfg,current)
    writer=backup_store.BackupWriter(destination,key,home,site,current['version'])
    cmd, env=installer.commands(home,cfg)
    if site['backend']=='compose':
        # Use the signed current release, not the installation's original frozen files.
        cmd[cmd.index('-f')+1] = str(home/'releases'/current['version']/'compose/compose.yaml')
    kube=['kubectl','--context',cfg['context'],'-n',site['namespace']]
    stopped=False;helper=None;success=False;guardpod=None
    objects=None;cluster_snapshot=None
    if site['backend']=='helm':
        # Validate scope and capture live Secrets/ConfigMaps, not just stale local copies.
        objects=kube_objects(home,site)
        cluster_snapshot=checked(kube+['get',*objects,'-o','json'])
        writer.put('kubernetes',io.BytesIO(cluster_snapshot))
        pods=json.loads(checked(kube+['get','pods','-l','app.kubernetes.io/instance='+site['name'],'-o','json']))['items']
        guards=[p for p in pods if p['metadata'].get('labels',{}).get('app.kubernetes.io/name')=='guardrail' and not p['metadata'].get('deletionTimestamp')]
        if len(guards)!=1: raise ValueError('Expected exactly one Guardrail pod')
        guardpod=guards[0]
        hpas=json.loads(checked(kube+['get','hpa','-o','json']))['items']
        controlled={site['name']+'-guardrail',site['name']+'-agent'}
        if any(h.get('spec',{}).get('scaleTargetRef',{}).get('kind')=='Deployment' and
               h['spec']['scaleTargetRef'].get('name') in controlled for h in hpas):
            raise ValueError('HPA for an application service must be disabled before a consistent backup')
        for service in ('guardrail','agent'):
            d=json.loads(checked(kube+['get','deployment',site['name']+'-'+service,'-o','json']))
            if d['spec'].get('replicas',1)!=1: raise ValueError('Backup requires one replica of each application service')
    uterctl.write(journal,{'operation':'backup','phase':'quiescing','version':current['version'],
                            'backup_id':writer.manifest['id'],'backend':site['backend']})
    try:
        stopped=True
        if site['backend']=='compose':
            checked(cmd+['stop','guardrail','agent'],env=env)
        else:
            checked(kube+['scale','deployment/'+site['name']+'-guardrail','deployment/'+site['name']+'-agent','--replicas=0'])
            wait_no_pods(kube,site)
            if checked(kube+['get',*objects,'-o','json']) != cluster_snapshot:
                raise ValueError('Kubernetes runtime resources changed during backup')
        archive_runtime(home,writer)
        if site['backend']=='compose':
            redis=cmd+['exec','-T','redis','sh','-ec','export REDISCLI_AUTH="$(cat /run/secrets/redis_password)"; exec redis-cli --rdb -']
            ids=checked(cmd+['ps','-aq','guardrail'],env=env).decode().split()
            if len(ids)!=1: raise ValueError('Stopped Guardrail container is unavailable')
            audit=['docker','--context',cfg['context'],'cp',ids[0]+':/var/lib/uter/audit/.','-']
            process_component(writer,'redis',redis,env=env,prefix=b'REDIS')
            process_component(writer,'audit',audit,env=env)
        else:
            redis=kube+['exec','deployment/'+site['name']+'-redis','-c','redis','--','sh','-ec','export REDISCLI_AUTH="$REDIS_PASSWORD"; exec redis-cli --rdb -']
            process_component(writer,'redis',redis,prefix=b'REDIS')
            helper=audit_pod(kube,site,current,guardpod)
            checked(kube+['wait','--for=condition=Ready','pod/'+helper,'--timeout=180s'])
            code='import sys,tarfile; t=tarfile.open(fileobj=sys.stdout.buffer,mode="w|"); t.add("/snapshot",arcname="audit",recursive=True); t.close()'
            process_component(writer,'audit',kube+['exec',helper,'-c','reader','--','python','-c',code])
        verify_encrypted_tar(writer,'runtime')
        verify_encrypted_tar(writer,'audit')
        if site['backend']=='compose':
            check=cmd+['exec','-T','redis','redis-check-rdb','/dev/stdin']
            verify_redis_snapshot(writer,check,env=env)
        else:
            check=kube+['exec','-i','deployment/'+site['name']+'-redis','-c','redis','--','redis-check-rdb','/dev/stdin']
            verify_redis_snapshot(writer,check)
        manifest=writer.finish()
        backup_store.verify_set(destination,key,home=home,site=site,version=current['version'])
        success=True
        return manifest
    finally:
        cleanup_error=None
        if helper:
            try: checked(kube+['delete','pod',helper,'--ignore-not-found','--wait=true'])
            except Exception as exc: cleanup_error=exc;success=False
        if stopped and not (success and leave_stopped):
            try:
                resume_writers(home,cfg,site,current)
                journal.unlink(missing_ok=True)
            except Exception:
                print('Backup recovery failed; inspect backup-operation.json and workloads.',file=__import__('sys').stderr)
                raise
        elif success and leave_stopped:
            uterctl.write(journal,{'operation':'backup','phase':'quiesced','version':current['version'],
                                    'backup_id':writer.manifest['id'],'backend':site['backend']})
        if cleanup_error: raise RuntimeError('Could not remove temporary backup pod; workloads were resumed') from cleanup_error
