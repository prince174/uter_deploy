"""Strict one-shot read-only audit helper specification.

The helper is not created until its signed plan, writer-stop observations and
UID-preconditioned cleanup have all been integrated. No backup is authorized.
"""
import json
import hmac
import os
import re
import select
import signal
import subprocess
import threading
import time

from scripts import (backup_installation, backup_snapshot, kubernetes_audit_writer_guard as writer_guard,
                     kubernetes_redis_identity as identity, kubernetes_sealed_config as sealed,
                     kubernetes_trusted_kubectl as binary, kubernetes_writer_quiesce as storage)


class AuditReaderError(ValueError):pass

CREATE_ATTEMPT='kubernetes-audit-reader-create-attempt.json'
CREATED='kubernetes-audit-reader-created.json'
DELETE_ATTEMPT='kubernetes-audit-reader-delete-attempt.json'
AUDIT_MAX_BYTES=1024*1024*1024


def _stop(process):
    try:
        if process.poll() is None:process.kill()
    except ProcessLookupError:pass


def _call_input(command,payload,config_fd,binary_fd):
    """Bound output/time and kill the process group before reaping its leader."""
    process=None
    try:
        if not isinstance(payload,bytes) or len(payload)>4096:raise ValueError
        process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env=dict(binary.ENV),pass_fds=(config_fd,binary_fd),start_new_session=True,bufsize=0)
        if process.stdin.write(payload)!=len(payload):raise ValueError
        process.stdin.close()
        deadline=time.monotonic()+30;output=bytearray()
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ValueError
            ready,_,_=select.select([process.stdout],[],[],remaining)
            if not ready:raise ValueError
            data=os.read(process.stdout.fileno(),min(65536,2*1024*1024+1-len(output)))
            if not data:break
            output.extend(data)
            if len(output)>2*1024*1024:raise ValueError
        while True:
            if os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT):break
            if time.monotonic()>=deadline:raise ValueError
            time.sleep(.02)
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        if process.wait(timeout=10)!=0:raise ValueError
        return bytes(output)
    finally:
        if process is not None:
            try:
                if process.returncode is None:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:pass
            finally:
                if process.stdout is not None:process.stdout.close()
                if process.stdin is not None and not process.stdin.closed:process.stdin.close()


def pod_spec(plan):
    """Derive the complete immutable request from the authenticated plan."""
    try:
        expected={'schema','operation','site','audit_pvc_uid','audit_pvc_name','guardrail_pod_uid',
                  'guardrail_pod_sha256','reader_image','reader_name','recovery_binding_sha256'}
        if (not isinstance(plan,dict) or set(plan)!=expected or type(plan['schema']) is not int or plan['schema']!=1
                or not re.fullmatch(r'[0-9a-f]{32}',plan['operation'])
                or not re.fullmatch(r'[a-z][a-z0-9-]{0,40}',plan['site'])
                or plan['audit_pvc_name']!=plan['site']+'-guardrail'
                or plan['reader_name']!=plan['site']+'-audit-reader-'+plan['operation'][:12]
                or not identity.UUID.fullmatch(plan['audit_pvc_uid']) or not identity.UUID.fullmatch(plan['guardrail_pod_uid'])
                or not identity.IMAGE.fullmatch(plan['reader_image'])
                or any(not re.fullmatch(r'[0-9a-f]{64}',plan[x]) for x in ('guardrail_pod_sha256','recovery_binding_sha256'))):
            raise ValueError
        return {'apiVersion':'v1','kind':'Pod','metadata':{'name':plan['reader_name'],'namespace':plan['site'],
                    'labels':{'uter.io/audit-reader':plan['operation']}},
                'spec':{'restartPolicy':'Never','automountServiceAccountToken':False,
                    'hostNetwork':False,'hostPID':False,'hostIPC':False,
                    'securityContext':{'runAsNonRoot':True,'runAsUser':10001,'runAsGroup':10001,'fsGroup':10001,
                                       'seccompProfile':{'type':'RuntimeDefault'}},
                    'containers':[{'name':'reader','image':plan['reader_image'],
                        'command':['python','-c','import time;time.sleep(600)'],
                        'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,
                                           'privileged':False,'capabilities':{'drop':['ALL']}},
                        'volumeMounts':[{'name':'audit','mountPath':'/snapshot','readOnly':True}]}],
                    'volumes':[{'name':'audit','persistentVolumeClaim':{'claimName':plan['audit_pvc_name'],'readOnly':True}}]}}
    except Exception:raise AuditReaderError('KUBE_AUDIT_READER_PLAN_UNVERIFIED') from None


def verify_pod(plan,pod,uid,*,ready,image_config_id=None):
    """Validate a created helper including identity, admission and mount."""
    try:
        expected=pod_spec(plan);meta=pod['metadata'];spec=pod['spec'];want=expected['spec']
        if (pod.get('kind')!='Pod' or meta.get('name')!=plan['reader_name']
                or meta.get('namespace')!=plan['site'] or meta.get('uid')!=uid
                or not identity.UUID.fullmatch(uid) or meta.get('deletionTimestamp')
                or meta.get('labels',{}).get('uter.io/audit-reader')!=plan['operation']
                or meta.get('ownerReferences') not in (None,[]) or meta.get('finalizers') not in (None,[])):
            raise ValueError
        for name in ('restartPolicy','automountServiceAccountToken','securityContext'):
            if spec.get(name)!=want[name]:raise ValueError
        for name in ('hostNetwork','hostPID','hostIPC'):
            if spec.get(name,False) is not False:raise ValueError
        if spec.get('initContainers') not in (None,[]) or spec.get('ephemeralContainers') not in (None,[]):raise ValueError
        containers=spec.get('containers');volumes=spec.get('volumes')
        if not isinstance(containers,list) or len(containers)!=1 or volumes!=want['volumes']:raise ValueError
        item=containers[0];desired=want['containers'][0]
        for name in ('name','image','command','securityContext','volumeMounts'):
            if item.get(name)!=desired[name]:raise ValueError
        for name in ('args','env','envFrom','lifecycle','ports','volumeDevices'):
            if item.get(name) not in (None,[]):raise ValueError
        if ready:
            statuses=pod['status']['containerStatuses']
            allowed={plan['reader_image'].rsplit('@',1)[1]}
            if image_config_id is not None:
                if not re.fullmatch(r'sha256:[0-9a-f]{64}',image_config_id):raise ValueError
                allowed.add(image_config_id)
            if (pod['status'].get('phase')!='Running' or not isinstance(statuses,list) or len(statuses)!=1
                    or statuses[0].get('name')!='reader' or statuses[0].get('ready') is not True
                    or type(statuses[0].get('restartCount')) is not int or statuses[0]['restartCount']!=0
                    or not isinstance(statuses[0].get('state',{}).get('running'),dict)
                    or not isinstance(statuses[0].get('containerID'),str)
                    or not re.fullmatch(r'(?:containerd|cri-o|docker)://[0-9a-f]{64}',statuses[0]['containerID'])
                    or not isinstance(statuses[0].get('imageID'),str)
                    or not any(statuses[0]['imageID'].endswith(x) for x in allowed)):
                raise ValueError
        return {'reader_identity_observed':True,'safe_to_backup':False}
    except Exception:raise AuditReaderError('KUBE_AUDIT_READER_POD_UNVERIFIED') from None


def create(session,operation,key):
    """Create one fixed reader after a durable intent, with no retry."""
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        if not hmac.compare_digest(backup_installation.safe_file(session._key_path,private=True,limit=32),key):raise ValueError
        session._scope();writer_guard.verify(session,operation,key)
        plan=storage._read(session.home,'kubernetes-audit-reader-plan.json',key)
        if (plan['operation']!=operation or plan['site']!=session.site
                or plan['audit_pvc_uid']!=session._record['audit_pvc_uid']
                or plan['reader_image']!=session.manifest['images']['guardrail']):raise ValueError
        binding=storage._read(session.home,'kubernetes-fence-recovery-auth.json',key)
        if storage._hash(binding)!=plan['recovery_binding_sha256']:raise ValueError
        request=pod_spec(plan);payload=json.dumps(request,sort_keys=True,separators=(',',':')).encode()
        if len(payload)>4096:raise ValueError
        intent={'operation':operation,'plan_sha256':storage._hash(plan),'request_sha256':storage._hash(request)}
        storage._write(session.home,CREATE_ATTEMPT,intent,key)
        # No arbitrary command or environment enters this subprocess. A timeout
        # leaves the durable marker; it must never result in a second create.
        config_fd=session._inner.config_fd;binary_fd=session._inner.api.binary_fd
        sealed.verify_sealed(config_fd,session.config_sha256)
        binary.verify(binary_fd,session._record['kubectl_sha256'])
        session._scope();writer_guard.verify(session,operation,key)
        command=['/proc/self/fd/'+str(binary_fd),'--kubeconfig=/proc/self/fd/'+str(config_fd),
                 '--context='+session.api.context,'--namespace='+session.site,'--request-timeout=20s',
                 'create','-f','-','-o','json']
        result=json.loads(_call_input(command,payload,config_fd,binary_fd));uid=result['metadata']['uid']
        verify_pod(plan,result,uid,ready=False)
        session._scope();writer_guard.verify(session,operation,key)
        storage._write(session.home,CREATED,{'operation':operation,'plan_sha256':storage._hash(plan),'uid':uid},key)
        return {'reader_created':True,'safe_to_backup':False}
    except Exception:raise AuditReaderError('KUBE_AUDIT_READER_CREATE_UNCERTAIN') from None


def delete(session,operation,key):
    """Request deletion once with an exact UID precondition; never infer absence."""
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        if not hmac.compare_digest(backup_installation.safe_file(session._key_path,private=True,limit=32),key):raise ValueError
        session._scope();writer_guard.verify(session,operation,key)
        plan=storage._read(session.home,'kubernetes-audit-reader-plan.json',key)
        created=storage._read(session.home,CREATED,key)
        if (set(created)!={'operation','plan_sha256','uid'} or created.get('operation')!=operation
                or created.get('plan_sha256')!=storage._hash(plan)
                or plan['operation']!=operation or plan['site']!=session.site
                or plan['audit_pvc_uid']!=session._record['audit_pvc_uid']):raise ValueError
        uid=created['uid'];pod=session._query(['get','pod',plan['reader_name']])
        verify_pod(plan,pod,uid,ready=False)
        intent={'operation':operation,'plan_sha256':storage._hash(plan),'uid':uid}
        storage._write(session.home,DELETE_ATTEMPT,intent,key)
        config_fd=session._inner.config_fd;binary_fd=session._inner.api.binary_fd
        sealed.verify_sealed(config_fd,session.config_sha256)
        binary.verify(binary_fd,session._record['kubectl_sha256'])
        session._scope();writer_guard.verify(session,operation,key)
        resource='/api/v1/namespaces/'+session.site+'/pods/'+plan['reader_name']
        body={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':uid}}
        command=['/proc/self/fd/'+str(binary_fd),'--kubeconfig=/proc/self/fd/'+str(config_fd),
                 '--context='+session.api.context,'--namespace='+session.site,'--request-timeout=20s',
                 'delete','--raw='+resource,'-f','-']
        response=json.loads(_call_input(command,json.dumps(body,separators=(',',':')).encode(),config_fd,binary_fd))
        status=(response.get('kind')=='Status' and response.get('status')=='Success')
        item=(response.get('kind')=='Pod' and response.get('metadata',{}).get('uid')==uid
              and response.get('metadata',{}).get('name')==plan['reader_name']
              and response.get('metadata',{}).get('namespace')==session.site)
        if not status and not item:raise ValueError
        session._scope();writer_guard.verify(session,operation,key)
        return {'reader_deletion_requested':True,'old_uid_gone':False,'safe_to_backup':False}
    except Exception:raise AuditReaderError('KUBE_AUDIT_READER_DELETE_UNCERTAIN') from None


def observe_deletion(session,operation,key):
    """Read-only UID observation; empty JSON output means the Pod is absent."""
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        if not hmac.compare_digest(backup_installation.safe_file(session._key_path,private=True,limit=32),key):raise ValueError
        session._scope();writer_guard.verify(session,operation,key)
        plan=storage._read(session.home,'kubernetes-audit-reader-plan.json',key)
        created=storage._read(session.home,CREATED,key)
        uid=created['uid'];digest=storage._hash(plan)
        if (set(created)!={'operation','plan_sha256','uid'} or created['operation']!=operation
                or created['plan_sha256']!=digest or plan['operation']!=operation or plan['site']!=session.site
                or storage._read(session.home,DELETE_ATTEMPT,key)!={'operation':operation,'plan_sha256':digest,'uid':uid}):
            raise ValueError
        pod_spec(plan)
        if not identity.UUID.fullmatch(uid):raise ValueError
        config_fd=session._inner.config_fd;binary_fd=session._inner.api.binary_fd
        sealed.verify_sealed(config_fd,session.config_sha256);binary.verify(binary_fd,session._record['kubectl_sha256'])
        command=['/proc/self/fd/'+str(binary_fd),'--kubeconfig=/proc/self/fd/'+str(config_fd),
                 '--context='+session.api.context,'--namespace='+session.site,'--request-timeout=20s',
                 'get','pod/'+plan['reader_name'],'--ignore-not-found','-o','json']
        raw=_call_input(command,b'',config_fd,binary_fd)
        session._scope();writer_guard.verify(session,operation,key)
        if not raw.strip():return {'reader_old_uid_gone':True,'safe_to_backup':False}
        pod=json.loads(raw);meta=pod['metadata']
        if (pod.get('kind')!='Pod' or meta.get('name')!=plan['reader_name'] or meta.get('namespace')!=session.site
                or meta.get('uid')!=uid):raise ValueError
        return {'reader_old_uid_gone':False,'safe_to_backup':False}
    except Exception:raise AuditReaderError('KUBE_AUDIT_READER_DELETION_UNVERIFIED') from None


def capture_audit(session,operation,key,writer):
    """Encrypt and structurally check one audit tar; not a complete backup."""
    process=None;timer=None;accepted=False
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        if not hmac.compare_digest(backup_installation.safe_file(session._key_path,private=True,limit=32),key):raise ValueError
        plan=storage._read(session.home,'kubernetes-audit-reader-plan.json',key)
        created=storage._read(session.home,CREATED,key)
        if (set(created)!={'operation','plan_sha256','uid'} or created['operation']!=operation
                or plan['operation']!=operation or created['plan_sha256']!=storage._hash(plan)
                or plan['audit_pvc_uid']!=session._record['audit_pvc_uid']):raise ValueError
        def observe():
            session._scope();writer_guard.verify(session,operation,key)
            pod=session._query(['get','pod',plan['reader_name']])
            image_id=session.manifest.get('image_config_ids',{}).get('guardrail')
            verify_pod(plan,pod,created['uid'],ready=True,image_config_id=image_id)
            return (pod['metadata']['uid'],pod['status']['containerStatuses'][0]['containerID'],storage._hash(pod['spec']))
        before=observe()
        config_fd=session._inner.config_fd;binary_fd=session._inner.api.binary_fd
        sealed.verify_sealed(config_fd,session.config_sha256);binary.verify(binary_fd,session._record['kubectl_sha256'])
        command=['/proc/self/fd/'+str(binary_fd),'--kubeconfig=/proc/self/fd/'+str(config_fd),
                 '--context='+session.api.context,'--namespace='+session.site,'--request-timeout=20s',
                 'exec','pod/'+plan['reader_name'],'-c','reader','--','python','-c',
                 'import sys,tarfile;t=tarfile.open(fileobj=sys.stdout.buffer,mode="w|");t.add("/snapshot",arcname="audit",recursive=True);t.close()']
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env=dict(binary.ENV),pass_fds=(config_fd,binary_fd),start_new_session=True)
        timer=threading.Timer(300,_stop,args=(process,));timer.start()
        class Limited:
            def __init__(self,source):self.source=source;self.count=0
            def read(self,size):
                chunk=self.source.read(size);self.count+=len(chunk)
                if self.count>AUDIT_MAX_BYTES:raise ValueError
                return chunk
        writer.put('audit',Limited(process.stdout))
        timer.cancel();timer.join();timer=None
        if process.wait(timeout=120)!=0:raise ValueError
        backup_snapshot.verify_encrypted_tar(writer,'audit')
        if observe()!=before:raise ValueError
        accepted=True
        return {'audit_component_captured':True,'complete_backup':False,'safe_to_update':False}
    except Exception:raise AuditReaderError('KUBE_AUDIT_CAPTURE_UNVERIFIED') from None
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
        if not accepted or cleanup_error:
            manifest=getattr(writer,'manifest',None)
            if isinstance(manifest,dict) and isinstance(manifest.get('files'),dict):manifest['files'].pop('audit',None)
        if cleanup_error and accepted:raise AuditReaderError('KUBE_AUDIT_CAPTURE_CLEANUP_UNVERIFIED') from None
