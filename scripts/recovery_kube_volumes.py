"""Populate NEW Kubernetes recovery PVCs; never use existing installation PVCs."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time

from scripts.recovery_aof import enable_checked

ROOT=Path(__file__).resolve().parents[1]


def run(args, data=None):
    p=subprocess.run([str(x) for x in args],input=data,capture_output=True,timeout=600)
    if p.returncode:raise RuntimeError(f'{args[0]} recovery operation failed; output withheld to protect data')
    return p.stdout


def stream(args, source):
    p=subprocess.Popen([str(x) for x in args],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    timer=threading.Timer(600,lambda: p.kill() if p.poll() is None else None);timer.start()
    try:
        with Path(source).open('rb') as f:shutil.copyfileobj(f,p.stdin,1024*1024)
        p.stdin.close()
        if p.wait(timeout=600)!=0:raise RuntimeError('Kubernetes recovery data transfer failed')
    finally:
        timer.cancel()
        if p.poll() is None:p.kill();p.wait()
        if not p.stdin.closed:p.stdin.close()


def populate(kube,namespace,name,marker,images,staged,sizes,storage_class,pull_secrets):
    if not re.fullmatch(r'[0-9a-f]{32}',marker):raise ValueError('Invalid recovery identity')
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,38}[a-z0-9]',name) or namespace!=name:
        raise ValueError('Recovery namespace and name must match')
    if not isinstance(kube,list) or len(kube)!=3 or kube[:2]!=['kubectl','--context'] or not kube[2] or kube[2].startswith('-'):
        raise ValueError('Explicit Kubernetes context required')
    if set(sizes)!={'redis','audit'} or any(not re.fullmatch(r'[1-9][0-9]*(?:Ki|Mi|Gi|Ti)',str(x)) for x in sizes.values()):
        raise ValueError('Recovery PVC sizes must be positive binary quantities')
    if storage_class and not re.fullmatch(r'[a-z0-9]([-a-z0-9.]*[a-z0-9])?',storage_class):
        raise ValueError('Invalid storage class')
    if not isinstance(pull_secrets,list) or any(not re.fullmatch(r'[a-z0-9]([-a-z0-9.]*[a-z0-9])?',x) for x in pull_secrets):
        raise ValueError('Invalid image pull secret')
    kube=kube+['-n',namespace];cm='uter-recovery-'+marker[:12];pods=[];created_cm=False
    try:
        run(kube+['create','configmap',cm,'--from-file=recovery_volume.py='+str(ROOT/'scripts/recovery_volume.py'),
                  '--from-file=archive_safety.py='+str(ROOT/'scripts/archive_safety.py')]);created_cm=True
        for kind,uid,gid,filename in [('redis',999,1000,'redis.rdb'),('audit',10001,10001,'audit.tar')]:
            pvc=name+('-redis' if kind=='redis' else '-guardrail')
            metadata={'name':pvc,'namespace':namespace,'labels':{'app.kubernetes.io/managed-by':'Helm','uter.io/recovery-id':marker},
                      'annotations':{'meta.helm.sh/release-name':name,'meta.helm.sh/release-namespace':namespace,'helm.sh/resource-policy':'keep'}}
            spec={'accessModes':['ReadWriteOnce'],'resources':{'requests':{'storage':sizes[kind]}}}
            if storage_class:spec['storageClassName']=storage_class
            run(kube+['create','-f','-'],json.dumps({'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':metadata,'spec':spec}).encode())
            helper='uter-r-'+marker[:12]+'-'+kind
            snapshot=Path(staged)/filename
            size_mib=max(1,(snapshot.stat().st_size+1048575)//1048576+16)
            pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':helper,'labels':{'uter.io/recovery-id':marker}},'spec':{
                'restartPolicy':'Never','automountServiceAccountToken':False,'imagePullSecrets':[{'name':x} for x in pull_secrets],
                'securityContext':{'runAsNonRoot':True,'runAsUser':uid,'runAsGroup':gid,'fsGroup':gid,
                                   'seccompProfile':{'type':'RuntimeDefault'}},
                'containers':[{'name':'helper','image':images['guardrail'],'command':['python','-c','import time;time.sleep(3600)'],
                    'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
                    'volumeMounts':[{'name':'data','mountPath':'/data'},{'name':'tmp','mountPath':'/tmp'},
                                    {'name':'code','mountPath':'/tool/scripts','readOnly':True}]}],
                'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':pvc}},
                           {'name':'tmp','emptyDir':{'sizeLimit':str(size_mib)+'Mi'}},
                           {'name':'code','configMap':{'name':cm}}]}}
            run(kube+['create','-f','-'],json.dumps(pod).encode());pods.append(helper)
            run(kube+['wait','--for=condition=Ready','pod/'+helper,'--timeout=300s'])
            code='import sys,shutil; f=open("/tmp/snapshot","xb"); shutil.copyfileobj(sys.stdin.buffer,f,1048576); f.close()'
            stream(kube+['exec','-i',helper,'--','python','-c',code],snapshot)
            run(kube+['exec',helper,'--','python','/tool/scripts/recovery_volume.py',kind,'--snapshot','/tmp/snapshot','--destination','/data'])
            run(kube+['delete','pod',helper,'--wait=true','--timeout=180s']);pods.remove(helper)
            if kind!='redis':continue
            redis_name='uter-r-'+marker[:12]+'-redis-init'
            def redis_spec(podname,appendonly):
                return {'apiVersion':'v1','kind':'Pod','metadata':{'name':podname,'labels':{'uter.io/recovery-id':marker}},'spec':{
                    'restartPolicy':'Never','automountServiceAccountToken':False,'imagePullSecrets':[{'name':x} for x in pull_secrets],
                    'securityContext':{'runAsNonRoot':True,'runAsUser':999,'runAsGroup':1000,'fsGroup':1000,
                                       'seccompProfile':{'type':'RuntimeDefault'}},
                    'containers':[{'name':'redis','image':images['redis'],'command':['redis-server'],
                        'args':['--dir','/data','--dbfilename','dump.rdb','--save','','--appendonly',appendonly,'--bind','127.0.0.1'],
                        'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
                        'volumeMounts':[{'name':'data','mountPath':'/data'},{'name':'tmp','mountPath':'/tmp'}]}],
                    'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':pvc}},{'name':'tmp','emptyDir':{}}]}}
            run(kube+['create','-f','-'],json.dumps(redis_spec(redis_name,'no')).encode());pods.append(redis_name)
            run(kube+['wait','--for=condition=Ready','pod/'+redis_name,'--timeout=300s'])
            def cli(args):return run(kube+['exec',redis_name,'--','redis-cli','--raw',*args])
            for attempt in range(60):
                try:
                    if cli(['PING']).strip()==b'PONG':break
                except RuntimeError:pass
                if attempt==59:raise TimeoutError('Restored Redis did not start')
                time.sleep(1)
            count=int(cli(['DBSIZE']).strip());enable_checked(cli)
            subprocess.run(kube+['exec',redis_name,'--','redis-cli','shutdown'],capture_output=True)
            for attempt in range(60):
                status=json.loads(run(kube+['get','pod',redis_name,'-o','json']))['status']
                terminated=next((x.get('state',{}).get('terminated') for x in status.get('containerStatuses',[]) if x.get('state',{}).get('terminated')),None)
                if terminated is not None:
                    if terminated.get('exitCode')!=0:raise ValueError('Redis recovery shutdown failed')
                    break
                if attempt==59:raise TimeoutError('Redis recovery shutdown timed out')
                time.sleep(1)
            run(kube+['delete','pod',redis_name,'--wait=true','--timeout=180s']);pods.remove(redis_name)
            check_name='uter-r-'+marker[:12]+'-redis-check'
            run(kube+['create','-f','-'],json.dumps(redis_spec(check_name,'yes')).encode());pods.append(check_name)
            run(kube+['wait','--for=condition=Ready','pod/'+check_name,'--timeout=300s'])
            for attempt in range(60):
                p=subprocess.run(kube+['exec',check_name,'--','redis-cli','--raw','DBSIZE'],capture_output=True)
                if p.returncode==0:
                    if int(p.stdout.strip())!=count:raise ValueError('Redis key count changed during recovery')
                    break
                if attempt==59:raise TimeoutError('Recovered Redis AOF did not start')
                time.sleep(1)
            run(kube+['delete','pod',check_name,'--wait=true','--timeout=180s']);pods.remove(check_name)
    finally:
        for pod in pods:
            subprocess.run(kube+['delete','pod',pod,'--ignore-not-found','--wait=true'],capture_output=True)
        if created_cm:subprocess.run(kube+['delete','configmap',cm,'--ignore-not-found'],capture_output=True)
