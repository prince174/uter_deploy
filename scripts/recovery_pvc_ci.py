"""Exercise recovery into new disposable Kubernetes PVCs on a CI-only cluster."""
import json
import os
import copy
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]


def call(args, data=None):
    result=subprocess.run([str(x) for x in args],input=data,capture_output=True,timeout=240)
    if result.returncode:
        stderr=result.stderr.decode(errors='replace')
        known=('Destination must be an explicitly mounted recovery volume',
               'Recovery volume is not empty', 'Permission denied',
               'Invalid Redis snapshot header', 'Audit log is missing',
               'No module named', 'No such file or directory')
        category=next((message for message in known if message in stderr),'unclassified')
        raise RuntimeError(f'{args[0]} recovery PVC test failed ({category}); output withheld')
    return result.stdout


def test(kube, namespace, image, redis_image, exported):
    """Create and remove only unique CI test PVCs and pods, never production PVCs."""
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or namespace != 'uter-upgrade-ci'
            or kube != ['kubectl','--context','kind-uter-upgrade-ci']):
        raise ValueError('This test only runs in its explicitly named disposable CI cluster')
    kube=kube+['-n',namespace]; cm='uter-recovery-ci-code'; names=[]
    try:
        call(kube+['create','configmap',cm,
                   '--from-file=recovery_volume.py='+str(ROOT/'scripts/recovery_volume.py'),
                   '--from-file=archive_safety.py='+str(ROOT/'scripts/archive_safety.py')])
        for kind,uid,gid,file in [('redis',999,1000,'redis.rdb'),('audit',10001,10001,'audit.tar')]:
            pvc='uter-recovery-ci-'+kind;helper=pvc+'-helper';names.append((pvc,helper))
            pvc_spec={'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':{'name':pvc},
                'spec':{'accessModes':['ReadWriteOnce'],'resources':{'requests':{'storage':'1Gi'}}}}
            call(kube+['create','-f','-'],json.dumps(pvc_spec).encode())
            pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':helper},'spec':{
                'restartPolicy':'Never','automountServiceAccountToken':False,
                'securityContext':{'runAsNonRoot':True,'runAsUser':uid,'runAsGroup':gid,'fsGroup':gid,
                                   'seccompProfile':{'type':'RuntimeDefault'}},
                'containers':[{'name':'helper','image':image,'command':['python','-c','import time;time.sleep(600)'],
                    'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
                    'volumeMounts':[{'name':'data','mountPath':'/data'},{'name':'tmp','mountPath':'/tmp'},
                                    {'name':'code','mountPath':'/tool/scripts','readOnly':True}]}],
                'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':pvc}},
                           {'name':'tmp','emptyDir':{'sizeLimit':'128Mi'}},
                           {'name':'code','configMap':{'name':cm}}]}}
            call(kube+['create','-f','-'],json.dumps(pod).encode())
            call(kube+['wait','--for=condition=Ready','pod/'+helper,'--timeout=180s'])
            source=Path(exported)/file
            if source.stat().st_size>100*1024*1024:raise ValueError('CI recovery input exceeds bounded tmpfs')
            copy='import sys; f=open("/tmp/snapshot","wb"); f.write(sys.stdin.buffer.read()); f.close()'
            call(kube+['exec','-i',helper,'--','python','-c',copy],source.read_bytes())
            call(kube+['exec',helper,'--','python','/tool/scripts/recovery_volume.py',kind,
                       '--snapshot','/tmp/snapshot','--destination','/data'])
            if kind=='audit':
                code='from pathlib import Path; assert Path("/data/audit.jsonl").is_file()'
                call(kube+['exec',helper,'--','python','-c',code])
            call(kube+['delete','pod',helper,'--wait=true','--timeout=180s'])
            if kind=='redis':
                redis_pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':helper+'-redis'},'spec':{
                    'restartPolicy':'Never','automountServiceAccountToken':False,
                    'securityContext':{'runAsNonRoot':True,'runAsUser':999,'runAsGroup':1000,'fsGroup':1000,
                                       'seccompProfile':{'type':'RuntimeDefault'}},
                    'containers':[{'name':'redis','image':redis_image,'command':['redis-server'],
                        'args':['--dir','/data','--dbfilename','dump.rdb','--save','','--appendonly','no','--bind','127.0.0.1'],
                        'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
                        'volumeMounts':[{'name':'data','mountPath':'/data'},{'name':'tmp','mountPath':'/tmp'}]}],
                    'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':pvc}},{'name':'tmp','emptyDir':{}}]}}
                call(kube+['create','-f','-'],json.dumps(redis_pod).encode())
                call(kube+['wait','--for=condition=Ready','pod/'+helper+'-redis','--timeout=180s'])
                for attempt in range(30):
                    p=subprocess.run(kube+['exec',helper+'-redis','--','redis-cli','--raw','GET','ci:upgrade:sentinel'],capture_output=True)
                    if p.returncode==0 and p.stdout.strip()==b'uter-upgrade-check':break
                    if attempt==29:raise ValueError('Restored Kubernetes PVC did not contain Redis sentinel')
                    time.sleep(1)
                # Redis started directly with AOF enabled can create an empty AOF and
                # ignore the restored RDB. Load RDB first, rewrite AOF, then restart.
                from scripts.recovery_aof import enable_checked
                def cli(args):
                    return call(kube+['exec',helper+'-redis','--','redis-cli','--raw',*args])
                enable_checked(cli)
                subprocess.run(kube+['exec',helper+'-redis','--','redis-cli','shutdown'],capture_output=True)
                for attempt in range(60):
                    pod_status=json.loads(call(kube+['get','pod',helper+'-redis','-o','json']))['status']
                    terminated=next((x.get('state',{}).get('terminated') for x in pod_status.get('containerStatuses',[])
                                     if x.get('state',{}).get('terminated')),None)
                    if terminated is not None:
                        if terminated.get('exitCode') != 0:raise ValueError('Redis recovery shutdown failed')
                        break
                    if attempt==59:raise ValueError('Redis recovery shutdown timed out')
                    time.sleep(1)
                call(kube+['delete','pod',helper+'-redis','--wait=true','--timeout=180s'])
                restarted=copy.deepcopy(redis_pod)
                restarted['metadata']['name']=helper+'-check'
                args=restarted['spec']['containers'][0]['args']
                args[args.index('--appendonly')+1]='yes'
                call(kube+['create','-f','-'],json.dumps(restarted).encode())
                call(kube+['wait','--for=condition=Ready','pod/'+helper+'-check','--timeout=180s'])
                for attempt in range(30):
                    p=subprocess.run(kube+['exec',helper+'-check','--','redis-cli','--raw','GET','ci:upgrade:sentinel'],capture_output=True)
                    if p.returncode==0 and p.stdout.strip()==b'uter-upgrade-check':break
                    if attempt==29:raise ValueError('AOF restart did not retain Redis snapshot')
                    time.sleep(1)
                call(kube+['delete','pod',helper+'-check','--wait=true','--timeout=180s'])
        print('New Kubernetes PVCs: audit extracted and Redis restored: PASS',flush=True)
    finally:
        for pvc,helper in names:
            subprocess.run(kube+['delete','pod',helper,helper+'-redis',helper+'-check','--ignore-not-found','--wait=true'],capture_output=True)
            subprocess.run(kube+['delete','pvc',pvc,'--ignore-not-found','--wait=true'],capture_output=True)
        subprocess.run(kube+['delete','configmap',cm,'--ignore-not-found'],capture_output=True)
