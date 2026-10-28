"""Restore a full Uter installation to a NEW disposable Kubernetes namespace in CI."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error

import yaml
import uterctl
from scripts import recovery_preflight, recovery_pvc_ci
from scripts.smoke_http import check as smoke

ROOT=Path(__file__).resolve().parents[1]
NAME='uter-restored-ci'


def call(args, data=None):
    result=subprocess.run([str(x) for x in args],input=data,capture_output=True,timeout=600)
    if result.returncode:raise RuntimeError(f'{args[0]} isolated Kubernetes recovery test failed; output withheld')
    return result.stdout


def test(home,backup,backup_key,publisher_key,exported,expected_audit):
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.name!='posix' or os.geteuid()!=0:
        raise ValueError('Disposable GitHub-hosted Linux runner required')
    kube=['kubectl','--context','kind-uter-upgrade-ci'];namespace_created=False;forward=None
    # Creation is exclusive; never remove a namespace that this test did not create.
    try:
        call(kube+['create','namespace',NAME]);namespace_created=True
        with tempfile.TemporaryDirectory(prefix='kube-recovery-',dir=ROOT/'work') as temp:
            temp=Path(temp);stage=temp/'stage'
            result=recovery_preflight.preflight(home,backup,backup_key,publisher_key,stage)
            if result['backend']!='helm':raise ValueError('Expected Kubernetes backup')
            source=stage/'runtime-staged';state=uterctl.read(source/'state.json');current=state['current']
            bundle=source/'releases'/current['version']
            if uterctl.verify(bundle,publisher_key)!=current:raise ValueError('Signed recovery bundle changed')
            cfg=uterctl.read(source/'install.json');old=cfg['name']
            values=yaml.safe_load((source/'runtime/values.yaml').read_text())
            # Restore the live Secrets/ConfigMaps recorded in the authenticated backup.
            resources=json.loads((stage/'kubernetes.json').read_text())['items']
            objects=[]
            for item in resources:
                if item['kind']=='PersistentVolumeClaim':continue
                oldname=item['metadata']['name']
                if not oldname.startswith(old+'-'):raise ValueError('Nonstandard resource name is unsupported in CI recovery')
                newname=NAME+oldname[len(old):]
                # Published images are public; avoid copying ephemeral CI registry credentials.
                if oldname==old+'-registry':continue
                obj={'apiVersion':'v1','kind':item['kind'],'metadata':{'name':newname,'namespace':NAME}}
                for field in ('data','binaryData','type','immutable'):
                    if field in item:obj[field]=item[field]
                objects.append(obj)
            for field in ('guardrailSecret','agentSecret','redisSecret','policyConfigMap','profileConfigMap'):
                value=values.get(field)
                if not isinstance(value,str) or not value.startswith(old+'-'):
                    raise ValueError('Unexpected Kubernetes resource reference')
                values[field]=NAME+value[len(old):]
            values['imagePullSecrets']=[];values['images']=current['images'];values['productVersion']=current['version']
            values_file=temp/'values.yaml';values_file.write_text(yaml.safe_dump(values))
            call(kube+['-n',NAME,'create','-f','-'],json.dumps({'apiVersion':'v1','kind':'List','items':objects}).encode())
            recovery_pvc_ci.test(kube,NAME,current['images']['guardrail'],current['images']['redis'],exported,keep_pvcs=True)
            call(['helm','--kube-context','kind-uter-upgrade-ci','upgrade','--install',NAME,
                  bundle/'charts/uter','--namespace',NAME,'-f',values_file,'--wait','--timeout','5m'])
            forward=subprocess.Popen(kube+['-n',NAME,'port-forward','service/'+NAME+'-guardrail','18002:8000'],
                                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            credentials=uterctl.read(source/'credentials.json')
            for attempt in range(45):
                try:smoke('http://127.0.0.1:18002','admin',credentials['admin']);break
                except (OSError,urllib.error.URLError):
                    if attempt==44:raise
                    time.sleep(1)
            from scripts.adopt_backup_ci import audit_and_redis
            cmd=kube+['-n',NAME,'exec','-i','deployment/'+NAME+'-guardrail','--','python','-']
            data=audit_and_redis(cmd,None,'read')
            if data['first_sha256']!=expected_audit['first_sha256']:
                raise ValueError('Restored Kubernetes audit chain does not match backup')
            print('New Kubernetes namespace: restored Redis, audit, runtime and smoke: PASS',flush=True)
    finally:
        if forward:
            forward.terminate();forward.wait(timeout=10)
        if namespace_created:
            subprocess.run(kube+['delete','namespace',NAME,'--wait=true','--timeout=300s'],capture_output=True)
