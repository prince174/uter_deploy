"""Restore an authenticated backup into a NEW Kubernetes namespace and installation."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error

import yaml
sys.dont_write_bytecode = True  # Signed bundles must remain byte-for-byte immutable.
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import adopt_installation, install, recovery_kube_volumes, recovery_preflight
from scripts.smoke_http import check as smoke

ROOT=Path(__file__).resolve().parents[1]


def run(args, *, data=None):
    p=subprocess.run([str(x) for x in args],input=data,capture_output=True,timeout=600)
    if p.returncode:raise RuntimeError(f'{args[0]} recovery operation failed; output withheld to protect data')
    return p.stdout


def resource_mapping(values,new_name):
    roles={'guardrailSecret':'guardrail-env','agentSecret':'agent-env','redisSecret':'redis-secret',
           'policyConfigMap':'policies','profileConfigMap':'profiles'}
    mapping={}
    for key,suffix in roles.items():
        old=values.get(key)
        if not isinstance(old,str) or not old or old in mapping:raise ValueError('Invalid or duplicate Kubernetes resource reference')
        mapping[old]=new_name+'-'+suffix;values[key]=mapping[old]
    pulls=values.get('imagePullSecrets',[])
    if not isinstance(pulls,list):raise ValueError('Invalid image pull secrets')
    for index,item in enumerate(pulls):
        old=item.get('name') if isinstance(item,dict) else None
        if not isinstance(old,str) or not old or old in mapping:raise ValueError('Invalid or duplicate image pull secret')
        mapping[old]=new_name+'-registry-'+str(index);item['name']=mapping[old]
    return mapping


def prepare_objects(items, mapping, source_name, namespace):
    objects=[];sizes={};seen=set()
    for item in items:
        kind=item.get('kind');old=item.get('metadata',{}).get('name')
        if kind=='PersistentVolumeClaim':
            role={'-redis':'redis','-guardrail':'audit'}
            matched=next((v for suffix,v in role.items() if old==source_name+suffix),None)
            if not matched or matched in sizes:raise ValueError('Unexpected Kubernetes PVC')
            sizes[matched]=item['spec']['resources']['requests']['storage']
            continue
        if kind not in ('Secret','ConfigMap') or old not in mapping or old in seen:
            raise ValueError('Unexpected Kubernetes recovery resource')
        seen.add(old)
        obj={'apiVersion':'v1','kind':kind,'metadata':{'name':mapping[old],'namespace':namespace}}
        for field in ('data','binaryData','type','immutable'):
            if field in item:obj[field]=item[field]
        objects.append(obj)
    if seen!=set(mapping) or set(sizes)!={'redis','audit'}:
        raise ValueError('Incomplete Kubernetes recovery resources')
    return objects,sizes


def restore(source_home,backup,backup_key,publisher_key,target,name,context,port,storage_class=None):
    if os.name!='posix':raise ValueError('Kubernetes recovery requires a Linux host')
    if not install.NAME.fullmatch(name):raise ValueError('Invalid new Kubernetes namespace name')
    if not isinstance(context,str) or not context or context.startswith('-'):raise ValueError('Explicit Kubernetes context required')
    if type(port) is not int or not 1024<=port<=65535:raise ValueError('Invalid recovery port')
    source_home=Path(source_home).resolve();target=Path(target).absolute()
    if target.exists() or target.is_symlink():raise ValueError('Recovery home already exists')
    parent=target.parent.resolve(strict=True);target=parent/target.name
    if target==source_home or target.is_relative_to(source_home):raise ValueError('Recovery home must be outside the original installation')
    with socket.socket() as s:s.bind(('127.0.0.1',port))
    marker_id=secrets.token_hex(16);kube=['kubectl','--context',context];forward=None
    with tempfile.TemporaryDirectory(prefix='.uter-recovery-',dir=parent) as temp:
        temp=Path(temp);stage=temp/'stage'
        result=recovery_preflight.preflight(source_home,backup,backup_key,publisher_key,stage)
        if result['backend']!='helm':raise ValueError('This command requires a Kubernetes backup')
        source=stage/'runtime-staged';state=uterctl.read(source/'state.json');current=state['current']
        cfg=uterctl.read(source/'install.json');site=uterctl.site_config(source)
        if name==site['name']:raise ValueError('Recovery namespace must have a different name')
        bundle=source/'releases'/current['version']
        if uterctl.verify(bundle,publisher_key)!=current:raise ValueError('Signed backup release changed')
        values=yaml.safe_load((source/'runtime/values.yaml').read_text())
        mapping=resource_mapping(values,name)
        objects,sizes=prepare_objects(json.loads((stage/'kubernetes.json').read_text())['items'],mapping,cfg['name'],name)
        selected=values.get('storageClass','') if storage_class is None else storage_class
        values.update(images=current['images'],productVersion=current['version'],storageClass=selected,
                      redisSize=sizes['redis'],auditSize=sizes['audit'])
        shutil.copytree(source,target)
        journal=target/'recovery-operation.json'
        def record(phase):uterctl.write(journal,{'schema':1,'phase':phase,'id':marker_id,'source_backup':result['backup_id']})
        record('preparing')
        uterctl.write(target/'install-state.json',{'status':'pending','operation':'recovery'})
        try:
            signed=target/'releases'/current['version']
            if uterctl.verify(signed,publisher_key)!=current:raise ValueError('Copied signed release changed')
            shutil.copytree(signed/'compose',target/'compose');shutil.copytree(signed/'charts',target/'charts')
            shutil.copyfile(signed/'empty.env',target/'empty.env')
            cfg.update(name=name,context=context,port=port,images=current['images']);uterctl.write(target/'install.json',cfg)
            runtime=target/'runtime';shutil.copyfile(ROOT/'scripts/smoke_http.py',runtime/'smoke_http.py')
            wrapper='''import json,subprocess,time,urllib.error\nfrom pathlib import Path\nfrom smoke_http import check\nhome=Path(__file__).resolve().parent.parent\ncfg=json.loads((home/"install.json").read_text())\ncreds=json.loads((home/"credentials.json").read_text())\nf=subprocess.Popen(["kubectl","--context",cfg["context"],"-n",cfg["name"],"port-forward","service/"+cfg["name"]+"-guardrail",str(cfg["port"])+":8000"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\ntry:\n for i in range(45):\n  try:\n   check("http://127.0.0.1:"+str(cfg["port"]),"admin",creds["admin"]);break\n  except (OSError,urllib.error.URLError):\n   if i==44:raise\n   time.sleep(1)\nfinally:\n f.terminate();f.wait(timeout=10)\n'''
            (runtime/'recovery_smoke.py').write_text(wrapper,encoding='utf-8')
            site.update(name=name,namespace=name,context=context,port=port,smoke_command=[sys.executable,str(runtime/'recovery_smoke.py')])
            uterctl.write(runtime/'site.json',site);uterctl.site_config(target)
            state.pop('last_backup',None);uterctl.write(target/'state.json',state)
            (runtime/'values.yaml').write_text(yaml.safe_dump(values),encoding='utf-8')
            (target/'values.yaml').write_text(yaml.safe_dump(values),encoding='utf-8')
            (target/'resources.yaml').write_text(yaml.safe_dump_all(objects),encoding='utf-8')
            ns={'apiVersion':'v1','kind':'Namespace','metadata':{'name':name,'labels':{'uter.io/recovery-id':marker_id}}}
            record('creating-namespace')
            run(kube+['create','-f','-'],data=json.dumps(ns).encode())
            run(kube+['-n',name,'create','-f','-'],data=json.dumps({'apiVersion':'v1','kind':'List','items':objects}).encode())
            record('restoring-volumes')
            pull_secrets=[x['name'] for x in values.get('imagePullSecrets',[])]
            recovery_kube_volumes.populate(kube,name,name,marker_id,current['images'],stage,sizes,selected,pull_secrets)
            record('starting')
            observed=json.loads(run(kube+['get','namespace',name,'-o','json']))
            if observed.get('metadata',{}).get('labels',{}).get('uter.io/recovery-id')!=marker_id:
                raise ValueError('Recovery namespace ownership could not be verified')
            run(['helm','--kube-context',context,'install',name,signed/'charts/uter','--namespace',name,
                 '-f',runtime/'values.yaml','--wait','--timeout','5m'])
            adopt_installation.verify_live(target,cfg,current)
            forward=subprocess.Popen(kube+['-n',name,'port-forward','service/'+name+'-guardrail',str(port)+':8000'],
                                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            credentials=uterctl.read(target/'credentials.json')
            for attempt in range(45):
                try:smoke('http://127.0.0.1:'+str(port),'admin',credentials['admin']);break
                except (OSError,urllib.error.URLError):
                    if attempt==44:raise
                    time.sleep(1)
            uterctl.write(target/'install-state.json',{'status':'ready','acceptance':'passed'})
            record('complete')
            return {'name':name,'home':str(target),'version':current['version'],'backup_id':result['backup_id']}
        finally:
            if forward:forward.terminate();forward.wait(timeout=10)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source-home','backup','backup-key','publisher-key','home'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--name',required=True);p.add_argument('--context',required=True)
    p.add_argument('--port',type=int,default=18000);p.add_argument('--storage-class')
    a=p.parse_args();print(json.dumps(restore(a.source_home,a.backup,a.backup_key,a.publisher_key,a.home,a.name,a.context,a.port,a.storage_class)))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(f'kubernetes recovery: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
