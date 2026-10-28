"""End-to-end restoration to a NEW disposable Compose project in GitHub CI only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

import uterctl
from scripts import recovery_aof, recovery_preflight
from scripts.smoke_http import check as smoke

ROOT=Path(__file__).resolve().parents[1]
NAME='uter-restored-ci'


def call(args, *, env=None):
    result=subprocess.run([str(x) for x in args],env=env,capture_output=True,timeout=600)
    if result.returncode:raise RuntimeError(f'{args[0]} isolated recovery test failed; output withheld')
    return result.stdout


def test(home,backup,backup_key,publisher_key,exported,expected_audit):
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.name!='posix' or os.geteuid()!=0:
        raise ValueError('Disposable GitHub-hosted Linux runner required')
    home=Path(home).resolve();work=ROOT/'work';target=work/'restored-compose'
    if target.exists():raise ValueError('Recovery test target already exists')
    for kind in ('container','network','volume'):
        if call(['docker',kind,'ls','-q','--filter','label=com.docker.compose.project='+NAME]).strip():
            raise ValueError('Recovery test project already exists')
    vols={kind:NAME+'_'+kind+'-data' for kind in ('redis','audit')}
    for volume in vols.values():
        if subprocess.run(['docker','volume','inspect',volume],capture_output=True).returncode==0:
            raise ValueError('Recovery test volume already exists')
    tmp_container=NAME+'-redis-init';cmd=None;env=None;created_volumes=[];created_container=False;compose_started=False
    if subprocess.run(['docker','inspect',tmp_container],capture_output=True).returncode==0:
        raise ValueError('Recovery test container already exists')
    try:
        with tempfile.TemporaryDirectory(prefix='compose-recovery-',dir=work) as temp:
            temp=Path(temp);stage=temp/'stage'
            result=recovery_preflight.preflight(home,backup,backup_key,publisher_key,stage)
            if result['backend']!='compose':raise ValueError('Expected Compose backup')
            source=stage/'runtime-staged';state=uterctl.read(source/'state.json');current=state['current']
            # Recreate runtime only under a new, unique project; never touch source home or volumes.
            shutil.copytree(source,target)
            bundle=target/'releases'/current['version']
            if uterctl.verify(bundle,publisher_key)!=current:raise ValueError('Signed recovery bundle changed')
            shutil.copytree(bundle/'compose',target/'compose')
            shutil.copytree(bundle/'charts',target/'charts')
            cfg=uterctl.read(target/'install.json');cfg.update(name=NAME,port=18001,images=current['images'])
            uterctl.write(target/'install.json',cfg)
            site=uterctl.site_config(target);site.update(name=NAME,namespace=NAME,port=18001)
            uterctl.write(target/'runtime/site.json',site)
            runtime=target/'runtime'
            for folder in ('policies','profiles','models'):os.chmod(runtime/folder,0o755)
            for path in (runtime/'policies/runtime.toml',runtime/'profiles/model_profiles.toml',runtime/'audit-hmac-key'):
                os.chown(path,10001,10001);os.chmod(path,0o400)
            for filename in ('redis.conf','redis-password'):
                os.chown(runtime/filename,999,10001);os.chmod(runtime/filename,0o440)
            env=os.environ.copy();env.update({s.upper()+'_IMAGE':v for s,v in current['images'].items()})
            env.update(RUNTIME_DIR=str(runtime),GUARDRAIL_PORT='18001',GUARDRAIL_CPUS=str(cfg.get('guardrail_cpus',2)))
            cmd=['docker','--context','default','compose','--project-name',NAME,'--env-file',str(target/'empty.env'),'-f',str(target/'compose/compose.yaml')]
            # Explicit names and labels bind the empty volumes to this test project.
            for kind,volume in vols.items():
                call(['docker','volume','create','--label','com.docker.compose.project='+NAME,
                      '--label','com.docker.compose.volume='+kind+'-data',volume])
                created_volumes.append(volume)
            for kind,uid,gid,filename in [('redis',999,1000,'redis.rdb'),('audit',10001,10001,'audit.tar')]:
                transfer=temp/(kind+'-input');shutil.copyfile(Path(exported)/filename,transfer)
                os.chown(transfer,uid,gid);os.chmod(transfer,0o400)
                image=current['images']['guardrail'];mount='type=volume,source='+vols[kind]+',target=/data'
                call(['docker','run','--rm','--network','none','--user','0','--mount',mount,
                      '--entrypoint','python',image,'-c',f"import os;os.chown('/data',{uid},{gid})"])
                call(['docker','run','--rm','--network','none','--user',f'{uid}:{gid}','--mount',mount,
                      '--mount','type=bind,source='+str(transfer)+',target=/snapshot,readonly',
                      '--mount','type=bind,source='+str(ROOT/'scripts')+',target=/tool/scripts,readonly',
                      '--entrypoint','python',image,'/tool/scripts/recovery_volume.py',kind,
                      '--snapshot','/snapshot','--destination','/data'])
            redis=current['images']['redis'];mount='type=volume,source='+vols['redis']+',target=/data'
            call(['docker','run','-d','--name',tmp_container,'--network','none','--user','999:1000',
                  '--mount',mount,'--entrypoint','redis-server',redis,'--dir','/data','--dbfilename','dump.rdb',
                  '--save','','--appendonly','no','--bind','127.0.0.1'])
            created_container=True
            def cli(args):return call(['docker','exec',tmp_container,'redis-cli','--raw',*args])
            for attempt in range(30):
                try:
                    if cli(['GET','ci:upgrade:sentinel']).strip()==b'uter-upgrade-check':break
                except RuntimeError:pass
                if attempt==29:raise ValueError('Restored Redis RDB did not load')
                time.sleep(1)
            recovery_aof.enable_checked(cli)
            subprocess.run(['docker','exec',tmp_container,'redis-cli','shutdown'],capture_output=True)
            if call(['docker','wait',tmp_container]).strip()!=b'0':raise ValueError('Redis recovery shutdown failed')
            call(['docker','rm',tmp_container])
            created_container=False
            compose_started=True
            call(cmd+['up','-d','--no-build','--pull','never','--wait','--wait-timeout','300'],env=env)
            credentials=uterctl.read(target/'credentials.json')
            smoke('http://127.0.0.1:18001','admin',credentials['admin'])
            from scripts.adopt_backup_ci import audit_and_redis
            guard=cmd+['exec','-T','guardrail','python','-']
            data=audit_and_redis(guard,env,'read')
            if data['first_sha256']!=expected_audit['first_sha256']:
                raise ValueError('Restored audit chain does not match backup')
            print('New Compose project: restored Redis, audit, runtime and smoke: PASS',flush=True)
    finally:
        if created_container:subprocess.run(['docker','rm','-f',tmp_container],capture_output=True)
        if compose_started:subprocess.run(cmd+['down','--volumes','--remove-orphans'],env=env,capture_output=True)
        for volume in created_volumes:subprocess.run(['docker','volume','rm',volume],capture_output=True)
