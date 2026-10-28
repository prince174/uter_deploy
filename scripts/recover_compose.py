"""Restore an authenticated backup into a NEW Compose project, leaving its source untouched."""
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

sys.dont_write_bytecode = True  # Signed bundles must remain byte-for-byte immutable.
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import adopt_installation, install, recovery_aof, recovery_preflight
from scripts.smoke_http import check as smoke

ROOT=Path(__file__).resolve().parents[1]


def run(args, *, env=None):
    p=subprocess.run([str(x) for x in args],env=env,capture_output=True,timeout=600)
    if p.returncode:raise RuntimeError(f'{args[0]} recovery operation failed; output withheld to protect data')
    return p.stdout


def stage_recovery_helpers(parent):
    """Expose only non-secret helper code to the unprivileged volume container."""
    directory = Path(parent) / 'recovery-code'
    directory.mkdir(mode=0o700)
    for name in ('recovery_volume.py', 'archive_safety.py'):
        source = ROOT / 'scripts' / name
        if source.is_symlink() or not source.is_file():
            raise ValueError('Recovery helper must be a regular signed file')
        target = directory / name
        with source.open('rb') as src, target.open('xb') as dst:
            shutil.copyfileobj(src, dst)
        target.chmod(0o444)
    directory.chmod(0o555)
    return directory


def restore(source_home,backup,backup_key,publisher_key,target,name,port):
    if os.name!='posix' or os.geteuid()!=0:
        raise ValueError('Compose recovery requires root on a Linux host')
    if not install.NAME.fullmatch(name):raise ValueError('Invalid new Compose project name')
    if type(port) is not int or not 1024<=port<=65535:raise ValueError('Invalid recovery port')
    if os.environ.get('DOCKER_HOST'):raise ValueError('Only the local default Docker context is supported')
    endpoint=json.loads(run(['docker','--context','default','context','inspect','default']))[0]['Endpoints']['docker']['Host']
    if not endpoint.startswith('unix://'):raise ValueError('A local Unix Docker socket is required')
    source_home=Path(source_home).resolve();target=Path(target).absolute()
    if target.exists() or target.is_symlink():raise ValueError('Recovery home already exists')
    parent=target.parent.resolve(strict=True);target=parent/target.name
    if target==source_home or target.is_relative_to(source_home):raise ValueError('Recovery home must be outside the original installation')
    with socket.socket() as s:
        s.bind(('127.0.0.1',port))
    for kind in ('container','network','volume'):
        if run(['docker','--context','default',kind,'ls','-q','--filter','label=com.docker.compose.project='+name]).strip():
            raise ValueError('Recovery project already exists; choose a new name')
    volumes={kind:name+'_'+kind+'-data' for kind in ('redis','audit')}
    for volume in volumes.values():
        if subprocess.run(['docker','--context','default','volume','inspect',volume],capture_output=True).returncode==0:
            raise ValueError('Recovery volume name already exists')
    marker_id=secrets.token_hex(16);temp_container='uter-recovery-'+marker_id
    created_container=False
    with tempfile.TemporaryDirectory(prefix='.uter-recovery-',dir=parent) as temp:
        temp=Path(temp);stage=temp/'stage'
        helper_code=stage_recovery_helpers(temp)
        result=recovery_preflight.preflight(source_home,backup,backup_key,publisher_key,stage)
        if result['backend']!='compose':raise ValueError('This command requires a Compose backup')
        source=stage/'runtime-staged';state=uterctl.read(source/'state.json');current=state['current']
        cfg=uterctl.read(source/'install.json');site=uterctl.site_config(source)
        if name==site['name']:raise ValueError('Recovery project must have a different name')
        bundle=source/'releases'/current['version']
        if uterctl.verify(bundle,publisher_key)!=current:raise ValueError('Signed backup release changed')
        # Validate the actual snapshot with the signed Redis image before creating a target.
        for image in current['images'].values():run(['docker','--context','default','pull',image])
        run(['docker','--context','default','run','--rm','--network','none','--read-only',
             '--cap-drop','ALL','--security-opt','no-new-privileges','--user','0:0',
             '--mount','type=bind,source='+str(stage/'redis.rdb')+',target=/snapshot.rdb,readonly',
             '--entrypoint','redis-check-rdb',current['images']['redis'],'/snapshot.rdb'])
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
            cfg.update(name=name,port=port,images=current['images']);uterctl.write(target/'install.json',cfg)
            runtime=target/'runtime'
            shutil.copyfile(ROOT/'scripts/smoke_http.py',runtime/'smoke_http.py')
            wrapper='''import json\nfrom pathlib import Path\nfrom smoke_http import check\nhome=Path(__file__).resolve().parent.parent\ncfg=json.loads((home/"install.json").read_text())\ncreds=json.loads((home/"credentials.json").read_text())\ncheck("http://127.0.0.1:"+str(cfg["port"]),"admin",creds["admin"])\n'''
            (runtime/'recovery_smoke.py').write_text(wrapper,encoding='utf-8')
            site.update(name=name,namespace=name,port=port,smoke_command=[sys.executable,str(runtime/'recovery_smoke.py')])
            uterctl.write(runtime/'site.json',site);uterctl.site_config(target)
            state.pop('last_backup',None);uterctl.write(target/'state.json',state)
            for folder in ('policies','profiles','models'):os.chmod(runtime/folder,0o755)
            for path in (runtime/'policies/runtime.toml',runtime/'profiles/model_profiles.toml',runtime/'audit-hmac-key'):
                os.chown(path,10001,10001);os.chmod(path,0o400)
            for filename in ('redis.conf','redis-password'):
                os.chown(runtime/filename,999,10001);os.chmod(runtime/filename,0o440)
            env=os.environ.copy()
            for k in list(env):
                if k.startswith('COMPOSE_'):del env[k]
            env.update({k.upper()+'_IMAGE':v for k,v in current['images'].items()})
            env.update(RUNTIME_DIR=str(runtime),GUARDRAIL_PORT=str(port),GUARDRAIL_CPUS=str(cfg.get('guardrail_cpus',4)))
            cmd=['docker','--context','default','compose','--project-name',name,'--env-file',str(target/'empty.env'),'-f',str(target/'compose/compose.yaml')]
            for kind,volume in volumes.items():
                run(['docker','--context','default','volume','create','--label','com.docker.compose.project='+name,
                     '--label','com.docker.compose.volume='+kind+'-data','--label','uter.recovery.id='+marker_id,volume])
                info=json.loads(run(['docker','--context','default','volume','inspect',volume]))[0]
                if (info.get('Labels') or {}).get('uter.recovery.id')!=marker_id:
                    raise ValueError('Recovery volume ownership could not be verified')
            record('restoring-volumes')
            for kind,uid,gid,filename in [('redis',999,1000,'redis.rdb'),('audit',10001,10001,'audit.tar')]:
                transfer=temp/(kind+'-input');shutil.copyfile(stage/filename,transfer)
                os.chown(transfer,uid,gid);os.chmod(transfer,0o400)
                image=current['images']['guardrail'];mount='type=volume,source='+volumes[kind]+',target=/data'
                run(['docker','--context','default','run','--rm','--network','none','--read-only',
                     '--cap-drop','ALL','--cap-add','CHOWN','--security-opt','no-new-privileges','--user','0','--mount',mount,
                     '--entrypoint','python',image,'-c',f"import os;os.chown('/data',{uid},{gid})"])
                run(['docker','--context','default','run','--rm','--network','none','--read-only',
                     '--cap-drop','ALL','--security-opt','no-new-privileges','--user',f'{uid}:{gid}','--mount',mount,
                     '--mount','type=bind,source='+str(transfer)+',target=/snapshot,readonly',
                     '--mount','type=bind,source='+str(helper_code)+',target=/tool/scripts,readonly',
                     '--entrypoint','python',image,'/tool/scripts/recovery_volume.py',kind,
                     '--snapshot','/snapshot','--destination','/data'])
            run(['docker','--context','default','run','-d','--name',temp_container,'--label','uter.recovery.id='+marker_id,
                 '--network','none','--read-only','--tmpfs','/tmp:size=128m,mode=1777',
                 '--cap-drop','ALL','--security-opt','no-new-privileges','--user','999:1000',
                 '--mount','type=volume,source='+volumes['redis']+',target=/data',
                 '--entrypoint','redis-server',current['images']['redis'],'--dir','/data','--dbfilename','dump.rdb',
                 '--save','','--appendonly','no','--bind','127.0.0.1'])
            created_container=True
            def cli(args):return run(['docker','--context','default','exec',temp_container,'redis-cli','--raw',*args])
            import time
            for attempt in range(60):
                try:
                    if cli(['PING']).strip()==b'PONG':break
                except RuntimeError:pass
                if attempt==59:raise TimeoutError('Restored Redis failed to start')
                time.sleep(1)
            recovery_aof.enable_checked(cli)
            subprocess.run(['docker','--context','default','exec',temp_container,'redis-cli','shutdown'],capture_output=True)
            if run(['docker','--context','default','wait',temp_container]).strip()!=b'0':raise ValueError('Redis recovery shutdown failed')
            run(['docker','--context','default','rm',temp_container]);created_container=False
            record('starting')
            run(cmd+['up','-d','--no-build','--pull','never','--wait','--wait-timeout','300'],env=env)
            adopt_installation.verify_live(target,cfg,current)
            credentials=uterctl.read(target/'credentials.json')
            smoke('http://127.0.0.1:'+str(port),'admin',credentials['admin'])
            uterctl.write(target/'install-state.json',{'status':'ready','acceptance':'passed'})
            record('complete')
            return {'name':name,'home':str(target),'version':current['version'],'backup_id':result['backup_id']}
        finally:
            if created_container:
                subprocess.run(['docker','--context','default','rm','-f',temp_container],capture_output=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source-home','backup','backup-key','publisher-key','home'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--name',required=True);p.add_argument('--port',type=int,default=18000)
    a=p.parse_args();print(json.dumps(restore(a.source_home,a.backup,a.backup_key,a.publisher_key,a.home,a.name,a.port)))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(f'compose recovery: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
