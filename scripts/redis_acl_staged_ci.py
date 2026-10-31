"""Staged ACL experiment on disposable hosted Redis, without Uter.

Signed bundle, lock and drain evidence are synthetic fixtures. Never run on a
shared daemon; this cannot authorize production maintenance or updates.
"""
import os
import json
from pathlib import Path
import re
import secrets
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts import (install_recovery, maintenance_evidence, redis_acl_experiment as base,
                     redis_acl_experiment_ci as clients, redis_acl_staged as staged, redis_fence_journal)
from scripts import bundle
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

IMAGE='ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc'
LABEL='uter.staged-acl.fixture'
PHASE='INITIAL'


def docker(*args,env):
    output=install_recovery.run_readonly(['/usr/bin/docker','--context','default',*args],timeout=120,env=env)
    if len(output)>65536:raise ValueError
    return output.strip()


def auth(client,user,password):
    """Classify only +OK or Redis WRONGPASS; never expose the error text."""
    values=[b'AUTH',user.encode('ascii'),password.encode('ascii')]
    client.sock.sendall(b'*3\r\n'+b''.join(b'$'+str(len(value)).encode()+b'\r\n'+value+b'\r\n' for value in values))
    line=client.file.readline(4097)
    if line==b'+OK\r\n':return True
    if len(line)<=4096 and line.startswith(b'-WRONGPASS ') and line.endswith(b'\r\n'):return False
    raise ValueError('AUTH_RESPONSE_UNVERIFIED')


def exercise(private,env,profile_bundle,publisher,*,restart):
    global PHASE
    nonce=secrets.token_hex(16);name='uter-staged-acl-'+nonce;ident=None;attempted=False
    connected=[];restart_observation=None;writer_password=secrets.token_hex(32);admin_password=secrets.token_hex(32)
    config=private/('redis-'+nonce+'.conf')
    rules=' '.join(sorted(base._UTER_TEST))
    config.write_text('bind 0.0.0.0\nprotected-mode yes\nappendonly yes\ndir /data\n'
        'user default off -@all\nuser uter-writer on >'+writer_password+' ~* &* -@all '+rules+'\n'
        'user uter-maint-test on >'+admin_password+' ~* &* +@all\n')
    config.chmod(0o600)
    home=private/('home-'+nonce);home.mkdir(mode=0o700)
    key=secrets.token_bytes(32);operation=secrets.token_hex(16);plan=secrets.token_hex(32)
    redis_fence_journal.create(home,backend='compose',site='uter-ci',resource='a'*64,plan_sha256=plan,operation=operation)
    recorder=maintenance_evidence.Recorder(home,key,operation=operation,backend='compose',plan_sha256=plan,lock_guard=lambda:True)
    def record(kind,stage):
        name='redis-staged-'+kind+'-'+stage+'.json'
        value={'schema':1,'kind':kind,'stage':stage,'operation':operation,'plan_sha256':plan}
        recorder._write(name,value)
        return recorder._read(name)==value
    try:
        if docker('ps','-aq','--no-trunc','--filter','name=^/'+name+'$',env=env):raise ValueError
        PHASE='REDIS_START';attempted=True
        ident=docker('run','-d','--name',name,'--label',LABEL+'='+nonce,'--restart','no','--user','0:0',
            '--publish','127.0.0.1::6379','--mount','type=bind,source='+str(config)+',target=/tmp/uter-redis.conf,readonly',
            '--entrypoint','redis-server',IMAGE,'/tmp/uter-redis.conf',env=env)
        if not re.fullmatch(r'[0-9a-f]{64}',ident):ident=None;raise ValueError
        PHASE='REDIS_PORT';mapping=docker('port',ident,'6379/tcp',env=env)
        if not re.fullmatch(r'127\.0\.0\.1:[1-9][0-9]{0,4}',mapping):raise ValueError
        port=int(mapping.rsplit(':',1)[1])
        if not 1<=port<=65535:raise ValueError
        for attempt in range(60):
            try:admin=clients.Client(port);connected.append(admin);break
            except OSError:
                if attempt==59:raise
                time.sleep(.25)
        PHASE='ADMIN_AUTH'
        if auth(admin,'uter-maint-test',admin_password) is not True:raise ValueError
        writer=clients.Client(port);connected.append(writer)
        PHASE='WRITER_AUTH'
        if auth(writer,'uter-writer',writer_password) is not True:raise ValueError
        writer.call('SET','ci-initial','ok')
        run_id=next(x.split(':',1)[1] for x in admin.call('INFO','SERVER').splitlines() if x.startswith('run_id:'))
        client_id=str(admin.call('CLIENT','ID'))
        session=staged.StagedAdmission(admin.call,bundle=profile_bundle,publisher=publisher,
            admin_user='uter-maint-test',run_id=run_id,client_id=client_id,
            record_intent=lambda stage:record('intent',stage),record_receipt=lambda stage:record('receipt',stage),
            identity_guard=lambda:True)  # Synthetic fixture; no production Docker identity proof.
        PHASE='DISABLE';first=session.disable_new_auth()
        if first['prior_writer_connections_retained']!=1 or first['safe_to_update']:raise ValueError
        # Redis ACL off must leave an already authenticated connection usable.
        PHASE='OLD_WRITER';
        if writer.call('SET','ci-after-disable','ok')!='OK':raise ValueError
        newcomer=clients.Client(port);connected.append(newcomer)
        PHASE='NEW_AUTH'
        if auth(newcomer,'uter-writer',writer_password) is not False:raise ValueError
        newcomer.close();connected.remove(newcomer)
        if restart:
            PHASE='RESTART'
            docker('restart',ident,env=env)
            try:session.finish_after_drain(lambda:True)
            except staged.StagedError:pass
            else:raise ValueError
            if session.phase!='uncertain':raise ValueError
            PHASE='RESTART_REAUTH'
            for attempt in range(60):
                try:
                    new_admin=clients.Client(port);connected.append(new_admin)
                    if auth(new_admin,'uter-maint-test',admin_password) is not True:raise ValueError
                    break
                except (OSError,ValueError):
                    if attempt==59:raise
                    time.sleep(.25)
            PHASE='RESTART_IDENTITY';new_run=next(x.split(':',1)[1] for x in new_admin.call('INFO','SERVER').splitlines() if x.startswith('run_id:'))
            if new_run==run_id:raise ValueError
            info=new_admin.call('ACL','GETUSER','uter-writer');flags=info.get('flags')
            if not isinstance(flags,list) or ('on' in flags)==('off' in flags):raise ValueError
            attempt_client=clients.Client(port);connected.append(attempt_client)
            allowed=auth(attempt_client,'uter-writer',writer_password)
            if allowed!=('on' in flags):raise ValueError
            restart_observation='RESTART_WRITER_AUTH_ALLOWED' if allowed else 'RESTART_WRITER_AUTH_DENIED'
            attempt_client.close();connected.remove(attempt_client)
            calls=[];server_reads=[];restart_intents=[]
            def restarted_call(*args):
                calls.append(args);result=new_admin.call(*args)
                if args==('INFO','SERVER'):server_reads.append(result)
                return result
            def restart_intent(stage):
                restart_intents.append(stage);return record('restart-intent',stage)
            PHASE='RESTART_STALE';stale=staged.StagedAdmission(restarted_call,bundle=profile_bundle,publisher=publisher,
                admin_user='uter-maint-test',run_id=run_id,client_id=str(new_admin.call('CLIENT','ID')),
                record_intent=restart_intent,
                record_receipt=lambda stage:record('restart-receipt',stage),identity_guard=lambda:True)
            stale.phase='auth-disabled'  # Fixture only; no production replay/recovery claim.
            try:stale.finish_after_drain(lambda:True)
            except staged.StagedError:pass
            else:raise ValueError
            if (len(server_reads)!=1 or 'run_id:'+new_run not in server_reads[0].splitlines()
                    or restart_intents or any(command[:2]==('CLIENT','KILL') for command in calls)):raise ValueError
        else:
            PHASE='FINISH'
            result=session.finish_after_drain(lambda:True)  # Synthetic drain, not Uter.
            if result['writer_clients_killed']!=1 or result['safe_to_update']:raise ValueError
            try:writer.call('PING')
            except (OSError,ValueError):pass
            else:raise ValueError
    finally:
        PHASE_FAILURE=PHASE;PHASE='CLEANUP';cleanup_failed=False
        for client in connected:
            for item in (client.file,client.sock):
                try:item.close()
                except Exception:cleanup_failed=True
        if attempted:
            if ident is None:
                matches=docker('ps','-aq','--no-trunc','--filter','name=^/'+name+'$',env=env).splitlines()
                if len(matches)!=1 or not re.fullmatch(r'[0-9a-f]{64}',matches[0]):raise ValueError('CLEANUP_UNCERTAIN')
                ident=matches[0]
            if (docker('inspect','--format','{{index .Config.Labels "'+LABEL+'"}}',ident,env=env)!=nonce
                    or docker('inspect','--format','{{.Name}}',ident,env=env)!='/'+name):raise ValueError('CLEANUP_UNCERTAIN')
            docker('rm','-f','-v',ident,env=env)
            if docker('ps','-aq','--no-trunc','--filter','id='+ident,env=env):raise ValueError('CLEANUP_UNCERTAIN')
        if cleanup_failed:raise ValueError('CLEANUP_UNCERTAIN')
        PHASE=PHASE_FAILURE
    return restart_observation


def main():
    global PHASE
    if (sys.platform!='linux' or os.environ.get('GITHUB_ACTIONS')!='true'
            or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('RUNNER_OS')!='Linux'
            or os.environ.get('UTER_CI_STAGED_ACL')!='true' or os.environ.get('DOCKER_HOST')):
        raise ValueError('STAGED_ACL_FIXTURE_ENVIRONMENT_UNVERIFIED')
    with tempfile.TemporaryDirectory(prefix='uter-staged-acl-') as tmp:
        private=Path(tmp);private.chmod(0o700)
        env={'PATH':'/usr/bin:/bin','HOME':str(private),'DOCKER_CONFIG':str(private),'LANG':'C'}
        if docker('context','inspect','default','--format','{{.Endpoints.docker.Host}}',env=env)!='unix:///var/run/docker.sock':raise ValueError
        signing=Ed25519PrivateKey.generate();private_key=private/'fixture-private.pem';publisher=private/'fixture-public.pem'
        private_key.write_bytes(signing.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        publisher.write_bytes(signing.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        manifest={'schema':1,'config_schema':1,'tooling_schema':1,'status':'released','version':'1.0.0',
            'source_commit':'a'*40,'data_epoch':1,'upgrade_from':[],
            'images':{name:'example/'+name+'@sha256:'+'b'*64 for name in ('guardrail','agent','redis')},
            'maintenance_protocol':{'version':1,'services':['agent','guardrail']}}
        manifest_path=private/'fixture-manifest.json';manifest_path.write_text(json.dumps(manifest))
        PHASE='PROFILE';profile_bundle=private/'fixture-bundle';bundle.build(manifest_path,profile_bundle,private_key)
        if staged.verify_profile(profile_bundle,publisher)!=manifest:raise ValueError
        PHASE='PULL';docker('pull',IMAGE,env=env)
        exercise(private,env,profile_bundle,publisher,restart=False)
        restart_observation=exercise(private,env,profile_bundle,publisher,restart=True)
        if restart_observation not in ('RESTART_WRITER_AUTH_ALLOWED','RESTART_WRITER_AUTH_DENIED'):raise ValueError
    print(restart_observation)
    print('STAGED_ACL_REDIS_CI_PASS: synthetic drain; no Uter, fence or update verified')


if __name__=='__main__':
    try:main()
    except Exception:
        allowed={'INITIAL','PROFILE','PULL','REDIS_START','REDIS_PORT','ADMIN_AUTH','WRITER_AUTH','DISABLE',
                 'OLD_WRITER','NEW_AUTH','FINISH','RESTART','RESTART_REAUTH','RESTART_IDENTITY','RESTART_STALE','CLEANUP'}
        print('STAGED_ACL_REDIS_CI_'+(PHASE if PHASE in allowed else 'UNKNOWN')+'_UNVERIFIED',file=sys.stderr);sys.exit(1)
