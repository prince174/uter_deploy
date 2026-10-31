"""Staged ACL experiment on disposable hosted Redis, without Uter.

Signed bundle, lock and drain evidence are synthetic fixtures. Never run on a
shared daemon; this cannot authorize production maintenance or updates.
"""
import os
import json
import hashlib
from pathlib import Path
import re
import secrets
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts import (install_recovery, maintenance_evidence, redis_acl_durable, redis_acl_experiment as base,
                     redis_acl_experiment_ci as clients, redis_acl_staged as staged, redis_fence_journal)
from scripts import bundle
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

IMAGE='ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc'
LABEL='uter.staged-acl.fixture'
PHASE='INITIAL'
CASE='NONE'
DETAIL='NONE'
OBSERVATION='NONE'
IDENTITY='NONE'


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


def normalize_mounts(value):
    """Normalize only unordered mounts; never discard or merge fields."""
    if not isinstance(value,dict) or not isinstance(value.get('mounts'),list):raise ValueError
    mounts=value['mounts'];destinations=[]
    for item in mounts:
        if not isinstance(item,dict) or not isinstance(item.get('Destination'),str):raise ValueError
        destinations.append(item['Destination'])
    if len(destinations)!=len(set(destinations)):raise ValueError
    return dict(value,mounts=sorted(mounts,key=lambda item:item['Destination']))


def exercise(private,env,profile_bundle,publisher,*,restart,durable=False):
    global PHASE,CASE,DETAIL,OBSERVATION,IDENTITY
    CASE='DURABLE' if durable else 'LEGACY'
    DETAIL='NONE';OBSERVATION='NONE';IDENTITY='NONE'
    nonce=secrets.token_hex(16);name='uter-staged-acl-'+nonce;ident=None;attempted=False
    connected=[];restart_observation=None;writer_password=secrets.token_hex(32);admin_password=secrets.token_hex(32)
    config=private/('redis-'+nonce+'.conf');acl_dir=None
    rules=' '.join(sorted(base._UTER_TEST))
    writer_hash=hashlib.sha256(writer_password.encode('ascii')).hexdigest()
    admin_hash=hashlib.sha256(admin_password.encode('ascii')).hexdigest()
    if durable:
        acl_dir=private/('acl-'+nonce);acl_dir.mkdir();os.chown(acl_dir,0,1000);acl_dir.chmod(0o710)
        acl_file=acl_dir/redis_acl_durable.NAME
        acl_file.write_bytes(redis_acl_durable.render(admin_user='uter-maint-test',writer_hash=writer_hash,
                                                       admin_hash=admin_hash,writer_on=True))
        os.chown(acl_file,999,1000);acl_file.chmod(0o400)
        config.write_text('bind 0.0.0.0\nprotected-mode yes\nappendonly yes\ndir /data\naclfile /acl/users.acl\n')
        config.chmod(0o644)
    else:
        config.write_text('bind 0.0.0.0\nprotected-mode yes\nappendonly yes\ndir /data\n'
            'user default off -@all\nuser uter-writer on >'+writer_password+' ~* &* -@all '+rules+'\n'
            'user uter-maint-test on >'+admin_password+' ~* &* +@all\n')
        config.chmod(0o600)
    home=private/('home-'+nonce);home.mkdir(mode=0o700)
    key=secrets.token_bytes(32);operation=secrets.token_hex(16);plan=secrets.token_hex(32)
    redis_fence_journal.create(home,backend='compose',site='uter-ci',resource='a'*64,plan_sha256=plan,operation=operation)
    recorder=maintenance_evidence.Recorder(home,key,operation=operation,backend='compose',plan_sha256=plan,lock_guard=lambda:True)
    def record(kind,stage,digest=None):
        name='redis-staged-'+kind+'-'+stage+'.json'
        value={'schema':1,'kind':kind,'stage':stage,'operation':operation,'plan_sha256':plan}
        if digest is not None:value['version_sha256']=digest
        recorder._write(name,value)
        return recorder._read(name)==value
    try:
        if docker('ps','-aq','--no-trunc','--filter','name=^/'+name+'$',env=env):raise ValueError
        PHASE='REDIS_START';attempted=True
        command=['run','-d','--name',name,'--label',LABEL+'='+nonce,'--restart','no',
                 '--user','999:1000' if durable else '0:0','--publish','127.0.0.1::6379',
                 '--mount','type=bind,source='+str(config)+',target=/tmp/uter-redis.conf,readonly']
        if durable:
            command+=['--mount','type=bind,source='+str(acl_dir)+',target=/acl,readonly',
                      '--tmpfs','/data:uid=999,gid=1000,mode=0700']
        ident=docker(*command,'--entrypoint','redis-server',IMAGE,'/tmp/uter-redis.conf',env=env)
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
        def redis_snapshot():
            fmt=('{"id":{{json .Id}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},'
                 '"started":{{json .State.StartedAt}},"restarts":{{json .RestartCount}},'
                 '"restart":{{json .HostConfig.RestartPolicy.Name}},"mounts":{{json .Mounts}}}')
            return normalize_mounts(json.loads(docker('inspect','--format',fmt,ident,env=env)))
        pinned=redis_snapshot()
        if (pinned.get('id')!=ident or pinned.get('running') is not True or pinned.get('restart')!='no'
                or type(pinned.get('pid')) is not int or pinned['pid']<=1):raise ValueError
        if durable:
            mount=[x for x in pinned.get('mounts',[]) if x.get('Destination')=='/acl']
            if (len(mount)!=1 or mount[0].get('Type')!='bind' or mount[0].get('RW') is not False
                    or mount[0].get('Source')!=str(acl_dir)
                    or admin.call('CONFIG','GET','aclfile')!=['aclfile','/acl/users.acl']):raise ValueError
        def identity_guard():
            global IDENTITY
            try:observed=redis_snapshot()
            except Exception:
                IDENTITY='QUERY_FAILED';return False
            for field in ('id','running','pid','started','restarts','restart','mounts'):
                if observed.get(field)!=pinned.get(field):
                    IDENTITY=field.upper();return False
            if observed!=pinned:
                IDENTITY='OTHER';return False
            return True
        durable_prepare=None
        if durable:
            durable_prepare=redis_acl_durable.DurablePrepare(bundle=profile_bundle,publisher=publisher,directory=acl_dir,
                admin_user='uter-maint-test',writer_hash=writer_hash,admin_hash=admin_hash,
                lock_guard=identity_guard,record_intent=lambda stage:record('intent',stage),
                record_receipt=lambda stage,digest:record('receipt',stage,digest))
        session=staged.StagedAdmission(admin.call,bundle=profile_bundle,publisher=publisher,
            admin_user='uter-maint-test',run_id=run_id,client_id=client_id,
            record_intent=lambda stage:record('intent',stage),record_receipt=lambda stage:record('receipt',stage),
            identity_guard=identity_guard,durable_prepare=durable_prepare)
        PHASE='DISABLE'
        try:first=session.disable_new_auth()
        except staged.StagedError:
            DETAIL=session.failure_phase;OBSERVATION=session.observe_phase
            raise
        if first['prior_writer_connections_retained']!=1 or first['safe_to_update']:raise ValueError
        if durable:
            if first['host_acl_file_verified'] is not True or durable_prepare.verify_off() is not True:raise ValueError
            durable_record=recorder._read('redis-staged-receipt-writer-off-file-durable.json')
            if durable_record.get('version_sha256')!=durable_prepare.prepared[0]:raise ValueError
        # Redis ACL off must leave an already authenticated connection usable.
        PHASE='OLD_WRITER';
        if writer.call('SET','ci-after-disable','ok')!='OK':raise ValueError
        newcomer=clients.Client(port);connected.append(newcomer)
        PHASE='NEW_AUTH'
        if auth(newcomer,'uter-writer',writer_password) is not False:raise ValueError
        newcomer.close();connected.remove(newcomer)
        if restart:
            PHASE='RESTART'
            if durable:
                docker('kill','--signal','KILL',ident,env=env)
                docker('start',ident,env=env)
            else:docker('restart',ident,env=env)
            try:session.finish_after_drain(lambda:True)
            except staged.StagedError:pass
            else:raise ValueError
            if session.phase!='uncertain':raise ValueError
            PHASE='RESTART_REAUTH'
            # An ephemeral host port may change after Docker restarts a container.
            mapping=docker('port',ident,'6379/tcp',env=env)
            if not re.fullmatch(r'127\.0\.0\.1:[1-9][0-9]{0,4}',mapping):raise ValueError
            port=int(mapping.rsplit(':',1)[1])
            if not 1<=port<=65535:raise ValueError
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
            if durable:
                directory,_=redis_acl_durable._directory(acl_dir)
                try:raw_acl,_=redis_acl_durable._read(directory)
                finally:os.close(directory)
                if (allowed or raw_acl!=durable_prepare.after
                        or hashlib.sha256(raw_acl).hexdigest()!=durable_record.get('version_sha256')):raise ValueError
            prefix='DURABLE_' if durable else ''
            restart_observation=prefix+('RESTART_WRITER_AUTH_ALLOWED' if allowed else 'RESTART_WRITER_AUTH_DENIED')
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
            try:result=session.finish_after_drain(lambda:True)  # Synthetic drain, not Uter.
            except staged.StagedError:
                DETAIL=session.failure_phase;OBSERVATION=session.observe_phase
                raise
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


def make_fixture_profile(private):
    """Create CI-only signed declaration, not a signed product image."""
    signing=Ed25519PrivateKey.generate();private_key=private/'fixture-private.pem';publisher=private/'fixture-public.pem'
    private_key.write_bytes(signing.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    publisher.write_bytes(signing.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    manifest={'schema':1,'config_schema':1,'tooling_schema':1,'status':'released','version':'1.0.0',
        'source_commit':'a'*40,'data_epoch':1,'upgrade_from':[],
        'images':{name:'example/'+name+'@sha256:'+'b'*64 for name in ('guardrail','agent','redis')},
        'maintenance_protocol':{'version':1,'services':['agent','guardrail']}}
    manifest_path=private/'fixture-manifest.json';manifest_path.write_text(json.dumps(manifest))
    profile_bundle=private/'fixture-bundle';bundle.build(manifest_path,profile_bundle,private_key)
    if staged.verify_profile(profile_bundle,publisher)!=manifest:raise ValueError
    return profile_bundle,publisher


def main():
    global PHASE
    if (sys.platform!='linux' or os.environ.get('GITHUB_ACTIONS')!='true'
            or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('RUNNER_OS')!='Linux'
            or os.environ.get('UTER_CI_STAGED_ACL')!='true' or os.environ.get('DOCKER_HOST') or os.geteuid()!=0):
        raise ValueError('STAGED_ACL_FIXTURE_ENVIRONMENT_UNVERIFIED')
    with tempfile.TemporaryDirectory(prefix='uter-staged-acl-') as tmp:
        private=Path(tmp);private.chmod(0o700)
        env={'PATH':'/usr/bin:/bin','HOME':str(private),'DOCKER_CONFIG':str(private),'LANG':'C'}
        if docker('context','inspect','default','--format','{{.Endpoints.docker.Host}}',env=env)!='unix:///var/run/docker.sock':raise ValueError
        PHASE='PROFILE';profile_bundle,publisher=make_fixture_profile(private)
        PHASE='PULL';docker('pull',IMAGE,env=env)
        exercise(private,env,profile_bundle,publisher,restart=False)
        restart_observation=exercise(private,env,profile_bundle,publisher,restart=True)
        if restart_observation not in ('RESTART_WRITER_AUTH_ALLOWED','RESTART_WRITER_AUTH_DENIED'):raise ValueError
        exercise(private,env,profile_bundle,publisher,restart=False,durable=True)
        durable_restart=exercise(private,env,profile_bundle,publisher,restart=True,durable=True)
        if durable_restart!='DURABLE_RESTART_WRITER_AUTH_DENIED':raise ValueError
    print(restart_observation)
    print(durable_restart)
    print('STAGED_ACL_REDIS_CI_PASS: synthetic drain; no Uter, fence or update verified')


if __name__=='__main__':
    try:main()
    except Exception:
        allowed={'INITIAL','PROFILE','PULL','REDIS_START','REDIS_PORT','ADMIN_AUTH','WRITER_AUTH','DISABLE',
                 'OLD_WRITER','NEW_AUTH','FINISH','RESTART','RESTART_REAUTH','RESTART_IDENTITY','RESTART_STALE','CLEANUP'}
        details={'NONE','INITIAL','OBSERVE_ON','CLIENTS_ON','REOBSERVE_ON','DURABLE_PREPARE',
                 'DURABLE_REOBSERVE_ON','ACL_OFF','OBSERVE_OFF','CLIENTS_OFF','FINAL_OBSERVE','COMPLETE',
                 'FINISH_GUARD','FINISH_OBSERVE','FINISH_CLIENTS','FINISH_REOBSERVE','FINISH_KILL',
                 'FINISH_POST_OBSERVE','FINISH_POST_CLIENTS','FINISH_RECEIPT','FINISH_FINAL_OBSERVE'}
        observations={'NONE','INITIAL','IDENTITY_BEFORE','PROFILE_BEFORE','DURABLE_BEFORE','INFO_SERVER','INFO_REPLICATION','INFO_PERSISTENCE',
                      'REDIS_IDENTITY','ACL_USERS','ACL_DEFAULT','ACL_WRITER','ACL_ADMIN','IDENTITY_AFTER',
                      'PROFILE_AFTER','DURABLE_AFTER','COMPLETE'}
        identities={'NONE','QUERY_FAILED','ID','RUNNING','PID','STARTED','RESTARTS','RESTART','MOUNTS','OTHER'}
        print('STAGED_ACL_REDIS_CI_'+(CASE if CASE in {'NONE','LEGACY','DURABLE'} else 'UNKNOWN')+'_'
              +(PHASE if PHASE in allowed else 'UNKNOWN')+'_'+(DETAIL if DETAIL in details else 'UNKNOWN')+'_'
              +(OBSERVATION if OBSERVATION in observations else 'UNKNOWN')+'_'
              +(IDENTITY if IDENTITY in identities else 'UNKNOWN')+'_UNVERIFIED',file=sys.stderr);sys.exit(1)
