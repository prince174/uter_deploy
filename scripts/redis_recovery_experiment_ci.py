"""Restore an authenticated synthetic RDB to disposable hosted Redis only.

This is not production recovery, live capture, cutover, or update authorization.
"""
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import tarfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import (audit_backup_evidence, backup_store, maintenance_evidence, redis_fence_journal,
                     redis_digest_resp, redis_recovery_experiment as recovery, recovery_evidence_experiment as combined)

IMAGE='ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc'
PHASE='INITIAL'


def docker(*args):
    return subprocess.run(['docker','--context','default',*args],check=True,stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL,timeout=120).stdout.decode().strip()


def cleanup(name,nonce,created):
    # Never delete a resource without first checking its unpredictable label.
    if not created:
        matches=docker('ps','-aq','--no-trunc','--filter','name=^/'+name+'$').splitlines()
        if len(matches)!=1 or not re.fullmatch(r'[0-9a-f]{64}',matches[0]): raise ValueError
        created=matches[0]
    if not re.fullmatch(r'[0-9a-f]{64}',created):raise ValueError
    try: label=docker('inspect','--format','{{index .Config.Labels "uter.recovery.fixture"}}',created)
    except subprocess.CalledProcessError:
        # A failed inspect cannot distinguish absence from daemon failure.
        raise ValueError from None
    if label!=nonce: raise ValueError
    docker('rm','-f','-v',created)
    if created and docker('ps','-aq','--no-trunc','--filter','id='+created): raise ValueError


def cleanup_network(name,nonce,created):
    if not created:
        matches=docker('network','ls','-q','--no-trunc','--filter','name='+name).splitlines()
        if len(matches)!=1 or not re.fullmatch(r'[0-9a-f]{64}',matches[0]):raise ValueError
        created=matches[0]
    if not re.fullmatch(r'[0-9a-f]{64}',created):raise ValueError
    identity=docker('network','inspect','--format','{{.Name}} {{index .Labels "uter.recovery.fixture"}}',created)
    if identity!=name+' '+nonce:raise ValueError
    docker('network','rm',created)
    if docker('network','ls','-q','--no-trunc','--filter','id='+created):raise ValueError


def cleanup_all(clients,names,nonce,attempted,ids,network_attempted,network_name,network_id):
    failed=False
    for sock,client in clients:
        for close in (client.close,sock.close):
            try:close()
            except Exception:failed=True
    for index in (1,0):
        if attempted[index]:
            try:cleanup(names[index],nonce,ids[index])
            except Exception:failed=True
    if network_attempted:
        try:cleanup_network(network_name,nonce,network_id)
        except Exception:failed=True
    return not failed


def start(name,nonce,config,network,data=None):
    cmd=['run','-d','--name',name,'--label','uter.recovery.fixture='+nonce,
         '--network',network,
         '--publish','127.0.0.1::6379','--mount',f'type=bind,src={config},dst=/etc/fixture.conf,readonly']
    if data is not None:cmd+=['--mount',f'type=bind,src={data},dst=/data,readonly']
    result=docker(*cmd,'--entrypoint','redis-server',IMAGE,'/etc/fixture.conf')
    if not re.fullmatch(r'[0-9a-f]{64}',result): raise ValueError
    return result


def connect(name,password):
    port_text=docker('port',name,'6379/tcp')
    if not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}',port_text): raise ValueError
    port=int(port_text.rsplit(':',1)[1]);deadline=time.monotonic()+30
    while True:
        try:
            sock=socket.create_connection(('127.0.0.1',port),timeout=3)
            client=redis_digest_resp.Client(sock,time.monotonic()+120)
            try:
                if client.command('AUTH',password)!=b'OK' or client.command('PING')!=b'PONG': raise ValueError
            except Exception:
                client.close();sock.close();raise
            return sock,client,port
        except OSError:
            if time.monotonic()>=deadline: raise
            time.sleep(.25)


def fingerprint(port,password,key):
    with socket.create_connection(('127.0.0.1',port),timeout=3) as sock:
        return redis_digest_resp.fingerprint(sock,password,key)


def tar_fixture(name,data):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w') as archive:
        entry=tarfile.TarInfo(name);entry.size=len(data);archive.addfile(entry,io.BytesIO(data))
    return buffer.getvalue()


def main():
    global PHASE
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'
            or os.environ.get('RUNNER_OS')!='Linux' or os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT')):
        raise ValueError
    if docker('context','inspect','default','--format','{{.Endpoints.docker.Host}}')!='unix:///var/run/docker.sock':
        raise ValueError
    nonce=secrets.token_hex(16);names=['uter-rdb-source-'+nonce,'uter-rdb-target-'+nonce]
    ids=[None,None];attempted=[False,False];clients=[]
    network_name='uter-rdb-net-'+nonce;network_id=None;network_attempted=False
    with tempfile.TemporaryDirectory(prefix='uter-rdb-fixture-') as path:
        root=Path(path);root.chmod(0o755)
        password=secrets.token_hex(32).encode();key=secrets.token_bytes(32);digest_key=secrets.token_bytes(32)
        config=root/'redis.conf'
        config.write_bytes(b'bind 0.0.0.0\nprotected-mode yes\nrequirepass '+password+
                           b'\nsave ""\nappendonly no\ndir /data\ndbfilename dump.rdb\n')
        config.chmod(0o644) # random fixture-only credential on an ephemeral runner
        try:
            PHASE='NETWORK_CREATE';network_attempted=True
            network_id=docker('network','create','--label','uter.recovery.fixture='+nonce,network_name)
            if not re.fullmatch(r'[0-9a-f]{64}',network_id):raise ValueError
            PHASE='SOURCE_START';attempted[0]=True;ids[0]=start(names[0],nonce,config,network_id)
            sock,client,source_port=connect(names[0],password);clients.append((sock,client))
            PHASE='SYNTHETIC_DATA'
            expiry=int(time.time()*1000)+15*60*1000
            commands=[('SET',b'string',b'\x00fixture\xff'),('HSET','hash','field','value'),
                      ('LPUSH','list','one','two'),('SADD','set','alpha','beta'),
                      ('ZADD','sorted','1','a','2','b'),('PEXPIREAT','string',str(expiry)),
                      ('SELECT','1'),('SET','second-db','value'),('SELECT','0')]
            for command in commands:client.command(*command)
            if client.command('SAVE')!=b'OK':raise ValueError
            before=fingerprint(source_port,password,digest_key)
            if before['keys']!=6 or before['safe_to_resume'] is not False:raise ValueError
            PHASE='AUTHENTICATED_BACKUP'
            snapshot=root/'snapshot.rdb';docker('cp',names[0]+':/data/dump.rdb',str(snapshot))
            if snapshot.stat().st_size>recovery.MAX_RDB_BYTES:raise ValueError
            home=root/'home';home.mkdir(mode=0o700);site={'backend':'compose','name':'synthetic','namespace':'synthetic','context':'default'}
            resource=secrets.token_hex(32);operation=secrets.token_hex(16);plan=secrets.token_hex(32);boot=secrets.token_hex(16)
            redis_fence_journal.create(home,backend='compose',site=site['name'],resource=resource,
                                       operation=operation,plan_sha256=plan)
            recorder=maintenance_evidence.Recorder(home,key,operation=operation,backend='compose',plan_sha256=plan,
                                                    lock_guard=lambda:True) # fixture only, not a real lock
            receipt={'protocol':1,'boot_id':boot,'state':'quiesced','safe_to_stop':True,'active_requests':0,'error':None,
                     'evidence':{'redis_closed':True,'audit':{'last_seq':1,'last_hash':'f'*64,'fsynced':True,'verified':True}}}
            recorder.intent('guardrail','fixture-instance',boot);recorder.receipt('guardrail','fixture-instance',boot,receipt)
            bundle=root/'fixture-bundle';bundle.mkdir();(bundle/'checksums.json').write_bytes(b'fixture only')
            product={'version':'1.0.0','images':{'guardrail':'fixture.invalid/guardrail@sha256:'+'a'*64}}
            event={'audit_seq':1,'audit_prev_hash':None,'audit_hash':'f'*64,'audit_hmac':'e'*64}
            backup=root/'backup';writer=backup_store.BackupWriter(backup,key,home,site,'1.0.0')
            writer.put('runtime',io.BytesIO(tar_fixture('runtime/audit-hmac-key',b'synthetic audit key')))
            with snapshot.open('rb') as source:writer.put('redis',source)
            writer.put('audit',io.BytesIO(tar_fixture('audit.jsonl',json.dumps(event).encode()+b'\n')));writer.finish()
            # Tamper rejection is checked before the target exists.
            path=backup/'redis.enc';raw=path.read_bytes();path.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
            try:recovery.prepare(backup,key=key,home=home,site=site,version='1.0.0')
            except recovery.RecoveryExperimentError:pass
            else:raise ValueError
            path.write_bytes(raw)
            def fake_audit(files,audit_key,image):
                if audit_key!='synthetic audit key' or image!=product['images']['guardrail'] or len(files)!=1:raise ValueError
                return {'last_seq':1,'last_hash':'f'*64,'files_verified':1,'verified_entries':1,
                        'segments_verified':1,'hmac_enabled':True,'ignored_trailing_entries':0,
                        'ignored_orphan_entries':0,'ignored_malformed_entries':0,'legacy_entries_skipped':0}
            def real_redis_oracle(payload):
                global PHASE
                data=root/'target-data';data.mkdir(mode=0o755);rdb=data/'dump.rdb';rdb.write_bytes(payload);rdb.chmod(0o644)
                PHASE='TARGET_RESTORE';attempted[1]=True;ids[1]=start(names[1],nonce,config,network_id,data)
                if ids[1]==ids[0]:raise ValueError
                target_sock,target_client,target_port=connect(names[1],password);clients.append((target_sock,target_client))
                after=fingerprint(target_port,password,digest_key);again=fingerprint(source_port,password,digest_key)
                if after['keys']!=6 or target_client.command('PEXPIRETIME','string')!=expiry:raise ValueError
                import hashlib
                return {'rdb_sha256':hashlib.sha256(payload).hexdigest(),'before':before,'after':after,'source_again':again}
            params={'home':home,'backup':backup,'key':key,'site':site,'resource':resource,'recorder':recorder}
            PHASE='FIXTURE_AUDIT_AND_REDIS'
            # Both publisher trust and the audit oracle are deliberately mocked.
            with patch.object(combined.maintenance_protocol,'verify_capability',return_value=product):
                audit_record=audit_backup_evidence.verify(**params,bundle=bundle,publisher='fixture',
                    instance='fixture-instance',boot=boot,strict_auditor=fake_audit)
                redis_record=combined.capture_redis(**params,version='1.0.0',restore_oracle=real_redis_oracle)
                PHASE='COMBINED_RECORDS'
                value=combined.combine(**params,bundle=bundle,publisher='fixture',instance='fixture-instance',boot=boot,
                                       audit=audit_record,redis=redis_record)
            if value['safe_to_update'] is not False or value['safe_to_resume'] is not False:raise ValueError
        finally:
            if not cleanup_all(clients,names,nonce,attempted,ids,network_attempted,network_name,network_id):
                PHASE='CLEANUP_UNCERTAIN'
                raise ValueError
    print('REDIS_SYNTHETIC_AUTHENTICATED_RDB_RESTORE_PASS; audit oracle and publisher are fixtures; safe_to_update=false')


if __name__=='__main__':
    try:main()
    except Exception:
        print('REDIS_RDB_EXPERIMENT_CI_'+PHASE+'_FAILED',file=sys.stderr)
        raise SystemExit(1)
