"""Opt-in signed 0.1.6 Compose netns firewall exercise on an isolated CI runner.

This driver is NOT an update or recovery path. Its manual cleanup is permitted
only for the exact synthetic installation in disposable GitHub-hosted CI. The
production adapter intentionally refuses to recover and is not wired to uterctl.
"""
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time

import uterctl
from scripts import (backup_snapshot, backup_store, compose_nsfirewall_adapter as fence,
                     compose_nsfirewall_protocol as protocol, compose_fence_recovery_plan as plans,
                     compose_redis_diagnostic as diagnostic, install, install_recovery,
                     redis_fence_journal as journal)

ROOT=Path(__file__).resolve().parents[1]
KEY='uter:ci-fence-check'
VALUE='ci-synthetic-fence-write'
PHASE='GUARD'


class SignedComposeFenceCheckFailure(ValueError): pass


CLIENT = r'''
import socket,sys
secret=sys.stdin.readline().strip()
s=socket.create_connection((sys.argv[1],6379),timeout=8);s.settimeout(2)
def req(*xs):
 b=b'*%d\r\n'%len(xs)+b''.join(b'$%d\r\n'%len(x.encode())+x.encode()+b'\r\n' for x in xs)
 s.sendall(b);return s.recv(1024)
if not req('AUTH',secret).startswith(b'+OK'):raise SystemExit(2)
if not req('SET','uter:ci-fence-check','ci-synthetic-fence-write').startswith(b'+OK'):raise SystemExit(3)
print('READY',flush=True);sys.stdin.readline()
try:
 req('SET','uter:ci-fence-check','blocked-write');raise SystemExit(4)
except TimeoutError:print('BLOCKED',flush=True)
sys.stdin.readline()
try:
 if req('SET','uter:ci-fence-check','old-socket-write') != b'':raise SystemExit(5)
except TimeoutError:raise
except OSError:pass
print('CLOSED',flush=True)
'''


def _verify(home, bundle, publisher, manifest):
    global PHASE
    PHASE='GUARD'
    env=os.environ
    for variable, expected, code in (
            ('GITHUB_ACTIONS','true','COMPOSE_SIGNED_CI_ACTIONS_GUARD'),
            ('RUNNER_ENVIRONMENT','github-hosted','COMPOSE_SIGNED_CI_HOSTED_GUARD'),
            ('RUNNER_OS','Linux','COMPOSE_SIGNED_CI_OS_GUARD'),
            ('UTER_CI_STRICT_RUNNER','true','COMPOSE_SIGNED_CI_STRICT_GUARD'),
            ('BACKEND','compose','COMPOSE_SIGNED_CI_BACKEND_GUARD')):
        if env.get(variable)!=expected: raise SignedComposeFenceCheckFailure(code)
    if env.get('DOCKER_HOST'): raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_HOST_GUARD')
    if env.get('DOCKER_CONTEXT','default') not in ('','default'):
        raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CONTEXT_GUARD')
    PHASE='PATH_CHECK'
    home=Path(home).resolve(strict=True);bundle=Path(bundle).resolve(strict=True);publisher=Path(publisher).resolve(strict=True)
    if not home.is_relative_to(ROOT/'work') or not bundle.is_relative_to(ROOT/'work') or not publisher.is_relative_to(ROOT/'work'):
        raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_PATH')
    PHASE='CONFIG_READ'
    cfg=uterctl.read(home/'install.json')
    PHASE='SITE_READ'
    site=uterctl.site_config(home)
    PHASE='SIGNED_IDENTITY'
    if (cfg.get('name')!='uter-upgrade-ci' or cfg.get('backend')!='compose' or cfg.get('context')!='default'
            or site.get('name')!='uter-upgrade-ci' or site.get('backend')!='compose'
            or uterctl.verify(bundle,publisher)!=manifest or manifest.get('version')!='0.1.6'):
        raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_IDENTITY')
    cmd,runenv=install.commands(home,cfg)
    cmd[cmd.index('-f')+1]=str(home/'releases'/manifest['version']/'compose/compose.yaml')
    def checked(command, *, supplied_env=None):
        try: return install_recovery.run_readonly([str(x) for x in command],timeout=180,env=supplied_env).strip()
        except Exception: raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_COMMAND') from None
    def docker(*args): return checked(['docker','--context','default',*args])
    def docker_json(*args):
        try:return json.loads(docker(*args))
        except (ValueError,TypeError):raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_RESPONSE') from None
    PHASE='DOCKER_SCOPE'
    if (docker('context','show')!='default' or
            docker_json('context','inspect','default','--format','{{json .Endpoints.docker.Host}}')!='unix:///var/run/docker.sock'):
        raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_DOCKER_SCOPE')
    PHASE='INSPECTION'
    redis_short=checked(cmd+['ps','-q','redis'],supplied_env=runenv)
    if not re.fullmatch(r'[0-9a-f]{12,64}',redis_short):raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_REDIS')
    redis_id=docker_json('inspect','--format','{{json .Id}}',redis_short)
    if not isinstance(redis_id,str) or not re.fullmatch(r'[0-9a-f]{64}',redis_id):raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_REDIS')
    live=diagnostic._redis_inspect(redis_id);netname=cfg['name']+'_backend';endpoint=live['networks'][netname]
    netid=endpoint['NetworkID'];network=docker_json('network','inspect','--format','{{json .IPAM}}',netid)
    if not re.fullmatch(r'[0-9a-f]{64}',netid) or len(network.get('Config',[]))!=1:
        raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_NETWORK')
    ipam=network['Config'][0];operation=plans.new_operation()
    plan={'schema':1,'operation':operation,'site':cfg['name'],'container_id':redis_id,
          'started_at':live['started'],'restart_count':live['restart_count'],'image_ref':manifest['images']['redis'],
          'image_config_id':live['image_id'],'restart_policy':'unless-stopped','volume_name':cfg['name']+'_redis-data',
          'volume_driver':'local','network_id':netid,'network_name':netname,'network_driver':'bridge',
          'network_scope':'local','network_internal':True,'network_subnet':ipam['Subnet'],
          'network_gateway':ipam['Gateway'],'endpoint_id':endpoint['EndpointID'],
          'endpoint_ipv4':endpoint['IPAddress'],'endpoint_static_ipv4':None,'endpoint_aliases':endpoint['Aliases'],
          'endpoint_mac':endpoint['MacAddress'].lower(),'ipv6_enabled':False,'network_options':{},'endpoint_driver_options':{}}
    # Only synthetic CI credentials are read; never sent to the host command line or logs.
    secret_file=home/'runtime/redis-password'
    if not secret_file.is_file() or secret_file.is_symlink():raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CREDENTIAL')
    secret=secret_file.read_text(encoding='utf-8').strip()
    if not re.fullmatch(r'[0-9a-f]{64}',secret):raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CREDENTIAL')
    client=None;adapter=None;key=os.urandom(32)
    endpoint_before=docker_json('inspect','--format','{{json .NetworkSettings.Networks}}',redis_id)
    try:
        with uterctl.locked(home):
            PHASE='STOP_WRITERS'
            checked(cmd+['stop','guardrail','agent'],supplied_env=runenv)
            exists=docker('exec',redis_id,'sh','-ec',
                'export REDISCLI_AUTH="$(cat /run/secrets/redis_password)"; redis-cli --raw EXISTS uter:ci-fence-check')
            if exists!='0':raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_FIXTURE_EXISTS')

            def create_round():
                nonlocal client,adapter,operation,plan
                operation=plans.new_operation();plan=dict(plan,operation=operation)
                digest=plans.create(home,plan,key)
                record=journal.create(home,backend='compose',site=cfg['name'],resource=redis_id,
                                      plan_sha256=digest,operation=operation)
                client=subprocess.Popen(['sudo','-n','-u','nobody','python3','-u','-c',CLIENT,plan['endpoint_ipv4']],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,start_new_session=True)
                client.stdin.write(secret+'\n');client.stdin.flush()
                selector=selectors.DefaultSelector();selector.register(client.stdout,selectors.EVENT_READ)
                if not selector.select(15) or client.stdout.readline().strip()!='READY':
                    raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_WRITER')
                adapter=fence.Adapter(home,bundle,publisher,key)
                if adapter.prepare(record) is not True:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_ISOLATION')
                journal.advance(home,operation=operation,expected='prepared',next_phase='isolating')
                adapter.disable_restart(record)
                adapter.install_rule(record)
                client.stdin.write('block\n');client.stdin.flush()
                if not selector.select(10) or client.stdout.readline().strip()!='BLOCKED':
                    raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_WRITER_NOT_BLOCKED')
                adapter.close_clients(record)
                if adapter.verify_fenced(record) is not True:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_ISOLATION')
                journal.advance(home,operation=operation,expected='isolating',next_phase='isolated')
                if adapter._redis(plan,'GET',KEY)!=VALUE:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_DATA')
                return selector

            def verify_closed(selector):
                nonlocal client
                client.stdin.write('closed\n');client.stdin.flush()
                if not selector.select(15) or client.stdout.readline().strip()!='CLOSED' or client.wait(timeout=5):
                    raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_OLD_SOCKET')
                client=None
                if adapter._redis(plan,'GET',KEY)!=VALUE:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_DATA')
                if adapter._redis(plan,'DEL',KEY)!='1':raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CLEANUP')
                if docker_json('inspect','--format','{{json .NetworkSettings.Networks}}',redis_id)!=endpoint_before:
                    raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_ENDPOINT_CHANGED')

            def remove_ci_marker(expected_phase):
                current=journal.read(home)
                plans.read(home,key,current['plan_sha256'],operation=operation,site=cfg['name'],resource=redis_id)
                if current['phase']!=expected_phase or current['operation']!=operation:
                    raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CLEANUP')
                (home/journal.NAME).unlink();(home/plans.NAME).unlink()

            # Round 1: prove that the supported no-capture release leaves the
            # network endpoint and original signed Redis running unchanged.
            PHASE='PRE_CAPTURE_ISOLATE'
            selector=create_round()
            first_operation=operation;first_key=key
            PHASE='PRE_CAPTURE_RELEASE'
            protocol.release_without_capture(home,operation,adapter)
            if journal.read(home)['phase']!='restored':raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_RELEASE')
            verify_closed(selector);remove_ci_marker('restored');adapter.close();adapter=None

            # Round 2: real encrypted RDB while fenced; production release is
            # intentionally refused after capture. CI performs separate explicit
            # exact-resource cleanup; that is not a recovery implementation.
            PHASE='CAPTURE_ISOLATE'
            key=os.urandom(32)
            if key==first_key:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_RANDOMNESS')
            selector=create_round();record=journal.read(home)
            if operation==first_operation or plan['operation']!=operation or record['operation']!=operation:
                raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_RANDOMNESS')
            journal.advance(home,operation=operation,expected='isolated',next_phase='capturing')
            PHASE='CAPTURE'
            with tempfile.TemporaryDirectory(prefix='nsfence-snapshot-',dir=ROOT/'work') as temp:
                writer=backup_store.BackupWriter(Path(temp)/'set',key,home,site,manifest['version'])
                redis_cmd=['docker','--context','default','exec',redis_id,'sh','-ec',
                    'export REDISCLI_AUTH="$(cat /run/secrets/redis_password)"; exec redis-cli --rdb -']
                check_cmd=['docker','--context','default','exec','-i',redis_id,'redis-check-rdb','/dev/stdin']
                backup_snapshot.process_component(writer,'redis',redis_cmd,prefix=b'REDIS')
                backup_snapshot.verify_redis_snapshot(writer,check_cmd)
                if adapter.verify_fenced(record) is not True:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_ISOLATION')
            journal.advance(home,operation=operation,expected='capturing',next_phase='captured')
            PHASE='CAPTURE_RELEASE_REFUSED'
            try:adapter.authorize_release_before_capture(record)
            except fence.NamespaceFenceError:pass
            else:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_UNSAFE_RELEASE')
            if journal.read(home)['phase']!='captured':raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_UNSAFE_RELEASE')
            # Trust boundary here is exclusively this disposable CI fixture.
            PHASE='CI_ONLY_CLEANUP'
            adapter._signed(plan);adapter._live_namespace(plan);adapter._check_firewall(installed=True)
            adapter._cmd(['-D','INPUT',*adapter._rule()])
            adapter._check_firewall(installed=False);adapter._live_namespace(plan)
            adapter._run('update','--restart=unless-stopped',redis_id)
            adapter._state(plan,detached=False,restart='unless-stopped',original_endpoint=True)
            verify_closed(selector);remove_ci_marker('captured');adapter.close();adapter=None
            PHASE='CI_RESUME'
            backup_snapshot.resume_writers(home,cfg,site,manifest)
    finally:
        if adapter is not None:adapter.close()
        if client is not None:
            try:os.killpg(client.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            client.wait(timeout=5)
    return {'signed_016_firewall_fence':'pass','no_capture_release':'pass',
            'snapshot_under_firewall':'pass','release_after_capture_blocked':'pass',
            'unchanged_endpoint':'pass','ci_only_cleanup':'pass','production_recovery_available':False}


def verify(home,bundle,publisher,manifest):
    try:return _verify(home,bundle,publisher,manifest)
    except SignedComposeFenceCheckFailure:raise
    except Exception:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_'+PHASE+'_FAILED') from None
