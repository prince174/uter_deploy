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
import stat
import subprocess
import tempfile
import time
import base64
import shutil
import sys

import uterctl
from scripts import (backup_snapshot, backup_store, compose_nsfirewall_adapter as fence,
                     compose_nsfirewall_protocol as protocol, compose_fence_recovery_plan as plans, compose_fence_start,
                     compose_redis_diagnostic as diagnostic, install, install_recovery,
                     redis_fence_journal as journal, compose_nsfirewall_checkpoint as checkpoint,
                     compose_snapshot_only as snapshot_only, snapshot_only_receipts as snapshot_receipts,
                     compose_fence_origin as origin, compose_fence_resume as resume)

ROOT=Path(__file__).resolve().parents[1]
KEY='uter:ci-fence-check'
VALUE='ci-synthetic-fence-write'
PHASE='GUARD'
DIAGNOSTICS={name:'COMPOSE_NSFENCE_CAUSE_'+name for name in (
    'NS_FENCE_DAEMON_UNVERIFIED','NS_FENCE_DAEMON_SOCKET_STATE','NS_FENCE_DAEMON_SOCKET_OR_PROC',
    'NS_FENCE_DAEMON_PEER_CREDENTIALS','NS_FENCE_DAEMON_PEER_PID1','NS_FENCE_DAEMON_PEER_PROCESS','NS_FENCE_DAEMON_PID_NAMESPACE',
    'NS_FENCE_SYSTEMD_UNVERIFIED',
    'NS_FENCE_DAEMON_PIDFD_UNAVAILABLE','NS_FENCE_DAEMON_PIDFD_EXITED',
    'NS_FENCE_DAEMON_PID_CHANGED','NS_FENCE_DAEMON_NAMESPACE_CHANGED','NS_FENCE_HOST_NAMESPACE_REJECTED',
    'NS_FENCE_NAMESPACE_CHANGED','NS_FENCE_PROCESS_CHANGED','NS_FENCE_NAMESPACE_PEER',
    'NS_FENCE_PROC_UNVERIFIED','NS_FENCE_CAPABILITIES_UNSUPPORTED',
    'NS_FENCE_FIREWALL_UNCERTAIN','NS_FENCE_RULE_UNVERIFIED','NS_FENCE_FIREWALL_CHANGED',
    'NS_FENCE_BIND_UNSUPPORTED','NS_FENCE_PORT_UNSUPPORTED','NS_FENCE_TLS_UNSUPPORTED',
    'COMPOSE_FENCE_EXECUTABLE_UNVERIFIED','COMPOSE_FENCE_DOCKER_UNCERTAIN',
    'COMPOSE_FENCE_REDIS_CHANGED','COMPOSE_FENCE_IDENTITY_INVALID','COMPOSE_FENCE_CLIENTS_REMAIN')}
START_DIAGNOSTICS={name:'COMPOSE_START_CI_'+name for name in (
    'FENCE_START_INCOMPLETE','FENCE_START_INTENT_INVALID','FENCE_START_INTENT_UNCERTAIN',
    'FENCE_START_NETWORK_UNVERIFIED','FENCE_START_PRIOR_OPERATION','FENCE_START_REDIS_UNVERIFIED',
    'FENCE_START_RESULT_UNVERIFIED','FENCE_START_STATE_CHANGED','FENCE_START_WRITER_EXIT_UNVERIFIED',
    'FENCE_START_OBSERVE_REDIS_CHANGED','FENCE_START_OBSERVE_WRITERS_CHANGED',
    'FENCE_START_RECHECK_PLAN_CHANGED','FENCE_START_RECHECK_WRITERS_CHANGED','FENCE_START_RECHECK_BUNDLE_CHANGED',
    'FENCE_START_WRITER_UNVERIFIED','FENCE_START_PRECHECK_UNCERTAIN','FENCE_START_PLAN_UNCERTAIN',
    'FENCE_START_INTENT_UNCERTAIN','FENCE_START_JOURNAL_UNCERTAIN','FENCE_START_RECHECK_UNCERTAIN',
    'FENCE_START_STOP_UNCERTAIN','FENCE_START_WRITER_STOP_VERIFY_UNCERTAIN',
    'FENCE_START_ISOLATE_UNCERTAIN','FENCE_START_RESULT_UNCERTAIN',
    'FENCE_EXECUTOR_COMPONENT_MISSING','FENCE_EXECUTOR_IMPORT_STATE_UNSAFE','FENCE_EXECUTOR_IMPORT_UNSAFE',
    'FENCE_EXECUTOR_ISOLATED_PYTHON_REQUIRED','FENCE_RECOVERY_BACKUP_KEY_INVALID',
    'FENCE_RECOVERY_BACKUP_KEY_REQUIRED','FENCE_RECOVERY_INSTALLATION_UNSUPPORTED',
    'FENCE_RECOVERY_KEY_LOCATION_INVALID','FENCE_RECOVERY_PATH_NOT_ABSOLUTE','FENCE_RECOVERY_PATH_UNSAFE',
    'FENCE_RECOVERY_SIGNED_BUNDLE_REQUIRED','FENCE_RECOVERY_SIGNED_VERSION_MISMATCH')}
for _prefix,_suffixes in (
    ('FENCE_START_RECHECK_PLAN',('PROCESS','IMAGE','NETWORK_ID','NETWORK_POLICY','IPAM','ENDPOINT_ID',
                                 'ENDPOINT_ADDRESS','ENDPOINT_ALIASES','ENDPOINT_MAC','ENDPOINT_OPTIONS','VOLUME','OTHER')),
    ('FENCE_START_RECHECK_WRITERS',('IDENTITY','STARTED','RESTART','OTHER')),
    ('FENCE_START_OBSERVE_WRITERS',('IDENTITY','STARTED','RESTART','OTHER')),
    ('FENCE_START_OBSERVE_REDIS',('PROCESS','IMAGE','NETWORK','VOLUME','OTHER'))):
    for _suffix in _suffixes:
        _name=_prefix+'_'+_suffix
        START_DIAGNOSTICS[_name]='COMPOSE_START_CI_'+_name
for _service in ('GUARDRAIL','AGENT'):
    for _category in ('RESPONSE','IDENTITY','RUNNING','EXIT_TYPE','EXIT_NONZERO','OOM','ENGINE_ERROR',
                      'STARTED','RESTART_COUNT','PROJECT','SERVICE','IMAGE_REF','IMAGE_ID','FINISHED'):
        _name='FENCE_START_WRITER_STOP_'+_service+'_'+_category
        START_DIAGNOSTICS[_name]='COMPOSE_START_CI_'+_name
for _stage in ('SIGNED_LIVE','WRITER_IDENTITIES','REDIS_INSPECT','PLAN_VALIDATE','CONFIG',
               'STATE','NETWORK','PEERS','REINSPECT','BUNDLE_HASH'):
    for _code in ('ERROR','KEY_ERROR','TYPE_ERROR',*compose_fence_start._OBSERVE_DIAGNOSTIC_CODES,
                  *compose_fence_start._OBSERVE_ADAPTER_CODES):
        _name='FENCE_START_OBSERVE_'+_stage+'_'+_code
        START_DIAGNOSTICS[_name]='COMPOSE_START_CI_'+_name
CRASH_DIAGNOSTICS={name:'COMPOSE_CRASH_CI_'+name for name in (
    'COMMAND','COMMAND_TIMEOUT','LOCK','JOURNAL','SIGNED','READ','ENDPOINT','DELETE',
    'PLAN','CHECKPOINT','ORIGIN','CLEANUP',
    'NS_RECOVERY_INCOMPLETE','NS_RECOVERY_STATE_UNSUPPORTED','FENCE_RECOVERY_BACKUP_KEY_INVALID',
    'FENCE_RECOVERY_PATH_UNSAFE','FENCE_RECOVERY_KEY_LOCATION_INVALID','FENCE_RECOVERY_STATE_UNSUPPORTED',
    'FENCE_RECOVERY_INSTALLATION_UNSUPPORTED','FENCE_RECOVERY_SIGNED_VERSION_MISMATCH',
    'FENCE_RECOVERY_RESULT_UNVERIFIED','FENCE_EXECUTOR_COMPONENT_MISSING','FENCE_EXECUTOR_IMPORT_UNSAFE',
    'FENCE_EXECUTOR_IMPORT_STATE_UNSAFE','FENCE_EXECUTOR_ISOLATED_PYTHON_REQUIRED')}


class SignedComposeFenceCheckFailure(ValueError): pass


def _start_diagnostic(raw):
    """Map a single exact error line; never print or forward raw stderr."""
    match=re.fullmatch(rb'uterctl: (?:StartError|ValueError): ([A-Z0-9_]+)\r?\n',raw)
    if not match:return None
    return START_DIAGNOSTICS.get(match.group(1).decode('ascii'))


def _recovery_diagnostic(raw):
    """Recognize fixed CLI errors only; discard arbitrary stderr bytes."""
    match=re.fullmatch(rb'uterctl: (?:ValueError|NamespaceProtocolError): ([A-Z0-9_]+)\r?\n',raw)
    if not match:return None
    return CRASH_DIAGNOSTICS.get(match.group(1).decode('ascii'))


def _ci_signed_executor(source,root):
    """Fresh local CI key, never published; sign current checked-out scripts."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    bundle=Path(root)/'executor-bundle'
    shutil.copytree(source,bundle)
    for path in (ROOT/'scripts').glob('*.py'):
        shutil.copy2(path,bundle/'scripts'/path.name)
    shutil.copy2(ROOT/'uterctl.py',bundle/'uterctl.py')
    private=Ed25519PrivateKey.generate()
    public=Path(root)/'executor-publisher.pem'
    public.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM,
                       serialization.PublicFormat.SubjectPublicKeyInfo))
    raw=json.dumps(uterctl.inventory(bundle),sort_keys=True,indent=2).encode()
    (bundle/'checksums.json').write_bytes(raw)
    (bundle/'checksums.sig').write_bytes(base64.b64encode(private.sign(raw)))
    uterctl.verify(bundle,public)
    return bundle,public


def _ci_clear_killed_child_lock(home,pid):
    """CI only: parent has already waitpid-reaped its own killed child.

    This is deliberately not an installation stale-lock recovery protocol.
    No other controller may run on the disposable hosted fixture.
    """
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'
            or os.environ.get('UTER_CI_STRICT_RUNNER')!='true' or not isinstance(pid,int) or pid<=1
            or not Path(home).resolve(strict=True).is_relative_to(ROOT/'work')):
        raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_STALE_LOCK')
    directory=os.open(home,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fd=os.open('operation.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            info=os.fstat(fd);data=os.read(fd,64);now=os.stat('operation.lock',dir_fd=directory,follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
                    or info.st_mode&0o077 or data!=str(pid).encode()
                    or (info.st_dev,info.st_ino)!=(now.st_dev,now.st_ino)):
                raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_STALE_LOCK')
            os.unlink('operation.lock',dir_fd=directory);os.fsync(directory)
        finally:os.close(fd)
    except OSError:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_STALE_LOCK') from None
    finally:os.close(directory)


def _ci_wait_recovery_child(pid,timeout=300):
    """Bound a CI child; timeout leaves fixture state unknown and stops test."""
    reaped=False;deadline=time.monotonic()+timeout
    try:
        while True:
            waited,status=os.waitpid(pid,os.WNOHANG)
            if waited:
                reaped=True;break
            if time.monotonic()>=deadline:
                raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CRASH_RECOVERY_TIMEOUT')
            time.sleep(.1)
        if waited!=pid or not os.WIFEXITED(status) or os.WEXITSTATUS(status)!=0:
            raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CRASH_RECOVERY')
    finally:
        if not reaped:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:os.waitpid(pid,0)
            except ChildProcessError:pass


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
                checkpoint.read(home,current,key)
                if current['phase']!=expected_phase or current['operation']!=operation:
                    raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CLEANUP')
                if expected_phase=='redis_released':
                    released=origin.read(home,key,current)
                    if released['origin']!='pre_capture' or released['receipt_sha256']!='0'*64:
                        raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CLEANUP')
                    (home/origin.NAME).unlink()
                elif os.path.lexists(home/origin.NAME):
                    raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CLEANUP')
                (home/journal.NAME).unlink();(home/plans.NAME).unlink();(home/checkpoint.NAME).unlink()

            # Round 1: prove that the supported no-capture release leaves the
            # network endpoint and original signed Redis running unchanged.
            PHASE='PRE_CAPTURE_ISOLATE'
            selector=create_round()
            first_operation=operation;first_key=key
            PHASE='PRE_CAPTURE_RELEASE'
            # Drop every in-memory handle, then recover from the authenticated
            # checkpoint with a fresh adapter. This simulates losing controller
            # memory; it is not a forced process/host crash test.
            adapter.close();adapter=fence.Adapter(home,bundle,publisher,key)
            protocol.recover_before_capture(home,operation,adapter)
            if journal.read(home)['phase']!='redis_released':raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_RELEASE')
            verify_closed(selector);remove_ci_marker('redis_released');adapter.close();adapter=None

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

    # Force a real controller-process crash at a known pre-capture boundary.
    # The parent owns this disposable fixture exclusively; CI-only stale-lock
    # cleanup below is NOT an algorithm for recovering user installations.
    PHASE='CRASH_SETUP'
    crash_key=os.urandom(32);crash_operation=plans.new_operation()
    crash_plan=dict(plan,operation=crash_operation)
    with uterctl.locked(home):
        checked(cmd+['stop','guardrail','agent'],supplied_env=runenv)
    readfd,writefd=os.pipe();pid=os.fork()
    if pid==0:
        os.close(readfd)
        child_adapter=None
        try:
            with uterctl.locked(home):
                digest=plans.create(home,crash_plan,crash_key)
                record=journal.create(home,backend='compose',site=cfg['name'],resource=redis_id,
                                      plan_sha256=digest,operation=crash_operation)
                child_adapter=fence.Adapter(home,bundle,publisher,crash_key)
                if child_adapter._redis(crash_plan,'SET',KEY,VALUE)!='OK':raise ValueError
                protocol.isolate(home,crash_operation,child_adapter)
                os.write(writefd,b'R')
                while True:signal.pause()
        except BaseException:
            os._exit(12)
    os.close(writefd);reaped=False
    try:
        PHASE='CRASH_WAIT'
        import select
        if not select.select([readfd],[],[],300)[0] or os.read(readfd,1)!=b'R':
            raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CRASH_NOT_READY')
        os.kill(pid,signal.SIGKILL)
        waited,status=os.waitpid(pid,0);reaped=True
        if waited!=pid or not os.WIFSIGNALED(status) or os.WTERMSIG(status)!=signal.SIGKILL:
            raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CRASH_NOT_KILLED')
    finally:
        os.close(readfd)
        if not reaped:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:os.waitpid(pid,0)
            except ChildProcessError:pass
    PHASE='CRASH_STALE_LOCK'
    record=journal.read(home)
    if record['operation']!=crash_operation or record['phase']!='isolated':
        raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_CRASH_JOURNAL')
    _ci_clear_killed_child_lock(home,pid)
    PHASE='CRASH_RECOVERY'
    fd,keyfile=tempfile.mkstemp(prefix='fence-recovery-key-',dir=ROOT/'work')
    with os.fdopen(fd,'wb') as output:
        os.fchmod(output.fileno(),0o600);output.write(crash_key);output.flush();os.fsync(output.fileno())
    pre_executor_dir=tempfile.mkdtemp(prefix='fence-executor-',dir=ROOT/'work')
    pre_executor,pre_executor_public=_ci_signed_executor(bundle,pre_executor_dir)
    diagnostic_r,diagnostic_w=os.pipe()
    recovery_pid=os.fork()
    if recovery_pid==0:
        os.close(diagnostic_r);recovery=None;failure=CRASH_DIAGNOSTICS['COMMAND']
        try:
            # Call the real controller entry point. It must obtain the normal
            # operation lock itself and must never resume application writers.
            with tempfile.TemporaryFile() as error_file:
                try:
                    process=subprocess.run([sys.executable,'-I','-B',str(pre_executor/'uterctl.py'),'fence-recover-redis',
                                            '--home',str(home),'--bundle',str(bundle),'--key',str(publisher),
                                            '--backup-key',keyfile,'--executor-key',str(pre_executor_public)],
                                           cwd=pre_executor,env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                                                'LANG':'C','HOME':'/root'},stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL,stderr=error_file,timeout=240)
                except subprocess.TimeoutExpired:
                    failure=CRASH_DIAGNOSTICS['COMMAND_TIMEOUT'];raise
                if process.returncode:
                    error_file.seek(0);failure=_recovery_diagnostic(error_file.read(4097)) or failure
                    raise ValueError
            failure=CRASH_DIAGNOSTICS['LOCK']
            with uterctl.locked(home):
                recovery=fence.Adapter(home,bundle,publisher,crash_key)
                failure=CRASH_DIAGNOSTICS['JOURNAL']
                record=journal.read(home)
                if record['phase']!='redis_released':raise ValueError
                # _signed verifies both application writers remain stopped.
                failure=CRASH_DIAGNOSTICS['SIGNED']
                recovery._signed(crash_plan)
                failure=CRASH_DIAGNOSTICS['READ']
                if recovery._redis(crash_plan,'GET',KEY)!=VALUE:raise ValueError
                failure=CRASH_DIAGNOSTICS['ENDPOINT']
                if docker_json('inspect','--format','{{json .NetworkSettings.Networks}}',redis_id)!=endpoint_before:raise ValueError
                failure=CRASH_DIAGNOSTICS['DELETE']
                if recovery._redis(crash_plan,'DEL',KEY)!='1':raise ValueError
                failure=CRASH_DIAGNOSTICS['PLAN']
                plans.read(home,crash_key,record['plan_sha256'],operation=crash_operation,site=cfg['name'],resource=redis_id)
                failure=CRASH_DIAGNOSTICS['CHECKPOINT']
                checkpoint.read(home,record,crash_key)
                failure=CRASH_DIAGNOSTICS['ORIGIN']
                released=origin.read(home,crash_key,record)
                if released['origin']!='pre_capture' or released['receipt_sha256']!='0'*64:raise ValueError
                failure=CRASH_DIAGNOSTICS['CLEANUP']
                for name in (origin.NAME,journal.NAME,plans.NAME,checkpoint.NAME):(home/name).unlink()
                recovery.close();recovery=None
            os.close(diagnostic_w)
            os._exit(0)
        except BaseException:
            if recovery is not None:recovery.close()
            try:os.write(diagnostic_w,failure.encode('ascii'))
            except OSError:pass
            os.close(diagnostic_w)
            os._exit(13)
    os.close(diagnostic_w)
    try:
        try:_ci_wait_recovery_child(recovery_pid)
        except SignedComposeFenceCheckFailure:
            diagnostic_code=os.read(diagnostic_r,256).decode('ascii',errors='ignore')
            if diagnostic_code in CRASH_DIAGNOSTICS.values():raise SignedComposeFenceCheckFailure(diagnostic_code) from None
            raise
    finally:
        os.close(diagnostic_r)
        Path(keyfile).unlink(missing_ok=True)
        shutil.rmtree(pre_executor_dir)
    PHASE='CRASH_RESUME'
    with uterctl.locked(home):backup_snapshot.resume_writers(home,cfg,site,manifest)
    # Snapshot-only transaction: signed current executor, actual encrypted
    # runtime/Redis/audit backup, real process death after durable receipt,
    # then a fresh process verifies the complete backup before Redis release.
    # Stale-lock cleanup remains exclusively for this disposable fixture.
    PHASE='SNAPSHOT_CRASH_SETUP'
    with tempfile.TemporaryDirectory(prefix='snapshot-only-ci-',dir=ROOT/'work') as temp:
        executor,executor_public=_ci_signed_executor(bundle,temp)
        destination=Path(temp)/'backup';snap_key=os.urandom(32);snap_operation=plans.new_operation()
        snap_plan=dict(plan,operation=snap_operation)
        keyfile=Path(temp)/'backup.key'
        fd=os.open(keyfile,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as output:
            os.fchmod(output.fileno(),0o600);output.write(snap_key);output.flush();os.fsync(output.fileno())
        with uterctl.locked(home):checked(cmd+['stop','guardrail','agent'],supplied_env=runenv)
        readfd,writefd=os.pipe();pid=os.fork()
        if pid==0:
            os.close(readfd);owned=None
            try:
                with uterctl.locked(home):
                    digest=plans.create(home,snap_plan,snap_key)
                    entry=journal.create(home,backend='compose',site=cfg['name'],resource=redis_id,
                                         plan_sha256=digest,operation=snap_operation)
                    owned=fence.Adapter(home,bundle,publisher,snap_key)
                    if owned._redis(snap_plan,'SET',KEY,VALUE)!='OK':raise ValueError
                    protocol.isolate(home,snap_operation,owned)
                    entry=journal.read(home)
                    snapshot_only.capture(owned,entry,executor,executor_public,destination)
                    os.write(writefd,b'R')
                    while True:signal.pause()
            except BaseException:os._exit(21)
        os.close(writefd);reaped=False
        try:
            PHASE='SNAPSHOT_CRASH_WAIT'
            import select
            if not select.select([readfd],[],[],600)[0] or os.read(readfd,1)!=b'R':
                raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_SNAPSHOT_NOT_READY')
            os.kill(pid,signal.SIGKILL);waited,status=os.waitpid(pid,0);reaped=True
            if waited!=pid or not os.WIFSIGNALED(status) or os.WTERMSIG(status)!=signal.SIGKILL:
                raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_SNAPSHOT_NOT_KILLED')
        finally:
            os.close(readfd)
            if not reaped:
                try:os.kill(pid,signal.SIGKILL)
                except ProcessLookupError:pass
                try:os.waitpid(pid,0)
                except ChildProcessError:pass
        PHASE='SNAPSHOT_CRASH_LOCK'
        entry=journal.read(home)
        if entry['operation']!=snap_operation or entry['phase']!='captured':raise ValueError
        _ci_clear_killed_child_lock(home,pid)
        PHASE='SNAPSHOT_CRASH_RECOVERY'
        recovery_pid=os.fork()
        if recovery_pid==0:
            owned=None
            try:
                process=subprocess.run([sys.executable,'-I','-B',str(executor/'uterctl.py'),'fence-recover-snapshot-redis',
                                        '--home',str(home),'--bundle',str(bundle),'--key',str(publisher),
                                        '--backup-key',str(keyfile),'--backup-dir',str(destination),
                                        '--executor-key',str(executor_public)],cwd=executor,
                                       env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                            'LANG':'C','HOME':'/root'},stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=240)
                if process.returncode:raise ValueError
                with uterctl.locked(home):
                    owned=fence.Adapter(home,bundle,publisher,snap_key)
                    entry=journal.read(home)
                    if entry['phase']!='redis_released':raise ValueError
                    owned._signed(snap_plan)
                    if owned._redis(snap_plan,'GET',KEY)!=VALUE:raise ValueError
                    if docker_json('inspect','--format','{{json .NetworkSettings.Networks}}',redis_id)!=endpoint_before:raise ValueError
                    if owned._redis(snap_plan,'DEL',KEY)!='1':raise ValueError
                    plans.read(home,snap_key,entry['plan_sha256'],operation=snap_operation,site=cfg['name'],resource=redis_id)
                    checkpoint.read(home,entry,snap_key)
                    snapshot_receipts.read_decision(home,snap_key)
                    _,receipt_hash=snapshot_receipts.read_receipt(home,snap_key)
                    released=origin.read(home,snap_key,entry)
                    if released['origin']!='snapshot' or released['receipt_sha256']!=receipt_hash:raise ValueError
                    for name in (journal.NAME,plans.NAME,checkpoint.NAME,snapshot_receipts.DECISION,
                                 snapshot_receipts.RECEIPT,snapshot_receipts.DESCRIPTOR,origin.NAME):(home/name).unlink()
                    owned.close();owned=None
                os._exit(0)
            except BaseException:
                if owned is not None:owned.close()
                os._exit(23)
        _ci_wait_recovery_child(recovery_pid)
        PHASE='SNAPSHOT_CRASH_RESUME'
        with uterctl.locked(home):backup_snapshot.resume_writers(home,cfg,site,manifest)
    # Separate CLI round: capture must execute from the ephemeral signed
    # controller, not from a caller-supplied Python callback. The forced-death
    # test above remains separate, because this CLI is allowed to exit normally.
    PHASE='SNAPSHOT_CLI_SETUP'
    with tempfile.TemporaryDirectory(prefix='snapshot-cli-ci-',dir=ROOT/'work') as temp:
        executor,executor_public=_ci_signed_executor(bundle,temp)
        destination=Path(temp)/'backup';snap_key=os.urandom(32);keyfile=Path(temp)/'backup.key'
        fd=os.open(keyfile,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as output:
            os.fchmod(output.fileno(),0o600);output.write(snap_key);output.flush();os.fsync(output.fileno())
        with uterctl.locked(home):
            owned=fence.Adapter(home,bundle,publisher,snap_key)
            try:
                # Synthetic data is inserted before the command stops writers.
                if owned._redis(plan,'SET',KEY,VALUE)!='OK':raise ValueError
            finally:owned.close()
        PHASE='SNAPSHOT_CLI_START'
        with tempfile.TemporaryFile() as error_file:
            process=subprocess.run([sys.executable,'-I','-B',str(executor/'uterctl.py'),'fence-start-redis',
                                    '--home',str(home),'--bundle',str(bundle),'--key',str(publisher),
                                    '--backup-key',str(keyfile),'--executor-key',str(executor_public)],cwd=executor,
                                   env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                        'LANG':'C','HOME':'/root'},stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL,stderr=error_file,timeout=600)
            if process.returncode:
                error_file.seek(0);safe=_start_diagnostic(error_file.read(4097))
                raise SignedComposeFenceCheckFailure(safe or 'COMPOSE_SIGNED_CI_START_COMMAND')
        with uterctl.locked(home):
            entry=journal.read(home)
            if entry['phase']!='isolated' or entry['site']!=cfg['name'] or entry['resource']!=redis_id:raise ValueError
            snap_operation=entry['operation']
            snap_plan=plans.read(home,snap_key,entry['plan_sha256'],operation=snap_operation,site=cfg['name'],resource=redis_id)
            product_hash=snapshot_only._hash((bundle/'checksums.json').read_bytes())
            compose_fence_start.read_intent(home,snap_key,entry,product_hash)
        PHASE='SNAPSHOT_CLI_CAPTURE'
        process=subprocess.run([sys.executable,'-I','-B',str(executor/'uterctl.py'),'fence-backup-redis',
                                '--home',str(home),'--bundle',str(bundle),'--key',str(publisher),
                                '--backup-key',str(keyfile),'--backup-dir',str(destination),
                                '--executor-key',str(executor_public)],cwd=executor,
                               env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                    'LANG':'C','HOME':'/root'},stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600)
        if process.returncode:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_SNAPSHOT_COMMAND')
        PHASE='SNAPSHOT_CLI_RECOVERY'
        process=subprocess.run([sys.executable,'-I','-B',str(executor/'uterctl.py'),'fence-recover-snapshot-redis',
                                '--home',str(home),'--bundle',str(bundle),'--key',str(publisher),
                                '--backup-key',str(keyfile),'--backup-dir',str(destination),
                                '--executor-key',str(executor_public)],cwd=executor,
                               env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                    'LANG':'C','HOME':'/root'},stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600)
        if process.returncode:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_RECOVERY_COMMAND')
        with uterctl.locked(home):
            entry=journal.read(home)
            if entry['operation']!=snap_operation or entry['phase']!='redis_released':raise ValueError
            owned=fence.Adapter(home,bundle,publisher,snap_key)
            try:
                owned._signed(snap_plan)
                if owned._redis(snap_plan,'GET',KEY)!=VALUE:raise ValueError
                if docker_json('inspect','--format','{{json .NetworkSettings.Networks}}',redis_id)!=endpoint_before:raise ValueError
                plans.read(home,snap_key,entry['plan_sha256'],operation=snap_operation,site=cfg['name'],resource=redis_id)
                checkpoint.read(home,entry,snap_key);snapshot_receipts.read_decision(home,snap_key)
                compose_fence_start.read_intent(home,snap_key,entry,product_hash)
                _,receipt_hash=snapshot_receipts.read_receipt(home,snap_key)
                released=origin.read(home,snap_key,entry)
                if released['origin']!='snapshot' or released['receipt_sha256']!=receipt_hash:raise ValueError
            finally:owned.close()
        PHASE='SNAPSHOT_CLI_WRITERS'
        process=subprocess.run([sys.executable,'-I','-B',str(executor/'uterctl.py'),'fence-resume-writers',
                                '--home',str(home),'--bundle',str(bundle),'--key',str(publisher),
                                '--backup-key',str(keyfile),'--backup-dir',str(destination),
                                '--executor-key',str(executor_public)],cwd=executor,
                               env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                    'LANG':'C','HOME':'/root'},stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600)
        if process.returncode:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_WRITERS_COMMAND')
        with uterctl.locked(home):
            entry=journal.read(home)
            if entry['operation']!=snap_operation or entry['phase']!='writers_resumed':raise ValueError
            resume.read_intent(home,snap_key,entry)
            compose_fence_start.read_intent(home,snap_key,entry,product_hash)
            backup_snapshot.adopt_installation.verify_live(home,cfg,manifest)
            owned=fence.Adapter(home,bundle,publisher,snap_key)
            try:
                if owned._redis(snap_plan,'GET',KEY)!=VALUE:raise ValueError
                if docker_json('inspect','--format','{{json .NetworkSettings.Networks}}',redis_id)!=endpoint_before:raise ValueError
            finally:owned.close()
        PHASE='SNAPSHOT_CLI_FINALIZE'
        finalize_command=[sys.executable,'-I','-B',str(executor/'uterctl.py'),'fence-finalize',
                          '--home',str(home),'--bundle',str(bundle),'--key',str(publisher),
                          '--backup-key',str(keyfile),'--backup-dir',str(destination),
                          '--executor-key',str(executor_public)]
        clean_env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','HOME':'/root'}
        process=subprocess.run(finalize_command,cwd=executor,env=clean_env,stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600)
        if process.returncode:raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_FINALIZE_COMMAND')
        PHASE='SNAPSHOT_CLI_POSTCHECK'
        cleared=(journal.NAME,journal.FINALIZE_ANCHOR,plans.NAME,checkpoint.NAME,origin.NAME,resume.NAME,
                 compose_fence_start.NAME,snapshot_receipts.DESCRIPTOR,snapshot_receipts.RECEIPT,snapshot_receipts.DECISION)
        if any(os.path.lexists(home/name) for name in cleared):raise ValueError
        backup_store.verify_set(destination,snap_key,home=home,site=site,version=manifest['version'])
        again=subprocess.run(finalize_command,cwd=executor,env=clean_env,stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600)
        if again.returncode==0 or any(os.path.lexists(home/name) for name in cleared):raise ValueError
        with uterctl.locked(home):
            backup_snapshot.adopt_installation.verify_live(home,cfg,manifest)
            owned=fence.Adapter(home,bundle,publisher,snap_key)
            try:
                if owned._redis(snap_plan,'GET',KEY)!=VALUE:raise ValueError
                if owned._redis(snap_plan,'DEL',KEY)!='1':raise ValueError
            finally:owned.close()
    return {'signed_016_firewall_fence':'pass','no_capture_release':'pass',
            'snapshot_under_firewall':'pass','release_after_capture_blocked':'pass',
            'unchanged_endpoint':'pass','ci_only_cleanup':'pass',
            'pre_capture_sigkill_recovery':'pass','snapshot_sigkill_recovery':'pass',
            'signed_fence_start_cli':'pass','signed_snapshot_cli':'pass','signed_writer_resume_finalize':'pass',
            'production_recovery_available':False}


def verify(home,bundle,publisher,manifest):
    try:return _verify(home,bundle,publisher,manifest)
    except SignedComposeFenceCheckFailure:raise
    except Exception as error:
        if type(error) in (fence.NamespaceFenceError,fence.compose.ComposeFenceAdapterError):
            category=DIAGNOSTICS.get(str(error))
            if category:raise SignedComposeFenceCheckFailure(category) from None
        raise SignedComposeFenceCheckFailure('COMPOSE_SIGNED_CI_'+PHASE+'_FAILED') from None
