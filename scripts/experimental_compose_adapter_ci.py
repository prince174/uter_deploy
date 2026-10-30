"""Hosted-runner-only synthetic adapter exercise; not a production installation.

The pinned Redis image is published, but this fixture is NOT a signed 0.1.6
Compose installation. Only _signed is overridden; no CI result authorizes a
real upgrade or a rollback. Never run this on a local/shared Docker daemon.
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
import uuid

import uterctl
from scripts import (compose_fence_adapter as fence, compose_fence_protocol as protocol,
                     compose_fence_recovery_plan as plans, compose_redis_diagnostic as diag,
                     experimental_compose_fence_ci as helpers, experimental_netns_probe as common,
                     redis_fence_journal as journal)

IMAGE = helpers.REDIS
LABEL = helpers.LABEL
PASSWORD = common.OLD
PHASE = 'guard'


def main():
    global PHASE
    common.guard(os.environ)
    if common.cmd(['docker','context','show']) != 'default': raise RuntimeError('nondefault context')
    details = json.loads(common.cmd(['docker','context','inspect','default']))
    if len(details) != 1 or details[0]['Endpoints']['docker']['Host'] != 'unix:///var/run/docker.sock':
        raise RuntimeError('unexpected Docker endpoint')
    owner = uuid.uuid4().hex
    site = 'uterci-'+owner[:16]
    netname = site+'_backend'; volname = site+'_redis-data'
    # Helpers enforce their original exact synthetic volume naming prefix.
    net = None; volume_created = False; containers = []; client = None; uncertain = False
    try:
        with tempfile.TemporaryDirectory(prefix='uter-adapter-synthetic-') as tmp:
            PHASE='fixture-create'
            root=Path(tmp); root.chmod(0o755)
            home=root/'home'; home.mkdir(mode=0o700)
            runtime=home/'runtime';runtime.mkdir(mode=0o700)
            password=runtime/'redis-password';password.write_text(PASSWORD);password.chmod(0o644)
            config=runtime/'redis.conf'
            config.write_text('bind 0.0.0.0\nport 6379\nappendonly yes\nappendfsync always\ndir /data\nrequirepass '+PASSWORD+'\n')
            config.chmod(0o644)
            uncertain=True
            net=helpers.docker('network','create','--internal','--label',f'{LABEL}={owner}',
                               '--label',f'com.docker.compose.project={site}',
                               '--label','com.docker.compose.network=backend',netname)
            if not re.fullmatch(r'[0-9a-f]{64}',net): raise RuntimeError('network identifier invalid')
            uncertain=False
            uncertain=True
            if helpers.docker('volume','create','--label',f'{LABEL}={owner}',
                              '--label',f'com.docker.compose.project={site}',
                              '--label','com.docker.compose.volume=redis-data',volname)!=volname:
                raise RuntimeError('volume identifier invalid')
            volume_created=True;uncertain=False
            def start(*args):
                nonlocal uncertain
                uncertain=True
                ident=helpers.docker('run','-d','--label',f'{LABEL}={owner}',*args)
                if not re.fullmatch(r'[0-9a-f]{64}',ident): raise RuntimeError('container identifier invalid')
                containers.append(ident);uncertain=False
                return ident
            initial=start('--network','none','--user','0','--mount',f'type=volume,source={volname},target=/data',
                          common.PYTHON,'python','-c','import os,time;os.chmod("/data",0o777);time.sleep(600)')
            for _ in range(100):
                try:
                    if helpers.docker('exec',initial,'python','-c','import os;print(oct(os.stat("/data").st_mode & 0o777))')=='0o777': break
                except RuntimeError: pass
                time.sleep(.1)
            else: raise RuntimeError('synthetic volume not ready')
            helpers.cleanup('container',initial,owner);containers.remove(initial)
            redis=start('--network',netname,'--network-alias','redis','--restart','unless-stopped',
                        '--user','999:1000','--read-only','--tmpfs','/tmp:size=128m,mode=1777',
                        '--mount',f'type=volume,source={volname},target=/data',
                        '--mount',f'type=bind,source={password},target=/run/secrets/redis_password,readonly',
                        '--mount',f'type=bind,source={config},target=/usr/local/etc/redis/redis.conf,readonly',
                        IMAGE,'redis-server','/usr/local/etc/redis/redis.conf')
            for _ in range(100):
                try:
                    if helpers.docker('exec',redis,'redis-cli','-a',PASSWORD,'PING')=='PONG': break
                except RuntimeError: pass
                time.sleep(.1)
            else: raise RuntimeError('synthetic Redis not ready')
            details=diag._redis_inspect(redis)
            endpoint=details['networks'][netname]
            netinfo=json.loads(helpers.docker('network','inspect','--format','{{json .IPAM}}',net))
            config=netinfo['Config'][0]
            operation=plans.new_operation()
            plan={'schema':1,'operation':operation,'site':site,'container_id':redis,
                  'started_at':details['started'],'restart_count':details['restart_count'],'image_ref':IMAGE,
                  'image_config_id':details['image_id'],'restart_policy':'unless-stopped',
                  'volume_name':volname,'volume_driver':'local','network_id':net,'network_name':netname,
                  'network_driver':'bridge','network_scope':'local','network_internal':True,
                  'network_subnet':config['Subnet'],'network_gateway':config['Gateway'],
                  'endpoint_id':endpoint['EndpointID'],'endpoint_ipv4':endpoint['IPAddress'],
                  'endpoint_static_ipv4':None,'endpoint_aliases':endpoint['Aliases'],
                  'endpoint_mac':endpoint['MacAddress'].lower(),'ipv6_enabled':False,
                  'network_options':{},'endpoint_driver_options':{}}
            key=os.urandom(32)
            with uterctl.locked(home):
                PHASE='journal-create'
                digest=plans.create(home,plan,key)
                record=journal.create(home,backend='compose',site=site,resource=redis,
                                      plan_sha256=digest,operation=operation)
                class FixtureAdapter(fence.Adapter):
                    def _signed(self, supplied):
                        # NOT a signed-installation test. Still require the real lock.
                        self._lock()
                        if supplied != plan: raise RuntimeError('fixture plan changed')
                    def _verify_process(self, supplied):
                        try:
                            return super()._verify_process(supplied)
                        except fence.ComposeFenceAdapterError:
                            # Synthetic-only fixed diagnostics: never return process
                            # names, argv, environment, paths or Docker output.
                            code=("n=0; for f in /proc/[0-9]*/comm; do "
                                  "IFS= read -r name < \"$f\" || { printf COMM_UNREADABLE; exit 0; }; "
                                  "[ \"$name\" = redis-server ] || continue; n=$((n+1)); "
                                  "p=${f%/comm}; target=$(/bin/readlink \"$p/exe\" 2>/dev/null) "
                                  "|| { printf EXE_UNREADABLE; exit 0; }; "
                                  "[ \"$target\" = /usr/local/bin/redis-server ] "
                                  "|| { printf EXE_MISMATCH; exit 0; }; done; "
                                  "[ \"$n\" = 1 ] && printf PROCESS_MATCH || printf PROCESS_COUNT")
                            result=helpers.docker('exec','--user','999:1000',redis,'/bin/sh','-ec',code)
                            if result not in ('COMM_UNREADABLE','EXE_UNREADABLE','EXE_MISMATCH','PROCESS_MATCH','PROCESS_COUNT'):
                                result='DIAGNOSTIC_UNKNOWN'
                            print('Synthetic process check: '+result,flush=True)
                            raise
                adapter=FixtureAdapter(home,home/'unused',home/'unused',key)
                PHASE='reject-shared-namespace'
                # A container sharing the Redis netns must prevent any mutation.
                peer=start('--network','container:'+redis,common.PYTHON,'python','-c','import time;time.sleep(600)')
                try: adapter._peers(plan)
                except fence.ComposeFenceAdapterError as error:
                    if str(error) != 'COMPOSE_FENCE_SHARED_NAMESPACE': raise
                else: raise RuntimeError('shared network namespace was accepted')
                helpers.cleanup('container',peer,owner);containers.remove(peer)
                PHASE='active-client'
                client=subprocess.Popen(['sudo','-n','-u','nobody','python3','-u','-c',helpers.CLIENT,endpoint['IPAddress']],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
                sel=selectors.DefaultSelector();sel.register(client.stdout,selectors.EVENT_READ)
                if not sel.select(15) or client.stdout.readline().strip()!='READY': raise RuntimeError('fixture client did not connect')
                PHASE='isolate'
                protocol.isolate(home,record['operation'],adapter)
                if journal.read(home)['phase']!='isolated' or adapter.verify_isolated(record) is not True:
                    raise RuntimeError('synthetic isolation was not confirmed')
                if helpers.docker('exec',redis,'sh','-ec',
                    'export REDISCLI_AUTH="$(cat /run/secrets/redis_password)"; redis-cli --raw GET synthetic:old')!='1':
                    raise RuntimeError('synthetic pre-fence write changed')
                if adapter.verify_old_restoration_safe(record) is not False:
                    raise RuntimeError('unsupported restoration was accepted')
                PHASE='failed-capture'
                # Inject a failed snapshot after isolation. The journal must
                # retain uncertainty and no production restore is authorized.
                def broken_capture(): raise RuntimeError('synthetic snapshot error')
                try: protocol.capture(home,record['operation'],adapter,broken_capture)
                except protocol.ComposeFenceProtocolError as error:
                    if str(error) != 'COMPOSE_FENCE_CAPTURE_INCOMPLETE': raise
                else: raise RuntimeError('synthetic capture failure was accepted')
                if journal.read(home)['phase'] != 'capturing' or adapter.verify_old_restoration_safe(record) is not False:
                    raise RuntimeError('synthetic failed capture unexpectedly allowed recovery')
                PHASE='competing-dynamic-ip'
                # Synthetic-only experiment: occupy Redis' old dynamic IP with
                # another labelled container before manually reattaching. This
                # does NOT call adapter recovery or authorize production use.
                other=start('--network',netname,common.PYTHON,'python','-c','import time;time.sleep(600)')
                other_ip=helpers.docker('inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',other)
                if other_ip != endpoint['IPAddress']:
                    raise RuntimeError('synthetic competitor did not occupy original address')
                try:
                    helpers.docker('network','connect','--ip',endpoint['IPAddress'],net,redis)
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError('address conflict was incorrectly accepted')
                if diag._redis_inspect(redis)['networks']:
                    raise RuntimeError('failed synthetic connection unexpectedly changed Redis network')
                PHASE='synthetic-conflict-reconnect'
                # Reconnect without --ip in this synthetic test only and verify
                # that Docker allocated a DIFFERENT address while it is occupied.
                network_args=['network','connect']
                for alias in plan['endpoint_aliases']: network_args += ['--alias',alias]
                helpers.docker(*network_args,net,redis)
                changed=diag._redis_inspect(redis)['networks'][netname]
                if changed['IPAddress'] == endpoint['IPAddress']:
                    raise RuntimeError('conflicting synthetic address was reused')
                if helpers.docker('exec',redis,'sh','-ec',
                    'export REDISCLI_AUTH="$(cat /run/secrets/redis_password)"; redis-cli --raw GET synthetic:old')!='1':
                    raise RuntimeError('synthetic data changed after conflicting reconnect')
                PHASE='synthetic-endpoint-recreate'
                # Remove the competitor, then try to restore the original
                # endpoint. The outcome is reported as a fixture observation,
                # not a guarantee for any other Docker daemon or network.
                helpers.docker('network','disconnect',net,redis)
                helpers.cleanup('container',other,owner);containers.remove(other)
                helpers.docker(*network_args,net,redis)
                restored=diag._redis_inspect(redis)['networks'][netname]
                changed_ip=restored['IPAddress'] != endpoint['IPAddress']
                changed_aliases=set(restored.get('Aliases') or []) != set(endpoint.get('Aliases') or [])
                changed_mac=(restored.get('MacAddress') or '').lower() != plan['endpoint_mac']
                if changed_ip or changed_aliases or changed_mac:
                    # A mismatch is an expected, correctly blocked result. Do
                    # not report restoration as successful or resume writers.
                    try: adapter._state(plan,detached=False,restart='no')
                    except fence.ComposeFenceAdapterError as error:
                        if str(error) != 'COMPOSE_FENCE_NETWORK_CHANGED': raise
                    else: raise RuntimeError('mismatched synthetic endpoint was accepted')
                    print('Synthetic endpoint mismatch was blocked; IP changed: '+str(changed_ip)
                          +'; aliases changed: '+str(changed_aliases)+'; MAC changed: '+str(changed_mac),flush=True)
                else:
                    adapter._state(plan,detached=False,restart='no')
                    print('Synthetic endpoint happened to match; production recovery still blocked.',flush=True)
                if adapter.verify_old_restoration_safe(record) is not False or journal.read(home)['phase']!='capturing':
                    raise RuntimeError('synthetic recovery was incorrectly authorized')
                if helpers.docker('exec',redis,'sh','-ec',
                    'export REDISCLI_AUTH="$(cat /run/secrets/redis_password)"; redis-cli --raw GET synthetic:old')!='1':
                    raise RuntimeError('synthetic data changed after endpoint restoration')
    finally:
        if client is not None:
            try: os.killpg(client.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            client.wait(timeout=5)
        errors=[]
        for item in reversed(containers):
            try: helpers.cleanup('container',item,owner)
            except Exception: errors.append('container')
        if net:
            try: helpers.cleanup('network',net,owner)
            except Exception: errors.append('network')
        if volume_created:
            try:
                label=helpers.docker('volume','inspect','--format','{{index .Labels "'+LABEL+'"}}',volname)
                if label != owner or volname != site+'_redis-data': raise RuntimeError('volume ownership mismatch')
                helpers.docker('volume','rm',volname)
            except Exception: errors.append('volume')
        if uncertain: errors.append('unknown resource')
        if errors: raise RuntimeError('synthetic cleanup unconfirmed: '+', '.join(errors))
    print('Synthetic isolation, failed capture and conflicting dynamic address checks passed; no production restore was performed.')


if __name__ == '__main__':
    try: main()
    except RuntimeError as error:
        # RuntimeError messages here are fixed synthetic categories only.
        raise SystemExit('Synthetic Compose adapter test failed at '+PHASE+': '+str(error))
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        raise SystemExit('Synthetic Compose adapter test failed at '+PHASE+': '+type(error).__name__)
