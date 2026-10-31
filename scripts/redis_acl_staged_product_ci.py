"""Disposable real Uter + staged Redis ACL experiment, not a production fence."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
import tempfile
import time
import urllib.parse
import urllib.error
import urllib.request

from scripts import (maintenance_compose_product_ci as product, maintenance_protocol, maintenance_transport,
                     redis_acl_durable, redis_acl_experiment_ci, redis_acl_staged,
                     redis_acl_staged_ci, redis_fence_journal)


class ProductStageError(ValueError):pass


def _redis_backend_address(network,network_id,address,project):
    if (not isinstance(network,dict) or network.get('Id')!=network_id or network.get('Name')!=project+'_backend'
            or network.get('Driver')!='bridge' or network.get('Internal') is not True):raise ValueError
    try:
        ip=ipaddress.IPv4Address(address)
        configs=network['IPAM']['Config']
        if not isinstance(configs,list) or not configs or len(configs)>8:raise ValueError
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:raise ValueError
        matches=[]
        for item in configs:
            if not isinstance(item,dict):raise ValueError
            if 'Subnet' not in item:continue
            subnet=ipaddress.ip_network(item['Subnet'],strict=True)
            if subnet.version==4 and ip in subnet:
                gateway=ipaddress.IPv4Address(item['Gateway'])
                if gateway not in subnet or ip in (subnet.network_address,subnet.broadcast_address,gateway):raise ValueError
                matches.append(subnet)
        if len(matches)!=1:raise ValueError
    except (KeyError,TypeError,ValueError):raise ValueError('REDIS_BACKEND_UNVERIFIED') from None
    return str(ip)


def _guardrail_auth_denied(entries,address):
    if not isinstance(entries,list) or len(entries)>100:raise ValueError
    for entry in entries:
        if not isinstance(entry,list) or len(entry)%2:raise ValueError
        keys=entry[::2]
        if any(not isinstance(key,str) for key in keys) or len(keys)!=len(set(keys)):raise ValueError
        fields=dict(zip(keys,entry[1::2]));info=fields.get('client-info')
        if fields.get('reason')!='auth' or fields.get('username')!='uter-writer' or not isinstance(info,str):continue
        parts=[token.split('=',1) for token in info.split() if '=' in token]
        if len(parts)!=len({item[0] for item in parts}):raise ValueError
        observed=dict(parts).get('addr','').rsplit(':',1)[0]
        if observed==address:return True
    return False


def exercise(home,project,admin_password,acl_admin_password,writer_password,acl_dir):
    """Run only on the one-use CI project created by image_integration.py."""
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'
            or os.environ.get('RUNNER_OS')!='Linux' or os.environ.get('UTER_CI_STAGED_PRODUCT')!='true'
            or os.geteuid()!=0 or not re.fullmatch(r'uter-acl-[0-9a-f]{32}',project)):
        raise ProductStageError('STAGED_PRODUCT_ENVIRONMENT_UNVERIFIED')
    scenario=os.environ.get('UTER_CI_STAGED_SCENARIO')
    if scenario not in ('drain','restart'):
        raise ProductStageError('STAGED_PRODUCT_ENVIRONMENT_UNVERIFIED')
    home=Path(home).resolve(strict=True)
    if home!=(Path(__file__).resolve().parents[1]/'work/integration').resolve(strict=True):
        raise ProductStageError('STAGED_PRODUCT_ENVIRONMENT_UNVERIFIED')
    signals=home/'staged-signals';acl_dir=Path(acl_dir)
    if (not acl_dir.is_absolute() or acl_dir.name!='acl'
            or acl_dir.parent.parent!=Path(tempfile.gettempdir()).absolute()
            or not re.fullmatch(r'uter-product-acl-[a-z0-9_]{8}',acl_dir.parent.name)):
        raise ProductStageError('STAGED_PRODUCT_ENVIRONMENT_UNVERIFIED')
    directory,_=redis_acl_durable._directory(acl_dir);os.close(directory)
    profile_home=acl_dir.parent/'staged-profile';profile_home.mkdir(mode=0o700)
    profile,publisher=redis_acl_staged_ci.make_fixture_profile(profile_home)
    state={'clients':[],'threads':[],'result':None,'watcher':None,'session':None,'recorder':None,'pinned':None,'phase':'INITIAL'}
    def request(path,payload=None,token=None,form=False):
        headers={};data=None
        if token:headers['Authorization']='Bearer '+token
        if payload is not None:
            data=(urllib.parse.urlencode(payload) if form else json.dumps(payload)).encode()
            headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json'
        with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:18000'+path,data=data,headers=headers),timeout=70) as response:
            raw=response.read(1048577)
            if len(raw)>1048576:raise ValueError
            return response.status,json.loads(raw)
    def complete_request(token):
        try:
            status,body=request('/chat',{'message':'What does TechCorp do? fixture-staged-drain',
                                        'user_id':'staged-fixture'},token=token)
            state['result']=(status,isinstance(body,dict) and body.get('blocked') is False)
        except urllib.error.HTTPError as exc:
            state['result']=('HTTP_'+str(exc.code) if exc.code in (400,401,403,404,429,500,503) else 'HTTP_OTHER',False)
        except Exception:state['result']=('REQUEST_ERROR',False)
    def before(recorder,pinned,stable):
        state['phase']='PIN'
        state.update(recorder=recorder,pinned=pinned)
        def backend(ident):
            networks=json.loads(product._docker('inspect','--format','{{json .NetworkSettings.Networks}}',ident))
            if not isinstance(networks,dict) or not isinstance(networks.get(project+'_backend'),dict):raise ValueError
            value=networks[project+'_backend'];address=value.get('IPAddress');network_id=value.get('NetworkID')
            if (not isinstance(address,str) or str(ipaddress.IPv4Address(address))!=address
                    or not isinstance(network_id,str) or not re.fullmatch(r'[0-9a-f]{64}',network_id)):raise ValueError
            return address,network_id
        guardrail_address,network_id=backend(pinned['guardrail']['id'])
        redis_address,redis_network=backend(pinned['redis']['id'])
        if redis_network!=network_id:raise ValueError
        state['phase']='REDIS_NETWORK'
        network=json.loads(product._docker('network','inspect','--format','{{json .}}',network_id))
        redis_address=_redis_backend_address(network,network_id,redis_address,project)
        if not stable() or backend(pinned['redis']['id'])!=(redis_address,network_id):raise ValueError
        state.update(guardrail_address=guardrail_address,network_id=network_id,backend=backend)
        ports=json.loads(product._docker('inspect','--format','{{json .NetworkSettings.Ports}}',pinned['guardrail']['id']))
        if (not isinstance(ports,dict) or ports.get('8000/tcp')!=[{'HostIp':'127.0.0.1','HostPort':'18000'}]
                or not stable()):raise ValueError
        state['phase']='LOGIN_HTTP'
        try:status,login=request('/auth/token',{'username':'admin','password':admin_password},form=True)
        except urllib.error.HTTPError as exc:
            state['phase']='LOGIN_HTTP_'+str(exc.code) if exc.code in (400,401,403,404,429,500,503) else 'LOGIN_HTTP_OTHER'
            raise
        state['phase']='LOGIN_RESPONSE'
        if status!=200 or not isinstance(login,dict) or not isinstance(login.get('access_token'),str):raise ValueError
        state['phase']='LOGIN_RECHECK'
        try:unchanged=stable()
        except product.ProbeError as exc:
            code=str(exc)
            state['phase']='LOGIN_RECHECK_'+code if code in ('MAINTENANCE_CI_IDENTITY_UNVERIFIED',
                'MAINTENANCE_CI_IMAGE_UNVERIFIED','MAINTENANCE_CI_INSPECT_UNVERIFIED') else 'LOGIN_RECHECK_QUERY'
            raise
        except Exception:
            state['phase']='LOGIN_RECHECK_QUERY';raise
        if not unchanged:
            candidate='LOGIN_RECHECK_'+getattr(stable,'changed','OTHER')
            state['phase']=candidate
            raise ValueError
        request_thread=threading.Thread(target=complete_request,args=(login['access_token'],),daemon=True)
        state['threads'].append(request_thread)
        redis_id=pinned['redis']['id']
        state['phase']='REDIS_ADMIN_AUTH';admin=redis_acl_experiment_ci.Client(6379,host=redis_address);state['clients'].append(admin)
        if redis_acl_staged_ci.auth(admin,'uter-maint-test',acl_admin_password) is not True:raise ValueError
        if not stable() or backend(redis_id)!=(redis_address,network_id):raise ValueError
        state['phase']='REDIS_WRITER_AUTH';writer=redis_acl_experiment_ci.Client(6379,host=redis_address);state['clients'].append(writer)
        if redis_acl_staged_ci.auth(writer,'uter-writer',writer_password) is not True:raise ValueError
        if not stable() or backend(redis_id)!=(redis_address,network_id):raise ValueError
        state['phase']='ACCEPT_REQUEST';request_thread.start();deadline=time.monotonic()+40
        while not (signals/'entered').exists():
            if not request_thread.is_alive():
                result=state['result']
                if isinstance(result,tuple) and result[0] in ('HTTP_400','HTTP_401','HTTP_403','HTTP_404',
                    'HTTP_429','HTTP_500','HTTP_503','HTTP_OTHER','REQUEST_ERROR'):
                    state['phase']='ACCEPT_'+result[0]
                elif result==(200,True):state['phase']='ACCEPT_EARLY_ALLOWED'
                elif result==(200,False):state['phase']='ACCEPT_EARLY_BLOCKED'
                else:state['phase']='ACCEPT_ENDED'
                raise ValueError
            if time.monotonic()>=deadline:state['phase']='ACCEPT_TIMEOUT';raise ValueError
            time.sleep(.05)
        state['phase']='ACCEPT_STABILITY'
        if not request_thread.is_alive() or not stable():raise ValueError
        state['phase']='REDIS_CONFIG'
        if admin.call('CONFIG','GET','aclfile')!=['aclfile','/acl/users.acl']:raise ValueError
        state['phase']='REDIS_MOUNT'
        info=json.loads(product._docker('inspect','--format','{{json .Mounts}}',redis_id))
        mounts=[x for x in info if x.get('Destination')=='/acl']
        if (len(mounts)!=1 or mounts[0].get('Type')!='bind' or mounts[0].get('RW') is not False
                or mounts[0].get('Source')!=str(acl_dir)):raise ValueError
        run_id=next(line.split(':',1)[1] for line in admin.call('INFO','SERVER').splitlines() if line.startswith('run_id:'))
        client_id=str(admin.call('CLIENT','ID'))
        journal=redis_fence_journal.read(recorder.home)
        def record(kind,stage,digest=None):
            name='redis-staged-'+kind+'-'+stage+'.json'
            value={'schema':1,'kind':kind,'stage':stage,'operation':recorder.operation,
                   'site':journal['site'],'resource':journal['resource'],'plan_sha256':recorder.plan}
            if digest is not None:value['version_sha256']=digest
            recorder._write(name,value)
            return recorder._read(name)==value
        durable=redis_acl_durable.DurablePrepare(bundle=profile,publisher=publisher,directory=acl_dir,
            admin_user='uter-maint-test',writer_hash=hashlib.sha256(writer_password.encode()).hexdigest(),
            admin_hash=hashlib.sha256(acl_admin_password.encode()).hexdigest(),lock_guard=stable,
            record_intent=lambda stage:record('intent',stage),record_receipt=lambda stage,digest:record('receipt',stage,digest))
        session=redis_acl_staged.StagedAdmission(admin.call,bundle=profile,publisher=publisher,
            admin_user='uter-maint-test',run_id=run_id,client_id=client_id,identity_guard=stable,
            record_intent=lambda stage:record('intent',stage),record_receipt=lambda stage:record('receipt',stage),
            durable_prepare=durable)
        state.update(session=session,admin=admin,writer=writer,run_id=run_id)
        state['phase']='ACL_OFF';outcome=session.disable_new_auth()
        if (outcome['host_acl_file_verified'] is not True or outcome['prior_writer_connections_retained']<1
                or not request_thread.is_alive() or writer.call('SET','ci-staged-before-drain','ok')!='OK'):
            raise ValueError
        state['phase']='NEW_AUTH';fresh=redis_acl_experiment_ci.Client(6379,host=redis_address);state['clients'].append(fresh)
        if redis_acl_staged_ci.auth(fresh,'uter-writer',writer_password) is not False:raise ValueError
        fresh.close();state['clients'].remove(fresh)
        # Redis must process the closed unauthorized socket before client inventory.
        for attempt in range(100):
            try:
                redis_acl_staged._clients(admin.call('CLIENT','LIST'),'uter-maint-test',client_id,only_admin=False)
                break
            except ValueError:
                if attempt==99:raise
                time.sleep(.05)
        def release_when_draining():
            try:
                deadline=time.monotonic()+45
                while time.monotonic()<deadline:
                    for service in ('agent','guardrail'):
                        status,raw=maintenance_transport.request(service=service,method='GET',
                            container_id=pinned[service]['id'],identity_guard=stable)
                        result=maintenance_protocol._parse(raw)
                        if status==202 and result['state']=='draining' and result['active_requests']>=1:
                            if not request_thread.is_alive():raise ValueError
                            state['watcher']='observed-draining';return
                    time.sleep(.1)
                raise ValueError
            except Exception:state['watcher']='error'
            finally:(signals/'release').write_text('release',encoding='ascii')
        state['phase']='DRAIN';watcher=threading.Thread(target=release_when_draining,daemon=True)
        state['threads'].append(watcher);watcher.start()

    def after(recorder,pinned,result,stable):
        state['phase']='RECEIPTS'
        for thread in state['threads']:thread.join(timeout=60)
        if any(thread.is_alive() for thread in state['threads']) or state['watcher']!='observed-draining':raise ValueError
        if state['result']!=(200,True):raise ValueError
        journal=redis_fence_journal.read(recorder.home)
        def drain_guard():
            if not stable():return False
            for service in ('agent','guardrail'):
                instance=pinned[service]['id'];receipt=result[instance]
                if recorder.read_receipt(service,instance,receipt['boot_id'],site=journal['site'],
                                         resource=journal['resource'])!=receipt:return False
            return True
        if scenario=='restart':
            state['phase']='RESTART'
            admin=state['admin']
            if admin.call('ACL','LOG','RESET')!='OK':raise ValueError
            before=json.loads(product._docker('inspect','--format',
                '{"started":{{json .State.StartedAt}},"restarts":{{json .RestartCount}}}',pinned['guardrail']['id']))
            product._docker('restart','--time','5',pinned['guardrail']['id'])
            after_restart=json.loads(product._docker('inspect','--format',
                '{"started":{{json .State.StartedAt}},"restarts":{{json .RestartCount}}}',pinned['guardrail']['id']))
            if (after_restart==before or state['backend'](pinned['guardrail']['id'])
                    !=(state['guardrail_address'],state['network_id'])):raise ValueError
            state['phase']='RESTART_AUTH_LOG';deadline=time.monotonic()+120;auth_denied=False
            while time.monotonic()<deadline:
                entries=admin.call('ACL','LOG','100')
                auth_denied=_guardrail_auth_denied(entries,state['guardrail_address'])
                if auth_denied:break
                time.sleep(.25)
            if not auth_denied:raise ValueError
            # The old receipts belong to the pre-restart process. They must
            # never authorize KILL after the Guardrail identity changes.
            try:state['session'].finish_after_drain(drain_guard)
            except redis_acl_staged.StagedError:pass
            else:raise ValueError
            if state['session'].phase!='uncertain':raise ValueError
            if (recorder.home/'redis-staged-intent-kill-writer-clients.json').exists():raise ValueError
            if state['writer'].call('PING')!='PONG':raise ValueError
            state['result']='restart-rejected';return
        state['phase']='KILL';outcome=state['session'].finish_after_drain(drain_guard)
        if outcome['writer_clients_killed']<1 or outcome['safe_to_update'] is not False:raise ValueError
        state['result']='drain-and-kill-verified'

    passed=False
    try:
        product.exercise(home,project=project,before_collect=before,after_collect=after)
        if state['result']!=('restart-rejected' if scenario=='restart' else 'drain-and-kill-verified'):raise ValueError
        passed=True
    except Exception:
        allowed={'INITIAL','PIN','LOGIN_HTTP','LOGIN_HTTP_OTHER','LOGIN_RESPONSE','LOGIN_RECHECK',
                 'LOGIN_HTTP_400','LOGIN_HTTP_401','LOGIN_HTTP_403','LOGIN_HTTP_404','LOGIN_HTTP_429',
                 'LOGIN_HTTP_500','LOGIN_HTTP_503','REDIS_NETWORK',
                 'REDIS_ADMIN_AUTH','REDIS_WRITER_AUTH',
                 'ACCEPT_REQUEST','ACCEPT_ENDED','ACCEPT_EARLY_ALLOWED','ACCEPT_EARLY_BLOCKED',
                 'ACCEPT_TIMEOUT','ACCEPT_STABILITY',
                 'REDIS_CONFIG','REDIS_MOUNT','ACL_OFF','NEW_AUTH','DRAIN','RECEIPTS',
                 'RESTART','RESTART_AUTH_LOG','KILL'}
        allowed|={'ACCEPT_'+code for code in ('HTTP_400','HTTP_401','HTTP_403','HTTP_404',
                  'HTTP_429','HTTP_500','HTTP_503','HTTP_OTHER','REQUEST_ERROR')}
        allowed|={'LOGIN_RECHECK_'+service+'_'+field for service in ('AGENT','GUARDRAIL','REDIS')
                  for field in ('ID','IMAGE','RUNNING','STARTED','RESTARTS','PROJECT','SERVICE')}
        allowed|={'LOGIN_RECHECK_QUERY','LOGIN_RECHECK_MAINTENANCE_CI_IDENTITY_UNVERIFIED',
                  'LOGIN_RECHECK_MAINTENANCE_CI_IMAGE_UNVERIFIED','LOGIN_RECHECK_MAINTENANCE_CI_INSPECT_UNVERIFIED'}
        try:
            (home.parent/'integration-evidence'/('staged-product-'+scenario+'-failure.txt')).write_text(
                (state['phase'] if state['phase'] in allowed else 'UNKNOWN')+'\n',encoding='ascii')
        except Exception:pass
        raise ProductStageError('STAGED_PRODUCT_DRAIN_UNVERIFIED') from None
    finally:
        failed=False
        try:(signals/'release').write_text('release',encoding='ascii')
        except Exception:failed=True
        for thread in state['threads']:
            try:
                if thread.ident is not None:thread.join(timeout=60)
            except Exception:failed=True
        if any(thread.is_alive() for thread in state['threads']):failed=True
        for client in state['clients']:
            for item in (client.file,client.sock):
                try:item.close()
                except Exception:failed=True
        if failed:raise ProductStageError('STAGED_PRODUCT_CLEANUP_UNVERIFIED')
    if passed:
        evidence=home.parent/'integration-evidence'/('staged-product-'+scenario+'.txt')
        evidence.write_text('Actual Uter image fixture: '+scenario+' assertions passed.\n'
            'Profile signature and lock are synthetic; ingress/Redis production fencing, audit recovery and update are not established.\n',encoding='ascii')
        print('STAGED_PRODUCT_'+scenario.upper()+'_CI_PASS: fixture ingress; no production fence or update verified')
