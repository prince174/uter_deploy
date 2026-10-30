"""Narrow Compose fence start; host, Docker and privileged controllers trusted.

Caller must hold the installation O_EXCL lock and verify the signed executor.
The durable authenticated intent and fence journal precede writer stop; an
uncertain result leaves all evidence and never restarts writers. This module
does not capture, migrate, restore writers, or authorize an update.
"""
import hashlib
import hmac
import json
import os
from contextlib import contextmanager
from pathlib import Path
import re
import stat

import uterctl
from scripts import (backup_crypto, compose_fence_recovery_plan as plans,
                     compose_nsfirewall_adapter as fence, compose_nsfirewall_protocol as protocol,
                     compose_redis_diagnostic as diagnostic, install, redis_fence_journal as journal)

NAME='compose-fence-start-intent.json'


class StartError(ValueError): pass


_OBSERVE_DIAGNOSTIC_CODES=frozenset(('COMPOSE_DIAGNOSTIC_DAEMON_INVALID','COMPOSE_DIAGNOSTIC_DATA_VOLUME_INVALID',
    'COMPOSE_DIAGNOSTIC_FAILED','COMPOSE_DIAGNOSTIC_IDENTITY_INVALID','COMPOSE_DIAGNOSTIC_IMAGE_CHANGED',
    'COMPOSE_DIAGNOSTIC_INSTALLED_BUNDLE_MISMATCH','COMPOSE_DIAGNOSTIC_NETWORK_INVALID',
    'COMPOSE_DIAGNOSTIC_QUERY_FAILED','COMPOSE_DIAGNOSTIC_REDIS_INVALID','COMPOSE_DIAGNOSTIC_RESPONSE_INVALID',
    'COMPOSE_DIAGNOSTIC_STATE_CHANGED','COMPOSE_DIAGNOSTIC_VOLUME_INVALID')) | frozenset(
    'COMPOSE_DIAGNOSTIC_STATE_CHANGED_'+suffix for suffix in (
        'PROCESS','IMAGE','SECURITY','MOUNTS','MOUNTS_ORDER','MOUNTS_CONTENT','NETWORK_MODE','PORTS','NETWORK_SET','NETWORK_FIELDS',
        'NETWORK_ID','ENDPOINT_ID','ENDPOINT_ADDRESS','ENDPOINT_GATEWAY','ENDPOINT_MAC','ENDPOINT_IPAM',
        'ENDPOINT_OPTIONS','ENDPOINT_IPV6','ALIASES_ORDER','ALIASES_CONTENT','DNSNAMES_ORDER',
        'DNSNAMES_CONTENT','NETWORK_OTHER','OTHER'))
_OBSERVE_ADAPTER_CODES=frozenset(('COMPOSE_FENCE_AOF_UNHEALTHY','COMPOSE_FENCE_CONFIG_UNSUPPORTED',
    'COMPOSE_FENCE_DOCKER_UNCERTAIN','COMPOSE_FENCE_EXECUTABLE_UNVERIFIED','COMPOSE_FENCE_IDENTITY_INVALID',
    'COMPOSE_FENCE_INSPECTION_FAILED','COMPOSE_FENCE_LOCK_INVALID','COMPOSE_FENCE_MODULES_UNSUPPORTED',
    'COMPOSE_FENCE_MOUNTS_UNSUPPORTED','COMPOSE_FENCE_NETWORK_CHANGED','COMPOSE_FENCE_PEERS_UNKNOWN',
    'COMPOSE_FENCE_PLAN_INVALID','COMPOSE_FENCE_REDIS_CHANGED','COMPOSE_FENCE_REPLICATION_UNSUPPORTED',
    'COMPOSE_FENCE_SHARED_NAMESPACE','COMPOSE_FENCE_SHARED_VOLUME','COMPOSE_FENCE_UNIX_SOCKET_UNSUPPORTED',
    'COMPOSE_FENCE_VOLUME_CHANGED'))


@contextmanager
def _observe_stage(stage):
    """Emit only a fixed category, never exception contents or external output."""
    try:yield
    except StartError:raise
    except Exception as error:
        code='ERROR'
        if isinstance(error,diagnostic.ComposeDiagnosticError) and str(error) in _OBSERVE_DIAGNOSTIC_CODES:
            code=str(error)
        elif isinstance(error,fence.compose.ComposeFenceAdapterError) and str(error) in _OBSERVE_ADAPTER_CODES:
            code=str(error)
        elif isinstance(error,KeyError):code='KEY_ERROR'
        elif isinstance(error,TypeError):code='TYPE_ERROR'
        raise StartError('FENCE_START_OBSERVE_'+stage+'_'+code) from None


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def _changed_class(before,after,groups,prefix):
    """Report only fixed field classes, never field values or external output."""
    if not isinstance(before,dict) or not isinstance(after,dict):return prefix+'_OTHER'
    for label,fields in groups:
        if any(before.get(name)!=after.get(name) for name in fields):return prefix+'_'+label
    return prefix+'_OTHER'


def _redis_change(before,after):
    return _changed_class(before,after,(('PROCESS',('id','running','pid','started','restart_count','restart')),
        ('IMAGE',('image','image_id')),('NETWORK',('network_mode','ports','publish_all','runtime_ports','networks')),
        ('VOLUME',('mounts',))), 'FENCE_START_OBSERVE_REDIS')


def _plan_change(before,after):
    return _changed_class(before,after,(('PROCESS',('container_id','started_at','restart_count','restart_policy')),
        ('IMAGE',('image_ref','image_config_id')),
        ('NETWORK_ID',('network_id','network_name')),
        ('NETWORK_POLICY',('network_driver','network_scope','network_internal','ipv6_enabled','network_options')),
        ('IPAM',('network_subnet','network_gateway')),
        ('ENDPOINT_ID',('endpoint_id',)),('ENDPOINT_ADDRESS',('endpoint_ipv4','endpoint_static_ipv4')),
        ('ENDPOINT_ALIASES',('endpoint_aliases',)),('ENDPOINT_MAC',('endpoint_mac',)),
        ('ENDPOINT_OPTIONS',('endpoint_driver_options',)),
        ('VOLUME',('volume_name','volume_driver'))), 'FENCE_START_RECHECK_PLAN')


def _writers_change(before,after,prefix):
    if not isinstance(before,dict) or not isinstance(after,dict):return prefix+'_OTHER'
    for label,fields in (('IDENTITY',('id','image_ref','image_id')),('STARTED',('started',)),
                         ('RESTART',('restart_count',))):
        for service in ('guardrail','agent'):
            left,right=before.get(service),after.get(service)
            if not isinstance(left,dict) or not isinstance(right,dict):return prefix+'_OTHER'
            if any(left.get(field)!=right.get(field) for field in fields):return prefix+'_'+label
    return prefix+'_OTHER'


def _validate_intent(record):
    if (not isinstance(record,dict)
            or set(record)!={'schema','operation','site','redis','guardrail','agent','plan_sha256','bundle_sha256'}
            or type(record['schema']) is not int or record['schema']!=1
            or not isinstance(record['operation'],str) or not isinstance(record['site'],str)
            or not re.fullmatch(r'[0-9a-f]{32}',record['operation'])
            or not re.fullmatch(r'[a-z][a-z0-9-]{0,40}',record['site'])
            or any(not isinstance(record[k],str) or not re.fullmatch(r'[0-9a-f]{64}',record[k])
                   for k in ('redis','plan_sha256','bundle_sha256'))):
        raise StartError('FENCE_START_INTENT_INVALID')
    for service in ('guardrail','agent'):
        writer=record[service]
        if (not isinstance(writer,dict) or set(writer)!={'id','started','restart_count','image_ref','image_id'}
                or not isinstance(writer['id'],str) or not re.fullmatch(r'[0-9a-f]{64}',writer['id'])
                or not isinstance(writer['started'],str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',writer['started'])
                or type(writer['restart_count']) is not int or writer['restart_count']<0
                or not isinstance(writer['image_ref'],str) or not uterctl.IMAGE.fullmatch(writer['image_ref'])
                or not isinstance(writer['image_id'],str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',writer['image_id'])):
            raise StartError('FENCE_START_INTENT_INVALID')
    if len({record['redis'],record['guardrail']['id'],record['agent']['id']})!=3:
        raise StartError('FENCE_START_INTENT_INVALID')
    return record


def _write_intent(home,record,key):
    """Write-once intent, with exact writer identities, before any stop call."""
    if not isinstance(key,bytes) or len(key)!=32:raise StartError('FENCE_START_INTENT_INVALID')
    _validate_intent(record)
    derived=backup_crypto.derive_key(key,b'compose-fence-start-intent-v1')
    raw=_canonical({'intent':record,'mac':hmac.new(derived,_canonical(record),hashlib.sha256).hexdigest()})+b'\n'
    directory=journal._directory(home)
    try:
        try:
            fd=os.open(NAME,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as target:
                os.fchmod(target.fileno(),0o600);target.write(raw);target.flush();os.fsync(target.fileno())
            os.fsync(directory)
        except OSError:raise StartError('FENCE_START_INTENT_UNCERTAIN') from None
    finally:os.close(directory)


def read_intent(home,key,record,bundle_hash):
    """Authenticate a bounded intent and bind it to the journal and bundle."""
    if not isinstance(key,bytes) or len(key)!=32:raise StartError('FENCE_START_INTENT_INVALID')
    directory=journal._directory(home)
    try:
        try:
            fd=os.open(NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            with os.fdopen(fd,'rb') as source:
                info=os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077
                        or info.st_nlink!=1 or info.st_size>8192):raise ValueError
                raw=source.read(8193)
            if len(raw)>8192:raise ValueError
            def pairs(items):
                result={}
                for name,value in items:
                    if name in result:raise ValueError
                    result[name]=value
                return result
            envelope=json.loads(raw,object_pairs_hook=pairs)
            if not isinstance(envelope,dict) or set(envelope)!={'intent','mac'}:raise ValueError
            intent=_validate_intent(envelope['intent']);mac=envelope['mac']
            derived=backup_crypto.derive_key(key,b'compose-fence-start-intent-v1')
            expected=hmac.new(derived,_canonical(intent),hashlib.sha256).hexdigest()
            if (not isinstance(mac,str) or not re.fullmatch(r'[0-9a-f]{64}',mac)
                    or not hmac.compare_digest(mac,expected)
                    or intent['operation']!=record['operation'] or intent['site']!=record['site']
                    or intent['redis']!=record['resource'] or intent['plan_sha256']!=record['plan_sha256']
                    or intent['bundle_sha256']!=bundle_hash):raise ValueError
            return intent
        except (OSError,ValueError,KeyError,TypeError,UnicodeError):
            raise StartError('FENCE_START_INTENT_UNVERIFIED') from None
    finally:os.close(directory)


def _writers(command,env,site,manifest):
    """Bind each exact running container ID to signed image, label and project."""
    ids={}
    for service in ('guardrail','agent'):
        short=diagnostic._read(command+['ps','-q',service],env).strip()
        if not re.fullmatch(r'[0-9a-f]{12,64}',short):raise StartError('FENCE_START_WRITER_UNVERIFIED')
        ident=diagnostic._json(diagnostic._docker('inspect','--format','{{json .Id}}',short))
        if not isinstance(ident,str) or not re.fullmatch(r'[0-9a-f]{64}',ident):
            raise StartError('FENCE_START_WRITER_UNVERIFIED')
        fmt=('{"running":{{json .State.Running}},"started":{{json .State.StartedAt}},"restart_count":{{json .RestartCount}},'
             '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
             '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
             '"image_ref":{{json .Config.Image}},"image_id":{{json .Image}}}')
        details=diagnostic._json(diagnostic._docker('inspect','--format',fmt,ident))
        reference=manifest['images'][service]
        local=diagnostic._json(diagnostic._docker('image','inspect','--format','{{json .Id}}',reference))
        if (not isinstance(details,dict) or details.get('running') is not True or details.get('project')!=site
                or details.get('service')!=service or details.get('image_ref')!=reference or details.get('image_id')!=local
                or not isinstance(details.get('started'),str)
                or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',details['started'])
                or type(details.get('restart_count')) is not int or details['restart_count']<0
                or not isinstance(local,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',local)):
            raise StartError('FENCE_START_WRITER_UNVERIFIED')
        ids[service]={'id':ident,'started':details['started'],'restart_count':details['restart_count'],
                      'image_ref':reference,'image_id':local}
    if ids['guardrail']['id']==ids['agent']['id']:raise StartError('FENCE_START_WRITER_UNVERIFIED')
    return ids


def _writer_stop_problem(observed,expected,service,site):
    """Classify exact failed predicates without returning runtime field values."""
    if not isinstance(observed,dict):return 'RESPONSE'
    if observed.get('id')!=expected['id']:return 'IDENTITY'
    if observed.get('running') is not False:return 'RUNNING'
    if type(observed.get('exit')) is not int:return 'EXIT_TYPE'
    if observed['exit']!=0:
        # A termination-like exit is diagnostic only; it is not proof that
        # pending requests or audit writes were drained safely.
        kind={137:'KILL_LIKE',143:'TERM_LIKE'}.get(observed['exit'],'OTHER')
        oom=observed.get('oom')
        state='TRUE' if oom is True else 'FALSE' if oom is False else 'UNKNOWN'
        return 'EXIT_'+kind+'_OOM_'+state
    if observed.get('oom') is not False:return 'OOM'
    if observed.get('error')!='':return 'ENGINE_ERROR'
    if observed.get('started')!=expected['started']:return 'STARTED'
    if observed.get('restart_count')!=expected['restart_count']:return 'RESTART_COUNT'
    if observed.get('project')!=site:return 'PROJECT'
    if observed.get('service')!=service:return 'SERVICE'
    if observed.get('image_ref')!=expected['image_ref']:return 'IMAGE_REF'
    if observed.get('image_id')!=expected['image_id']:return 'IMAGE_ID'
    finished=observed.get('finished')
    if (not isinstance(finished,str)
            or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',finished)
            or finished.startswith('0001-01-01T')):
        return 'FINISHED'
    return None


def _writers_stopped(writers,site):
    """Reject forced/uncertain termination of the exact observed instances.

    Exit code 0 is evidence of a normal process exit, not proof that all audit
    writes or inflight requests were flushed or acknowledged before stop.
    """
    fmt=('{"id":{{json .Id}},"running":{{json .State.Running}},"started":{{json .State.StartedAt}},'
         '"finished":{{json .State.FinishedAt}},"exit":{{json .State.ExitCode}},"oom":{{json .State.OOMKilled}},'
         '"error":{{json .State.Error}},"restart_count":{{json .RestartCount}},'
         '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
         '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
         '"image_ref":{{json .Config.Image}},"image_id":{{json .Image}}}')
    for service,expected in writers.items():
        observed=diagnostic._json(diagnostic._docker('inspect','--format',fmt,expected['id']))
        problem=_writer_stop_problem(observed,expected,service,site)
        if problem is not None:
            if service not in ('guardrail','agent'):raise StartError('FENCE_START_WRITER_EXIT_UNVERIFIED')
            raise StartError('FENCE_START_WRITER_STOP_'+service.upper()+'_'+problem)


def _observe(home,bundle,publisher,key,adapter):
    """Read-only preflight; every assumption is rechecked before writer stop."""
    with _observe_stage('SIGNED_LIVE'):
        diagnostic.inspect_installation(home,bundle,publisher)
        manifest=uterctl.verify(bundle,publisher);cfg=uterctl.read(Path(home)/'install.json')
        command,env=install.commands(home,cfg)
        command[command.index('-f')+1]=str(Path(home)/'releases'/manifest['version']/'compose/compose.yaml')
    with _observe_stage('WRITER_IDENTITIES'):
        writers=_writers(command,env,cfg['name'],manifest)
    with _observe_stage('REDIS_INSPECT'):
        short=diagnostic._read(command+['ps','-q','redis'],env).strip()
        if not re.fullmatch(r'[0-9a-f]{12,64}',short):raise StartError('FENCE_START_REDIS_UNVERIFIED')
        redis=diagnostic._json(diagnostic._docker('inspect','--format','{{json .Id}}',short))
        if not isinstance(redis,str) or not re.fullmatch(r'[0-9a-f]{64}',redis):
            raise StartError('FENCE_START_REDIS_UNVERIFIED')
        live=diagnostic._canonical_inspection(diagnostic._redis_inspect(redis))
        netid,_=diagnostic._require_redis(live,cfg['name'],redis,manifest['images']['redis'])
        endpoint=live['networks'][cfg['name']+'_backend']
    with _observe_stage('PLAN_VALIDATE'):
        ipam=diagnostic._json(diagnostic._docker('network','inspect','--format','{{json .IPAM}}',netid))
        if not isinstance(ipam,dict) or len(ipam.get('Config',[]))!=1:raise StartError('FENCE_START_NETWORK_UNVERIFIED')
        config=ipam['Config'][0]
        plan={'schema':1,'operation':plans.new_operation(),'site':cfg['name'],'container_id':redis,
              'started_at':live['started'],'restart_count':live['restart_count'],'image_ref':manifest['images']['redis'],
              'image_config_id':live['image_id'],'restart_policy':'unless-stopped','volume_name':cfg['name']+'_redis-data',
              'volume_driver':'local','network_id':netid,'network_name':cfg['name']+'_backend','network_driver':'bridge',
              'network_scope':'local','network_internal':True,'network_subnet':config['Subnet'],
              'network_gateway':config['Gateway'],'endpoint_id':endpoint['EndpointID'],
              'endpoint_ipv4':endpoint['IPAddress'],'endpoint_static_ipv4':None,'endpoint_aliases':endpoint['Aliases'],
              'endpoint_mac':endpoint['MacAddress'].lower(),'ipv6_enabled':False,'network_options':{},'endpoint_driver_options':{}}
        plans.validate(plan)
    # These checks validate process, mounts, config, shared namespaces/volume
    # and exact network fields before stopping an otherwise working service.
    with _observe_stage('CONFIG'):
        adapter._lock();adapter._config(Path(home)/'releases'/manifest['version'])
    with _observe_stage('STATE'):
        adapter._state(plan,detached=False,restart='unless-stopped',original_endpoint=True)
    with _observe_stage('NETWORK'):
        adapter._network_and_volume(plan)
    with _observe_stage('PEERS'):
        adapter._peers(plan)
    with _observe_stage('REINSPECT'):
        again=diagnostic._canonical_inspection(diagnostic._redis_inspect(redis))
        if again!=live:raise StartError(_redis_change(live,again))
        other_writers=_writers(command,env,cfg['name'],manifest)
        if other_writers!=writers:raise StartError(_writers_change(writers,other_writers,'FENCE_START_OBSERVE_WRITERS'))
    with _observe_stage('BUNDLE_HASH'):
        return plan,writers,hashlib.sha256((Path(bundle)/'checksums.json').read_bytes()).hexdigest()


def start(home,bundle,publisher,key):
    """Stop the two exact verified writers and install a scoped Redis fence."""
    adapter=fence.Adapter(home,bundle,publisher,key)
    phase='PRECHECK'
    try:
        adapter._lock()
        for name in (journal.NAME,journal.FINALIZE_ANCHOR,journal.UPDATE_INTENT,journal.UPDATE_START,journal.UPDATE_RESULT,plans.NAME,NAME,'backup-operation.json','session-migration-block.json'):
            if os.path.lexists(Path(home)/name):raise StartError('FENCE_START_PRIOR_OPERATION')
        plan,writers,bundle_hash=_observe(home,bundle,publisher,key,adapter)
        phase='PLAN'
        digest=plans.create(home,plan,key)
        intent={'schema':1,'operation':plan['operation'],'site':plan['site'],'redis':plan['container_id'],
                'guardrail':writers['guardrail'],'agent':writers['agent'],'plan_sha256':digest,'bundle_sha256':bundle_hash}
        phase='INTENT';_write_intent(home,intent,key)
        phase='JOURNAL'
        record=journal.create(home,backend='compose',site=plan['site'],resource=plan['container_id'],
                              plan_sha256=digest,operation=plan['operation'])
        # Recheck every exact service/Redis identity after durable intent and
        # immediately before the first mutation. Never infer timeout success.
        phase='RECHECK';adapter._lock();again,now,current_hash=_observe(home,bundle,publisher,key,adapter)
        normalized=dict(again,operation=plan['operation'])
        if normalized!=plan:raise StartError(_plan_change(plan,normalized))
        if now!=writers:raise StartError(_writers_change(writers,now,'FENCE_START_RECHECK_WRITERS'))
        if current_hash!=bundle_hash:raise StartError('FENCE_START_RECHECK_BUNDLE_CHANGED')
        phase='STOP';adapter._run('stop','--time','25',writers['guardrail']['id'],writers['agent']['id'])
        phase='WRITER_STOP_VERIFY'
        _writers_stopped(writers,plan['site'])
        phase='ISOLATE'
        protocol.isolate(home,record['operation'],adapter)
        phase='RESULT'
        final=journal.read(home)
        if final['operation']!=record['operation'] or final['phase']!='isolated':
            raise StartError('FENCE_START_RESULT_UNVERIFIED')
        return final['operation']
    except StartError:raise
    except Exception:raise StartError('FENCE_START_'+phase+'_UNCERTAIN') from None
    finally:adapter.close()
