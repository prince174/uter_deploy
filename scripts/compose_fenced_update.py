"""Read-only preflight for a narrowly scoped Compose fenced update.

This module does not authorize a rollout or bypass the session-migration gate.
Host root, Docker daemon, kernel and signed executors remain trusted; do not
run old controllers or other Docker automation concurrently.
"""
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

import uterctl
from scripts import (backup_crypto, backup_installation, backup_snapshot, backup_store, compose_fence_finalize, compose_fence_resume, compose_fence_start,
                     compose_fence_origin, compose_fence_recovery_plan, compose_nsfirewall_adapter, compose_snapshot_only as snapshot,
                     install_recovery, redis_fence_journal as journal, snapshot_only_receipts as receipts)


class FencedUpdateError(ValueError): pass


TARGET_START=journal.UPDATE_START
TARGET_RESULT=journal.UPDATE_RESULT
CLEANUP=journal.CLEANUP_INTENT
_SAFE_START_CODES=frozenset('FENCE_START_'+name for name in (
    'INCOMPLETE','INTENT_INVALID','INTENT_UNCERTAIN','INTENT_UNVERIFIED','NETWORK_UNVERIFIED',
    'PRIOR_OPERATION','REDIS_UNVERIFIED','RESULT_UNVERIFIED','WRITER_UNVERIFIED','WRITER_EXIT_UNVERIFIED',
    'RECHECK_BUNDLE_CHANGED',*(phase+'_UNCERTAIN' for phase in ('PRECHECK','PLAN','INTENT','JOURNAL','RECHECK',
        'STOP','WRITER_STOP_VERIFY','ISOLATE','RESULT'))))
_SAFE_START_CODES|=frozenset(prefix+'_'+suffix for prefix,suffixes in (
    ('FENCE_START_RECHECK_PLAN',('PROCESS','IMAGE','NETWORK_ID','NETWORK_POLICY','IPAM','ENDPOINT_ID',
        'ENDPOINT_ADDRESS','ENDPOINT_ALIASES','ENDPOINT_MAC','ENDPOINT_OPTIONS','VOLUME','OTHER')),
    ('FENCE_START_RECHECK_WRITERS',('IDENTITY','STARTED','RESTART','OTHER')),
    ('FENCE_START_OBSERVE_WRITERS',('IDENTITY','STARTED','RESTART','OTHER')),
    ('FENCE_START_OBSERVE_REDIS',('PROCESS','IMAGE','NETWORK','VOLUME','OTHER')))
    for suffix in suffixes)
_SAFE_START_CODES|=frozenset('FENCE_START_WRITER_STOP_'+service+'_'+category
    for service in ('GUARDRAIL','AGENT') for category in
    ('RESPONSE','IDENTITY','RUNNING','EXIT_TYPE','EXIT_NONZERO','OOM','ENGINE_ERROR','STARTED',
     'RESTART_COUNT','PROJECT','SERVICE','IMAGE_REF','IMAGE_ID','FINISHED',
     *('EXIT_'+kind+'_OOM_'+oom for kind in ('TERM_LIKE','KILL_LIKE','OTHER') for oom in ('TRUE','FALSE','UNKNOWN'))))
_SAFE_START_CODES|=frozenset('FENCE_START_OBSERVE_'+stage+'_'+category
    for stage in ('SIGNED_LIVE','WRITER_IDENTITIES','REDIS_INSPECT','PLAN_VALIDATE','CONFIG','STATE','NETWORK','PEERS','REINSPECT','BUNDLE_HASH')
    for category in ('ERROR','KEY_ERROR','TYPE_ERROR',*compose_fence_start._OBSERVE_DIAGNOSTIC_CODES,
                     *compose_fence_start._OBSERVE_ADAPTER_CODES))


def _evidence_names():
    return (compose_fence_recovery_plan.NAME,compose_fence_finalize.checkpoint.NAME,
            compose_fence_start.NAME,compose_fence_origin.NAME,receipts.DESCRIPTOR,receipts.RECEIPT,
            receipts.DECISION,journal.UPDATE_INTENT,TARGET_START,TARGET_RESULT)


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def _intent_mac(key,record):
    if not isinstance(key,bytes) or len(key)!=32:raise FencedUpdateError('FENCED_UPDATE_INTENT_INVALID')
    return hmac.new(backup_crypto.derive_key(key,b'compose-fenced-update-intent-v1'),_canonical(record),hashlib.sha256).hexdigest()


def _intent_valid(value,record):
    fields={'schema','operation','site','resource','plan_sha256','source_sha256','target_sha256',
            'executor_sha256','receipt_sha256','destination_sha256'}
    if (not isinstance(value,dict) or set(value)!=fields or type(value['schema']) is not int or value['schema']!=1
            or any(value[name]!=record[name] for name in ('operation','site','resource','plan_sha256'))
            or any(not isinstance(value[name],str) or not re.fullmatch(r'[0-9a-f]{64}',value[name])
                   for name in ('plan_sha256','source_sha256','target_sha256','executor_sha256','receipt_sha256','destination_sha256'))):
        raise FencedUpdateError('FENCED_UPDATE_INTENT_INVALID')
    return value


def read_intent(home,key,record):
    try:
        raw=backup_installation.safe_file(Path(home)/journal.UPDATE_INTENT,private=True,limit=4096)
        def pairs(items):
            result={}
            for name,value in items:
                if name in result:raise ValueError
                result[name]=value
            return result
        envelope=json.loads(raw,object_pairs_hook=pairs)
        if not isinstance(envelope,dict) or set(envelope)!={'intent','mac'}:raise ValueError
        value=_intent_valid(envelope['intent'],record)
        if not isinstance(envelope['mac'],str) or not hmac.compare_digest(envelope['mac'],_intent_mac(key,value)):raise ValueError
        return value
    except Exception:raise FencedUpdateError('FENCED_UPDATE_INTENT_UNVERIFIED') from None


def create_intent(home,key,record,source_hash,target_hash,executor_hash,receipt_hash,destination_hash):
    """Persist exact target and snapshot identity before release or target start."""
    backup_snapshot._require_legacy_operation_lock(home)
    if journal.read(home)!=record or record['phase']!='captured':raise FencedUpdateError('FENCED_UPDATE_STATE_UNVERIFIED')
    value=_intent_valid({'schema':1,**{name:record[name] for name in ('operation','site','resource','plan_sha256')},
        'source_sha256':source_hash,'target_sha256':target_hash,'executor_sha256':executor_hash,
        'receipt_sha256':receipt_hash,'destination_sha256':destination_hash},record)
    raw=_canonical({'intent':value,'mac':_intent_mac(key,value)})+b'\n'
    directory=journal._directory(home)
    try:
        try:
            fd=os.open(journal.UPDATE_INTENT,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as target:
                os.fchmod(target.fileno(),0o600);target.write(raw);target.flush();os.fsync(target.fileno())
            os.fsync(directory)
        except OSError:raise FencedUpdateError('FENCED_UPDATE_INTENT_UNCERTAIN') from None
    finally:os.close(directory)
    if read_intent(home,key,record)!=value:raise FencedUpdateError('FENCED_UPDATE_INTENT_UNVERIFIED')
    return value


def _config(home, bundle, manifest, site):
    # No inherited DOCKER_HOST, DOCKER_CONTEXT, COMPOSE_*, proxy, or arbitrary
    # substitution variables. Public images only: no user Docker credentials.
    with tempfile.TemporaryDirectory(prefix='uter-compose-config-') as directory:
        command,env=_compose_command(home,bundle,manifest,site,directory)
        command+=['config','--format','json']
        try:
            raw=install_recovery.run_readonly(command,timeout=30,env=env)
            value=json.loads(raw)
            if not isinstance(value,dict):raise ValueError
            return value
        except Exception:raise FencedUpdateError('FENCED_UPDATE_CONFIG_UNVERIFIED') from None


def _compose_command(home,bundle,manifest,site,config_dir):
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent',
         'DOCKER_CONFIG':str(config_dir),'LANG':'C','RUNTIME_DIR':str(home/'runtime'),
         **{name.upper()+'_IMAGE':image for name,image in manifest['images'].items()}}
    if 'port' in site:env['GUARDRAIL_PORT']=str(site['port'])
    if 'guardrail_cpus' in site:env['GUARDRAIL_CPUS']=str(site['guardrail_cpus'])
    command=['/usr/bin/docker','--context','default','compose','--project-name',site['name'],
             '--env-file',str(Path(bundle)/'empty.env'),'-f',str(Path(bundle)/'compose/compose.yaml')]
    return command,env


def _compare_configs(current, target, old, new):
    """Compare every canonical field, permitting only the two writer images."""
    try:
        a=copy.deepcopy(current);b=copy.deepcopy(target)
        if set(a['services'])!={'redis','agent','guardrail'} or set(b['services'])!=set(a['services']):raise ValueError
        for service in ('redis','agent','guardrail'):
            if (a['services'][service].get('image')!=old['images'][service]
                    or b['services'][service].get('image')!=new['images'][service]):raise ValueError
        for service in ('agent','guardrail'):
            del a['services'][service]['image'];del b['services'][service]['image']
        if a!=b:raise ValueError
    except (KeyError,TypeError,ValueError):raise FencedUpdateError('FENCED_UPDATE_CONFIG_CHANGED') from None


def preflight(home, source, target, publisher, state, site):
    """Verify signed transition and whole canonical config; never mutate workloads."""
    try:
        home=Path(home);source=Path(source);target=Path(target)
        old=uterctl.verify(source,publisher);new=uterctl.verify(target,publisher)
        if (state.get('adopted_installer') is not True or state.get('current')!=old
                or state.get('pending') is not None or site.get('backend')!='compose'
                or site.get('context')!='default' or site.get('namespace')!=site.get('name')
                or old['version']==new['version'] or old['data_epoch']!=new['data_epoch']):raise ValueError
        uterctl.transition(old,new)
        if old['images']['redis']!=new['images']['redis']:raise ValueError
        for name in ('compose/compose.yaml','empty.env','examples/redis.conf.example'):
            if snapshot._file(source/name)!=snapshot._file(target/name):raise ValueError
        _compare_configs(_config(home,source,old,site),_config(home,target,new,site),old,new)
        return old,new
    except FencedUpdateError:raise
    except Exception:raise FencedUpdateError('FENCED_UPDATE_PREFLIGHT_UNVERIFIED') from None


def stage_target(home,target,publisher,manifest):
    """Install a verified target bundle before stopping any application writer."""
    home=Path(home);target=Path(target)
    backup_snapshot._require_legacy_operation_lock(home)
    try:
        backup_installation.verify_tree(target)
        if uterctl.verify(target,publisher)!=manifest:raise ValueError
        releases=home/'releases';destination=releases/manifest['version']
        backup_installation.checked_existing_path(releases)
        info=releases.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.geteuid())
                or info.st_mode & 0o022):raise ValueError
        if os.path.lexists(destination):
            backup_installation.verify_tree(destination)
            if (uterctl.verify(destination,publisher)!=manifest
                    or snapshot._file(destination/'checksums.json')!=snapshot._file(target/'checksums.json')):raise ValueError
            return destination
        with tempfile.TemporaryDirectory(prefix='.fenced-target-',dir=releases) as temporary:
            staged=Path(temporary)/'bundle';shutil.copytree(target,staged,symlinks=True)
            backup_installation.verify_tree(staged)
            if uterctl.verify(staged,publisher)!=manifest:raise ValueError
            # Commit only a complete verified bundle. Fsync every file and
            # directory before its final name can appear in controller state.
            for root,dirs,files in os.walk(staged,topdown=False,followlinks=False):
                for name in files:
                    fd=os.open(Path(root)/name,os.O_RDONLY|os.O_NOFOLLOW)
                    try:os.fsync(fd)
                    finally:os.close(fd)
                fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(fd)
                finally:os.close(fd)
            os.rename(staged,destination)
            fd=os.open(releases,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
        return destination
    except Exception:raise FencedUpdateError('FENCED_UPDATE_TARGET_STAGE_UNCERTAIN') from None


def pull_writers(home,target,manifest,site):
    """Pull only the two signed writer images; never reconcile workloads."""
    try:
        with tempfile.TemporaryDirectory(prefix='uter-compose-pull-') as temporary:
            command,env=_compose_command(Path(home),target,manifest,site,temporary)
            subprocess.run(command+['pull','agent','guardrail'],env=env,stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                           check=True,timeout=900,start_new_session=True)
    except Exception:raise FencedUpdateError('FENCED_UPDATE_PULL_UNCERTAIN') from None


def capture_for_update(home,source,target,publisher,executor_key,key,destination):
    """Internal locked stage: signed preflight, fence, backup, then durable intent.

    The caller must hold the ordinary PID lock throughout subsequent stages.
    Failures leave existing evidence untouched, never resume or restore data.
    This stage is not an exposed user command and is not a complete update.
    """
    backup_snapshot._require_legacy_operation_lock(home)
    home=Path(home);destination=Path(destination)
    if journal.blocks_mutation(home):raise FencedUpdateError('FENCED_UPDATE_PRIOR_OPERATION')
    if (not destination.is_absolute() or '..' in destination.parts or os.path.lexists(destination)
            or destination==home or destination.is_relative_to(home)):
        raise FencedUpdateError('FENCED_UPDATE_DESTINATION_INVALID')
    phase='PRECHECK'
    try:
        backup_installation.private_directory(destination.parent)
        state=uterctl.read(home/'state.json');site=uterctl.site_config(home)
        old,new=preflight(home,source,target,publisher,state,site)
        if Path(source)!=(home/'releases'/old['version']):raise ValueError
        executor_hash=snapshot._executor(uterctl.ROOT,executor_key)
        # start() durably records the original exact IDs before first stop.
        phase='FENCE_START'
        operation=compose_fence_start.start(home,source,publisher,key)
        record=journal.read(home)
        if record['operation']!=operation or record['phase']!='isolated':raise ValueError
        adapter=compose_nsfirewall_adapter.Adapter(home,source,publisher,key)
        try:
            phase='ADAPTER_ATTACH'
            if adapter.attach_before_capture_recovery(record) is not True or adapter.verify_fenced(record) is not True:
                raise ValueError
            phase='BACKUP_CAPTURE'
            backup_id=snapshot.capture_for_mutation(adapter,record,uterctl.ROOT,executor_key,destination)
        finally:adapter.close()
        phase='RECEIPT'
        record=journal.read(home)
        receipt,receipt_hash=receipts.read_receipt(home,key)
        if record['operation']!=operation or record['phase']!='captured' or receipt['backup_id']!=backup_id:
            raise ValueError
        source_hash=hashlib.sha256(snapshot._file(Path(source)/'checksums.json')).hexdigest()
        target_hash=hashlib.sha256(snapshot._file(Path(target)/'checksums.json')).hexdigest()
        destination_hash=hashlib.sha256(str(destination.resolve()).encode()).hexdigest()
        phase='INTENT'
        create_intent(home,key,record,source_hash,target_hash,executor_hash,receipt_hash,destination_hash)
        return record,old,new
    except FencedUpdateError:raise
    except compose_fence_start.StartError as error:
        code=str(error)
        if phase=='FENCE_START' and code in _SAFE_START_CODES:
            raise FencedUpdateError('FENCED_UPDATE_CAPTURE_'+code) from None
        raise FencedUpdateError('FENCED_UPDATE_CAPTURE_'+phase+'_UNCERTAIN') from None
    except Exception:raise FencedUpdateError('FENCED_UPDATE_CAPTURE_'+phase+'_UNCERTAIN') from None


def _verify_binding(home,source,target,publisher,executor_key,key,destination,record,*,allow_committed=False):
    """Revalidate all immutable identities; does not itself prove a live fence."""
    intent=read_intent(home,key,record)
    state=uterctl.read(Path(home)/'state.json');site=uterctl.site_config(home)
    if allow_committed:
        source_manifest=uterctl.verify(source,publisher);target_manifest=uterctl.verify(target,publisher)
        current=state.get('current')
        if current==target_manifest:
            if state.get('previous')!=source_manifest or state.get('pending') is not None or state.get('adopted_installer') is not True:
                raise FencedUpdateError('FENCED_UPDATE_BINDING_UNVERIFIED')
            state=dict(state,current=source_manifest)
    old,new=preflight(home,source,target,publisher,state,site)
    receipt,receipt_hash=receipts.read_receipt(home,key)
    actual={'source_sha256':hashlib.sha256(snapshot._file(Path(source)/'checksums.json')).hexdigest(),
            'target_sha256':hashlib.sha256(snapshot._file(Path(target)/'checksums.json')).hexdigest(),
            'executor_sha256':snapshot._executor(uterctl.ROOT,executor_key),
            'receipt_sha256':receipt_hash,
            'destination_sha256':hashlib.sha256(str(Path(destination).resolve()).encode()).hexdigest()}
    if (any(intent[name]!=value for name,value in actual.items())
            or receipt.get('operation')!=record['operation']):
        raise FencedUpdateError('FENCED_UPDATE_BINDING_UNVERIFIED')
    return intent,old,new


def release_for_update(home,source,target,publisher,executor_key,key,destination):
    """Release only after persisted target intent and verified snapshot.

    From the first release attempt, external clients may write. An interrupted
    operation must never replay release, start writers, or restore the backup.
    """
    backup_snapshot._require_legacy_operation_lock(home)
    record=journal.read(home)
    if record['phase']!='captured':raise FencedUpdateError('FENCED_UPDATE_RELEASE_STATE_UNVERIFIED')
    try:
        _verify_binding(home,source,target,publisher,executor_key,key,destination,record)
        adapter=compose_nsfirewall_adapter.Adapter(home,source,publisher,key)
        try:
            backup_id=snapshot.release_for_mutation(adapter,uterctl.ROOT,executor_key,destination,target)
            final=journal.read(home)
            if (final['operation']!=record['operation'] or final['phase']!='redis_released'
                    or not isinstance(backup_id,str) or not re.fullmatch(r'[0-9a-f]{32}',backup_id)):
                raise ValueError
            # This rechecks the original pinned namespace/process after release;
            # it does not claim that external writers remain blocked.
            plan=adapter._plan(final)
            adapter._live_namespace(plan,restart='unless-stopped')
            adapter._network_and_volume(plan);adapter._check_firewall(installed=False)
        finally:adapter.close()
        return final
    except FencedUpdateError:raise
    except Exception:raise FencedUpdateError('FENCED_UPDATE_RELEASE_INCOMPLETE') from None


def read_target_start(home,key,record,intent):
    try:
        raw=backup_installation.safe_file(Path(home)/TARGET_START,private=True,limit=4096)
        def pairs(items):
            result={}
            for name,value in items:
                if name in result:raise ValueError
                result[name]=value
            return result
        envelope=json.loads(raw,object_pairs_hook=pairs)
        value={'schema':1,'operation':record['operation'],'intent_sha256':hashlib.sha256(_canonical(intent)).hexdigest()}
        derived=backup_crypto.derive_key(key,b'compose-fenced-target-start-v1')
        expected=hmac.new(derived,_canonical(value),hashlib.sha256).hexdigest()
        if (not isinstance(envelope,dict) or set(envelope)!={'start','mac'} or envelope['start']!=value
                or not isinstance(envelope['mac'],str) or not hmac.compare_digest(envelope['mac'],expected)):
            raise ValueError
        return value
    except Exception:raise FencedUpdateError('FENCED_UPDATE_START_INTENT_UNVERIFIED') from None


def create_target_start(home,key,record,intent):
    """Write once before Compose can start/recreate either target writer."""
    backup_snapshot._require_legacy_operation_lock(home)
    if journal.read(home)!=record or record['phase']!='redis_released' or read_intent(home,key,record)!=intent:
        raise FencedUpdateError('FENCED_UPDATE_START_STATE_UNVERIFIED')
    value={'schema':1,'operation':record['operation'],'intent_sha256':hashlib.sha256(_canonical(intent)).hexdigest()}
    derived=backup_crypto.derive_key(key,b'compose-fenced-target-start-v1')
    envelope={'start':value,'mac':hmac.new(derived,_canonical(value),hashlib.sha256).hexdigest()}
    directory=journal._directory(home)
    try:
        try:
            fd=os.open(TARGET_START,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as out:
                os.fchmod(out.fileno(),0o600);out.write(_canonical(envelope)+b'\n');out.flush();os.fsync(out.fileno())
            os.fsync(directory)
        except OSError:raise FencedUpdateError('FENCED_UPDATE_START_INTENT_UNCERTAIN') from None
    finally:os.close(directory)
    if read_target_start(home,key,record,intent)!=value:raise FencedUpdateError('FENCED_UPDATE_START_INTENT_UNVERIFIED')
    return value


def _target_value(record,intent,writers):
    value={'schema':1,'operation':record['operation'],'site':record['site'],'redis':record['resource'],
           'plan_sha256':record['plan_sha256'],'bundle_sha256':intent['target_sha256'],
           'agent':writers['agent'],'guardrail':writers['guardrail']}
    compose_fence_start._validate_intent(value)
    return value


def read_target_result(home,key,record,intent):
    try:
        raw=backup_installation.safe_file(Path(home)/TARGET_RESULT,private=True,limit=8192)
        def pairs(items):
            result={}
            for name,value in items:
                if name in result:raise ValueError
                result[name]=value
            return result
        envelope=json.loads(raw,object_pairs_hook=pairs)
        value=envelope['result']
        if not isinstance(envelope,dict) or set(envelope)!={'result','mac'}:raise ValueError
        if _target_value(record,intent,value)!=value:raise ValueError
        derived=backup_crypto.derive_key(key,b'compose-fenced-target-result-v1')
        expected=hmac.new(derived,_canonical(value),hashlib.sha256).hexdigest()
        if not isinstance(envelope['mac'],str) or not hmac.compare_digest(envelope['mac'],expected):raise ValueError
        return value
    except Exception:raise FencedUpdateError('FENCED_UPDATE_RESULT_UNVERIFIED') from None


def create_target_result(home,key,record,intent,writers):
    backup_snapshot._require_legacy_operation_lock(home)
    if journal.read(home)!=record or record['phase']!='target_starting':
        raise FencedUpdateError('FENCED_UPDATE_RESULT_STATE_UNVERIFIED')
    read_target_start(home,key,record,intent)
    value=_target_value(record,intent,writers)
    derived=backup_crypto.derive_key(key,b'compose-fenced-target-result-v1')
    raw=_canonical({'result':value,'mac':hmac.new(derived,_canonical(value),hashlib.sha256).hexdigest()})+b'\n'
    directory=journal._directory(home)
    try:
        try:
            fd=os.open(TARGET_RESULT,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as out:
                os.fchmod(out.fileno(),0o600);out.write(raw);out.flush();os.fsync(out.fileno())
            os.fsync(directory)
        except OSError:raise FencedUpdateError('FENCED_UPDATE_RESULT_UNCERTAIN') from None
    finally:os.close(directory)
    if read_target_result(home,key,record,intent)!=value:raise FencedUpdateError('FENCED_UPDATE_RESULT_UNVERIFIED')
    return value


def _released_binding(home,old,site,intent,executor_key,destination):
    """Reconstruct fixed snapshot binding after writers may be running."""
    return {'current':old,'site':site,'bundle':intent['source_sha256'],
            'checkpoint':hashlib.sha256(snapshot._file(Path(home)/compose_fence_finalize.checkpoint.NAME)).hexdigest(),
            'executor':snapshot._executor(uterctl.ROOT,executor_key),
            'destination':hashlib.sha256(str(Path(destination).resolve()).encode()).hexdigest()}


def start_target(home,source,target,publisher,executor_key,key,destination):
    """Attempt target writers once, preserving all evidence on any uncertainty."""
    backup_snapshot._require_legacy_operation_lock(home)
    home=Path(home);record=journal.read(home)
    if record['phase']!='redis_released':raise FencedUpdateError('FENCED_UPDATE_START_STATE_UNVERIFIED')
    if os.path.lexists(home/TARGET_START) or os.path.lexists(home/TARGET_RESULT):
        raise FencedUpdateError('FENCED_UPDATE_START_STATE_UNVERIFIED')
    try:
        intent,old,new=_verify_binding(home,source,target,publisher,executor_key,key,destination,record)
        site=uterctl.site_config(home)
        adapter=compose_nsfirewall_adapter.Adapter(home,source,publisher,key)
        try:
            plan=adapter._plan(record)
            adapter._signed(plan);adapter._config(Path(source))
            saved=compose_fence_finalize.checkpoint.read(home,record,key)
            compose_fence_finalize._attach_running_redis(adapter,record,plan,saved)
            binding=_released_binding(home,old,site,intent,executor_key,destination)
            _verify_mutation_backup(adapter,record,executor_key,destination,intent,binding)
            original=compose_fence_start.read_intent(home,key,record,intent['source_sha256'])
            compose_fence_start._writers_stopped({name:original[name] for name in ('agent','guardrail')},site['name'])
            compose_fence_resume._current_writer_ids(adapter,plan,original)
            create_target_start(home,key,record,intent)
            record=journal.advance(home,operation=record['operation'],expected='redis_released',next_phase='target_starting')
            # Once this command is sent an unknown daemon outcome is never
            # retried; target writes may already have occurred after release.
            with tempfile.TemporaryDirectory(prefix='uter-compose-update-') as directory:
                command,env=_compose_command(home,target,new,site,directory)
                subprocess.run(command+['up','-d','--no-deps','--no-build','--pull','never',
                                        '--wait','--wait-timeout','300','agent','guardrail'],
                               env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,check=True,timeout=360,start_new_session=True)
                writers=compose_fence_start._writers(command,env,site['name'],new)
            for service in ('agent','guardrail'):
                compose_fence_resume._healthy(adapter,writers[service],service,site['name'])
            adapter._live_namespace(plan,restart='unless-stopped')
            adapter._network_and_volume(plan);adapter._peers(plan);adapter._redis_config(plan)
            adapter._check_firewall(installed=False)
            read_target_start(home,key,record,intent)
            create_target_result(home,key,record,intent,writers)
            journal.advance(home,operation=record['operation'],expected='target_starting',next_phase='target_running')
            return writers
        finally:adapter.close()
    except FencedUpdateError:raise
    except Exception:raise FencedUpdateError('FENCED_UPDATE_START_INCOMPLETE') from None


def _verify_mutation_backup(adapter,record,executor_key,destination,intent,binding):
    descriptor,descriptor_hash=receipts.read_descriptor(adapter.home,adapter.backup_key)
    receipt,receipt_hash=receipts.read_receipt(adapter.home,adapter.backup_key)
    decision,_=receipts.read_decision(adapter.home,adapter.backup_key)
    released=compose_fence_origin.read(adapter.home,adapter.backup_key,record)
    if (descriptor['operation']!=record['operation'] or descriptor['backend']!='compose'
            or descriptor['site']!=record['site'] or descriptor['resource']!=record['resource']
            or descriptor['identity_sha256']!=record['plan_sha256']
            or descriptor['release_version']!=binding['current']['version']
            or descriptor['bundle_sha256']!=binding['bundle']
            or descriptor['fence_checkpoint_sha256']!=binding['checkpoint']
            or descriptor['backup_location_sha256']!=binding['destination']
            or descriptor['executor_sha256']!=binding['executor'] or decision['action']!='mutation'
            or receipt['descriptor_sha256']!=descriptor_hash or receipt_hash!=intent['receipt_sha256']
            or released['origin']!='snapshot' or released['receipt_sha256']!=receipt_hash):
        raise FencedUpdateError('FENCED_UPDATE_BACKUP_UNVERIFIED')
    raw=snapshot._file(Path(destination)/'manifest.json')
    verified=backup_store.verify_set(destination,adapter.backup_key,home=adapter.home,
                                     site=binding['site'],version=binding['current']['version'])
    if (verified['id']!=descriptor['backup_id'] or verified['id']!=receipt['backup_id']
            or hashlib.sha256(raw).hexdigest()!=receipt['manifest_sha256']
            or snapshot._file(Path(destination)/'manifest.json')!=raw):
        raise FencedUpdateError('FENCED_UPDATE_BACKUP_UNVERIFIED')
    return verified


def _durable_json(home,name,value):
    """Write complete new state atomically and fsync before marker cleanup."""
    directory=journal._directory(home)
    temporary='.fenced-state-'+os.urandom(12).hex()
    try:
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        with os.fdopen(fd,'wb') as out:
            out.write(_canonical(value)+b'\n');out.flush();os.fsync(out.fileno())
        os.replace(temporary,name,src_dir_fd=directory,dst_dir_fd=directory)
        os.fsync(directory)
    finally:os.close(directory)


def _verify_running_source(adapter,record,plan,source,publisher,old,new,site,*,allow_committed=False):
    """Authenticate source/Redis without the stopped-writers assumption."""
    home=adapter.home;adapter._lock()
    cfg=backup_installation.safe_json(home/'install.json')
    installed=home/'releases'/old['version']
    state=backup_installation.safe_json(home/'state.json')
    current=state.get('current')
    accepted_cfg=cfg.get('images')==old['images']
    if allow_committed and cfg.get('images')==new['images']:
        accepted_cfg=current in (old,new)
    if (Path(source)!=installed or uterctl.verify(installed,publisher)!=old
            or current not in ((old,new) if allow_committed else (old,))
            or (current==new and cfg.get('images')!=new['images'])
            or cfg.get('backend')!='compose' or cfg.get('context')!='default'
            or cfg.get('name')!=record['site'] or not accepted_cfg
            or old['images']['redis']!=plan['image_ref'] or site.get('name')!=record['site']
            or site.get('context')!='default' or site.get('namespace')!=record['site']
            or os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT','default') not in ('','default')
            or adapter._json('context','inspect','default','--format','{{json .Endpoints.docker.Host}}')!='unix:///var/run/docker.sock'):
        raise FencedUpdateError('FENCED_UPDATE_RUNNING_IDENTITY_UNVERIFIED')
    adapter._config(installed)
    return cfg


def _cleanup_mac(key,value):
    if not isinstance(key,bytes) or len(key)!=32:raise FencedUpdateError('FENCED_CLEANUP_KEY_INVALID')
    return hmac.new(backup_crypto.derive_key(key,b'compose-fenced-cleanup-v1'),_canonical(value),hashlib.sha256).hexdigest()


def _validate_cleanup(value):
    fields={'schema','record','plan','checkpoint','intent','result','source_version','target_version',
            'site','backup_id','backup_manifest_sha256','state_sha256','config_sha256','evidence'}
    if (not isinstance(value,dict) or set(value)!=fields or type(value['schema']) is not int or value['schema']!=1
            or journal._validate(value['record'])!=value['record'] or value['record']['phase']!='update_finalizing'
            or value['record']['backend']!='compose'
            or set(value['evidence'])!=set(_evidence_names())):raise ValueError
    compose_fence_recovery_plan.validate(value['plan'])
    if (value['plan']['operation']!=value['record']['operation'] or value['plan']['site']!=value['record']['site']
            or value['plan']['container_id']!=value['record']['resource']):raise ValueError
    compose_fence_finalize.checkpoint.validate(value['checkpoint'],value['record'])
    _intent_valid(value['intent'],value['record'])
    if _target_value(value['record'],value['intent'],value['result'])!=value['result']:raise ValueError
    if (not isinstance(value['site'],dict) or value['site'].get('name')!=value['record']['site']
            or value['site'].get('backend')!='compose' or value['site'].get('context')!='default'
            or value['site'].get('namespace')!=value['record']['site']):raise ValueError
    for field in ('source_version','target_version'):
        if not isinstance(value[field],str) or not uterctl.VERSION.fullmatch(value[field]):raise ValueError
    if (value['source_version']==value['target_version'] or not isinstance(value['backup_id'],str)
            or not re.fullmatch(r'[0-9a-f]{32}',value['backup_id'])):raise ValueError
    for digest in (value['backup_manifest_sha256'],value['state_sha256'],value['config_sha256'],*value['evidence'].values()):
        if not isinstance(digest,str) or not re.fullmatch(r'[0-9a-f]{64}',digest):raise ValueError
    return value


def read_cleanup(home,key):
    try:
        raw=backup_installation.safe_file(Path(home)/CLEANUP,private=True,limit=131072)
        def pairs(items):
            result={}
            for name,value in items:
                if name in result:raise ValueError
                result[name]=value
            return result
        envelope=json.loads(raw,object_pairs_hook=pairs)
        if not isinstance(envelope,dict) or set(envelope)!={'cleanup','mac'}:raise ValueError
        value=_validate_cleanup(envelope['cleanup'])
        if not isinstance(envelope['mac'],str) or not hmac.compare_digest(envelope['mac'],_cleanup_mac(key,value)):raise ValueError
        return value
    except Exception:raise FencedUpdateError('FENCED_CLEANUP_UNVERIFIED') from None


def seal_cleanup(home,key,record,plan,saved,intent,result,old,new,site,backup,destination,directory,files):
    """Seal complete pre-cleanup proof after both state files were fsynced."""
    backup_snapshot._require_legacy_operation_lock(home)
    if journal.read(home)!=record or record['phase']!='update_finalizing':raise FencedUpdateError('FENCED_CLEANUP_STATE_UNVERIFIED')
    hashes={}
    for name in _evidence_names():
        compose_fence_finalize._same_inode(directory,name,files[name])
        fd,info=files[name];raw=os.pread(fd,info.st_size+1,0)
        if len(raw)!=info.st_size:raise FencedUpdateError('FENCED_CLEANUP_EVIDENCE_UNVERIFIED')
        hashes[name]=hashlib.sha256(raw).hexdigest()
    def digest(path):return hashlib.sha256(backup_installation.safe_file(path,limit=131072)).hexdigest()
    value={'schema':1,'record':record,'plan':plan,'checkpoint':saved,'intent':intent,'result':result,
           'source_version':old['version'],'target_version':new['version'],'site':site,'backup_id':backup['id'],
           'backup_manifest_sha256':digest(Path(destination)/'manifest.json'),
           'state_sha256':digest(Path(home)/'state.json'),'config_sha256':digest(Path(home)/'install.json'),
           'evidence':hashes}
    _validate_cleanup(value)
    raw=_canonical({'cleanup':value,'mac':_cleanup_mac(key,value)})+b'\n'
    if len(raw)>16384:raise FencedUpdateError('FENCED_CLEANUP_PROOF_TOO_LARGE')
    dirfd=journal._directory(home)
    try:
        try:
            fd=os.open(CLEANUP,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dirfd)
            with os.fdopen(fd,'wb') as out:
                os.fchmod(out.fileno(),0o600);out.write(raw);out.flush();os.fsync(out.fileno())
            os.fsync(dirfd)
        except OSError:raise FencedUpdateError('FENCED_CLEANUP_SEAL_UNCERTAIN') from None
    finally:os.close(dirfd)
    if read_cleanup(home,key)!=value:raise FencedUpdateError('FENCED_CLEANUP_UNVERIFIED')
    return value


def finish_sealed_cleanup(home,target,publisher,executor_key,key,destination):
    """Recheck sealed proof and live target; unlink only verified leftovers."""
    backup_snapshot._require_legacy_operation_lock(home)
    home=Path(home);target=Path(target);destination=Path(destination);adapter=None
    try:
        for name in (journal.FINALIZE_ANCHOR,'backup-operation.json','recovery-operation.json',
                     'session-migration-block.json','redis-loopback-intent.json','redis-loopback-attempt.json'):
            if os.path.lexists(home/name):raise ValueError
        sealed=read_cleanup(home,key);record=sealed['record'];intent=sealed['intent']
        if os.path.lexists(home/journal.NAME) and journal.read(home)!=record:raise ValueError
        source=home/'releases'/sealed['source_version']
        if target!=home/'releases'/sealed['target_version']:raise ValueError
        old=uterctl.verify(source,publisher);new=uterctl.verify(target,publisher)
        if (old['version']!=sealed['source_version'] or new['version']!=sealed['target_version']
                or hashlib.sha256(snapshot._file(source/'checksums.json')).hexdigest()!=intent['source_sha256']
                or hashlib.sha256(snapshot._file(target/'checksums.json')).hexdigest()!=intent['target_sha256']
                or snapshot._executor(uterctl.ROOT,executor_key)!=intent['executor_sha256']
                or hashlib.sha256(str(destination.resolve()).encode()).hexdigest()!=intent['destination_sha256']):raise ValueError
        state=backup_installation.safe_json(home/'state.json');cfg=backup_installation.safe_json(home/'install.json')
        site=uterctl.site_config(home)
        if (site!=sealed['site'] or state.get('current')!=new or state.get('previous')!=old
                or state.get('pending') is not None or state.get('adopted_installer') is not True
                or state.get('last_backup')!={'id':sealed['backup_id'],'path':str(destination.resolve()),'version':old['version']}
                or cfg.get('images')!=new['images'] or cfg.get('backend')!='compose'
                or cfg.get('context')!='default' or cfg.get('name')!=record['site']):raise ValueError
        for name,field in (('state.json','state_sha256'),('install.json','config_sha256')):
            if hashlib.sha256(backup_installation.safe_file(home/name,limit=131072)).hexdigest()!=sealed[field]:raise ValueError
        preflight(home,source,target,publisher,dict(state,current=old),site)
        backup=backup_store.verify_set(destination,key,home=home,site=site,version=old['version'])
        if (backup['id']!=sealed['backup_id'] or hashlib.sha256(snapshot._file(destination/'manifest.json')).hexdigest()!=sealed['backup_manifest_sha256']):raise ValueError
        adapter=compose_nsfirewall_adapter.Adapter(home,source,publisher,key);adapter._lock()
        if (os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT','default') not in ('','default')
                or adapter._json('context','inspect','default','--format','{{json .Endpoints.docker.Host}}')!='unix:///var/run/docker.sock'):
            raise ValueError
        adapter._config(source);plan=sealed['plan']
        if plan['image_ref']!=old['images']['redis'] or new['images']['redis']!=plan['image_ref']:raise ValueError
        compose_fence_finalize._attach_running_redis(adapter,record,plan,sealed['checkpoint'])
        with tempfile.TemporaryDirectory(prefix='uter-compose-verify-') as temporary:
            command,env=_compose_command(home,target,new,site,temporary)
            writers=compose_fence_start._writers(command,env,site['name'],new)
        if _target_value(record,intent,writers)!=sealed['result']:raise ValueError
        for service in ('agent','guardrail'):compose_fence_resume._healthy(adapter,writers[service],service,site['name'])
        adapter._live_namespace(plan,restart='unless-stopped');adapter._network_and_volume(plan)
        adapter._peers(plan);adapter._redis_config(plan);adapter._check_firewall(installed=False)
        remaining=[name for name in _evidence_names() if os.path.lexists(home/name)]
        has_journal=os.path.lexists(home/journal.NAME)
        names=remaining+([journal.NAME] if has_journal else [])+[CLEANUP]
        with compose_fence_finalize._pin_files(home,names) as (directory,files):
            if read_cleanup(home,key)!=sealed:raise ValueError
            # A previous seal call may have failed after writing complete bytes
            # but before durable fsync. Re-establish durability before deleting
            # any authenticated evidence, even on a recovery invocation.
            compose_fence_finalize._same_inode(directory,CLEANUP,files[CLEANUP])
            os.fsync(files[CLEANUP][0]);os.fsync(directory)
            for name in remaining:
                compose_fence_finalize._same_inode(directory,name,files[name])
                fd,info=files[name];raw=os.pread(fd,info.st_size+1,0)
                if len(raw)!=info.st_size or hashlib.sha256(raw).hexdigest()!=sealed['evidence'][name]:raise ValueError
            for name in remaining:
                compose_fence_finalize._same_inode(directory,name,files[name]);os.unlink(name,dir_fd=directory);os.fsync(directory)
            if has_journal:
                if journal.read(home)!=record:raise ValueError
                compose_fence_finalize._same_inode(directory,journal.NAME,files[journal.NAME])
                os.unlink(journal.NAME,dir_fd=directory);os.fsync(directory)
            if read_cleanup(home,key)!=sealed:raise ValueError
            compose_fence_finalize._same_inode(directory,CLEANUP,files[CLEANUP])
            # State/config were durably committed before sealing. If fsync
            # fails after this final unlink, no marker can be promised.
            os.unlink(CLEANUP,dir_fd=directory);os.fsync(directory)
        if journal.blocks_mutation(home):raise ValueError
        return new
    except Exception:raise FencedUpdateError('FENCED_CLEANUP_INCOMPLETE') from None
    finally:
        if adapter is not None:adapter.close()


def finalize_target(home,source,target,publisher,executor_key,key,destination):
    """Commit a verified target once; remove authenticated evidence only last."""
    backup_snapshot._require_legacy_operation_lock(home)
    home=Path(home);record=journal.read(home)
    if record['phase'] not in ('target_running','update_finalizing'):
        raise FencedUpdateError('FENCED_UPDATE_FINALIZE_STATE_UNVERIFIED')
    names=list(_evidence_names())+[journal.NAME]
    adapter=None
    try:
        for name in (journal.FINALIZE_ANCHOR,'backup-operation.json','recovery-operation.json',
                     'session-migration-block.json','redis-loopback-intent.json','redis-loopback-attempt.json'):
            if os.path.lexists(home/name):raise ValueError
        with compose_fence_finalize._pin_files(home,names) as (directory,files):
            intent,old,new=_verify_binding(home,source,target,publisher,executor_key,key,destination,record,
                                           allow_committed=record['phase']=='update_finalizing')
            if Path(target)!=home/'releases'/new['version']:raise ValueError
            read_target_start(home,key,record,intent)
            result=read_target_result(home,key,record,intent)
            compose_fence_start.read_intent(home,key,record,intent['source_sha256'])
            adapter=compose_nsfirewall_adapter.Adapter(home,source,publisher,key)
            plan=adapter._plan(record);site=uterctl.site_config(home)
            cfg=_verify_running_source(adapter,record,plan,source,publisher,old,new,site,
                                       allow_committed=record['phase']=='update_finalizing')
            saved=compose_fence_finalize.checkpoint.read(home,record,key)
            compose_fence_finalize._attach_running_redis(adapter,record,plan,saved)
            binding=_released_binding(home,old,site,intent,executor_key,destination)
            verified=_verify_mutation_backup(adapter,record,executor_key,destination,intent,binding)
            with tempfile.TemporaryDirectory(prefix='uter-compose-verify-') as temporary:
                command,env=_compose_command(home,target,new,site,temporary)
                writers=compose_fence_start._writers(command,env,site['name'],new)
            if _target_value(record,intent,writers)!=result:raise ValueError
            for service in ('agent','guardrail'):
                compose_fence_resume._healthy(adapter,writers[service],service,site['name'])
            adapter._live_namespace(plan,restart='unless-stopped')
            adapter._network_and_volume(plan);adapter._peers(plan);adapter._redis_config(plan)
            adapter._check_firewall(installed=False)
            for name in names:compose_fence_finalize._same_inode(directory,name,files[name])
            if record['phase']=='target_running':
                final=journal.advance(home,operation=record['operation'],expected='target_running',next_phase='update_finalizing')
            else:final=record
            state={'current':new,'previous':old,'pending':None,'adopted_installer':True,
                   'last_backup':{'id':verified['id'],'path':str(Path(destination).resolve()),'version':old['version']}}
            # Two files cannot be committed atomically together. The journal
            # remains blocking until both fsyncs succeed, including on crash.
            cfg=dict(cfg,images=new['images'])
            _durable_json(home,'install.json',cfg);_durable_json(home,'state.json',state)
            seal_cleanup(home,key,final,plan,saved,intent,result,old,new,site,verified,destination,directory,files)
            return finish_sealed_cleanup(home,target,publisher,executor_key,key,destination)
    except Exception:raise FencedUpdateError('FENCED_UPDATE_FINALIZE_INCOMPLETE') from None
    finally:
        if adapter is not None:adapter.close()
