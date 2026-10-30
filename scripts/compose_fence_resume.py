"""Experimental return of original Compose writers after Redis fence release.

This is NOT rollback. Traffic and new writes may begin as soon as a container
starts, before it is healthy. A durable one-shot intent and journal transition
precede the first start; after that point no retry, stop or restoration of an
older backup is attempted here. The marker remains even after success.

Trust the signed executor, host/root, kernel, daemon, Docker CLI and admins;
no old/parallel controller or external intervention may race this operation.
Health is Docker's reported readiness, not proof of absence of data changes.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import time

import uterctl
from scripts import (backup_crypto, backup_store, compose_fence_origin as origin, compose_fence_start as start,
                     compose_snapshot_only as snapshot, redis_fence_journal as journal,
                     snapshot_only_receipts as receipts, install, install_recovery)

NAME='compose-fence-resume-intent.json'


class ResumeError(ValueError): pass


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def _intent_mac(key,record):
    if not isinstance(key,bytes) or len(key)!=32:raise ResumeError('FENCE_RESUME_KEY_INVALID')
    derived=backup_crypto.derive_key(key,b'compose-fence-resume-intent-v1')
    return hmac.new(derived,_canonical(record),hashlib.sha256).hexdigest()


def _validate(record):
    fields={'schema','operation','plan_sha256','start_intent_sha256','bundle_sha256','executor_sha256','backup_receipt_sha256'}
    if (not isinstance(record,dict) or set(record)!=fields or type(record['schema']) is not int or record['schema']!=1
            or not isinstance(record['operation'],str) or not re.fullmatch(r'[0-9a-f]{32}',record['operation'])
            or any(not isinstance(record[k],str) or not re.fullmatch(r'[0-9a-f]{64}',record[k])
                   for k in fields-{'schema','operation'})):
        raise ResumeError('FENCE_RESUME_INTENT_INVALID')
    return record


def _write_intent(home,key,record):
    _validate(record);raw=_canonical({'intent':record,'mac':_intent_mac(key,record)})+b'\n'
    directory=journal._directory(home)
    try:
        try:
            fd=os.open(NAME,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as target:
                os.fchmod(target.fileno(),0o600);target.write(raw);target.flush();os.fsync(target.fileno())
            os.fsync(directory)
        except OSError:raise ResumeError('FENCE_RESUME_INTENT_UNCERTAIN') from None
    finally:os.close(directory)


def read_intent(home,key,record):
    """Authenticate bounded intent and bind its operation to the journal."""
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
            intent=_validate(envelope['intent']);mac=envelope['mac']
            if (not isinstance(mac,str) or not re.fullmatch(r'[0-9a-f]{64}',mac)
                    or not hmac.compare_digest(mac,_intent_mac(key,intent))
                    or intent['operation']!=record['operation'] or intent['plan_sha256']!=record['plan_sha256']):
                raise ValueError
            return intent
        except (OSError,ValueError,TypeError,KeyError,UnicodeError):
            raise ResumeError('FENCE_RESUME_INTENT_UNVERIFIED') from None
    finally:os.close(directory)


def _backup_evidence(adapter,record,executor_key,destination,release_origin,*,binding=None):
    """Verify a prior snapshot if any receipt exists; return its receipt hash."""
    paths=[adapter.home/name for name in (receipts.DESCRIPTOR,receipts.RECEIPT,receipts.DECISION)]
    present=[os.path.lexists(path) for path in paths]
    if release_origin['origin']=='pre_capture':
        if any(present) or destination is not None:raise ResumeError('FENCE_RESUME_BACKUP_UNEXPECTED')
        return '0'*64
    if release_origin['origin']!='snapshot' or not all(present) or destination is None:
        raise ResumeError('FENCE_RESUME_BACKUP_UNVERIFIED')
    if binding is None:
        binding=snapshot._bound(adapter,record,uterctl.ROOT,executor_key,destination)
    descriptor,_=receipts.read_descriptor(adapter.home,adapter.backup_key)
    receipt,receipt_hash=receipts.read_receipt(adapter.home,adapter.backup_key)
    decision,_=receipts.read_decision(adapter.home,adapter.backup_key)
    if (descriptor['operation']!=record['operation'] or descriptor['backend']!='compose'
            or descriptor['site']!=record['site'] or descriptor['resource']!=record['resource']
            or descriptor['identity_sha256']!=record['plan_sha256']
            or descriptor['release_version']!=binding['current']['version']
            or descriptor['bundle_sha256']!=binding['bundle']
            or descriptor['fence_checkpoint_sha256']!=binding['checkpoint']
            or descriptor['backup_location_sha256']!=binding['destination']
            or descriptor['executor_sha256']!=binding['executor'] or decision['action']!='release'
            or release_origin['receipt_sha256']!=receipt_hash):
        raise ResumeError('FENCE_RESUME_BACKUP_UNVERIFIED')
    manifest=snapshot._file(Path(destination)/'manifest.json')
    verified=backup_store.verify_set(destination,adapter.backup_key,home=adapter.home,
                                     site=binding['site'],version=binding['current']['version'])
    if (verified['id']!=descriptor['backup_id'] or verified['id']!=receipt['backup_id']
            or hashlib.sha256(manifest).hexdigest()!=receipt['manifest_sha256']
            or snapshot._file(Path(destination)/'manifest.json')!=manifest):
        raise ResumeError('FENCE_RESUME_BACKUP_UNVERIFIED')
    return receipt_hash


def _current_writer_ids(adapter,plan,intent):
    cfg=uterctl.read(adapter.home/'install.json');command,env=install.commands(adapter.home,cfg)
    command[command.index('-f')+1]=str(adapter.home/'releases'/uterctl.read(adapter.home/'state.json')['current']['version']/'compose/compose.yaml')
    for service in ('guardrail','agent'):
        raw=install_recovery.run_readonly(command+['ps','-aq',service],timeout=30,env=env).strip()
        if not re.fullmatch(r'[0-9a-f]{12,64}',raw):raise ResumeError('FENCE_RESUME_WRITER_IDENTITY')
        value=adapter._json('inspect','--format','{{json .Id}}',raw)
        if value!=intent[service]['id']:raise ResumeError('FENCE_RESUME_WRITER_IDENTITY')


def _healthy(adapter,writer,service,site,timeout=180):
    fmt=('{"id":{{json .Id}},"running":{{json .State.Running}},"health":{{json .State.Health.Status}},'
         '"restart_count":{{json .RestartCount}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
         '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
         '"image_ref":{{json .Config.Image}},"image_id":{{json .Image}}}')
    deadline=time.monotonic()+timeout
    while True:
        state=adapter._json('inspect','--format',fmt,writer['id'])
        if (not isinstance(state,dict) or state.get('id')!=writer['id'] or state.get('running') is not True
                or state.get('restart_count')!=writer['restart_count'] or state.get('project')!=site
                or state.get('service')!=service or state.get('image_ref')!=writer['image_ref']
                or state.get('image_id')!=writer['image_id']):raise ResumeError('FENCE_RESUME_WRITER_IDENTITY')
        health=state.get('health')
        if health=='healthy':return
        if health!='starting' or time.monotonic()>=deadline:raise ResumeError('FENCE_RESUME_HEALTH_UNCERTAIN')
        time.sleep(2)


def resume(adapter,record,executor_key,destination):
    """Resume only original writers once; caller holds the O_EXCL lock."""
    try:
        if any(os.path.lexists(adapter.home/name) for name in (journal.UPDATE_INTENT,journal.UPDATE_START,journal.UPDATE_RESULT)):raise ValueError
        if journal.read(adapter.home)!=record or record['phase']!='redis_released':raise ValueError
        plan=adapter._plan(record)
        if adapter._attach_recovery(record,('redis_released',)) is not True or adapter.installed:
            raise ValueError
        bundle_hash=hashlib.sha256(snapshot._file(adapter.bundle/'checksums.json')).hexdigest()
        original=start.read_intent(adapter.home,adapter.backup_key,record,bundle_hash)
        release_origin=origin.read(adapter.home,adapter.backup_key,record)
        writers={name:original[name] for name in ('guardrail','agent')}
        start._writers_stopped(writers,record['site'])
        _current_writer_ids(adapter,plan,original)
        receipt_hash=_backup_evidence(adapter,record,executor_key,destination,release_origin)
        executor_hash=snapshot._executor(uterctl.ROOT,executor_key)
        intent={'schema':1,'operation':record['operation'],'plan_sha256':record['plan_sha256'],
                'start_intent_sha256':hashlib.sha256(start._canonical(original)).hexdigest(),
                'bundle_sha256':bundle_hash,'executor_sha256':executor_hash,'backup_receipt_sha256':receipt_hash}
        _write_intent(adapter.home,adapter.backup_key,intent)
        # This durable transition is the point after which new data MAY exist.
        journal.advance(adapter.home,operation=record['operation'],expected='redis_released',next_phase='writers_resuming')
        for service in ('agent','guardrail'):
            adapter._run('start',writers[service]['id'])
            _healthy(adapter,writers[service],service,record['site'])
        # No user-facing request or mutating smoke is executed.
        adapter._live_namespace(plan,restart='unless-stopped')
        adapter._network_and_volume(plan);adapter._peers(plan);adapter._redis_config(plan)
        for service in ('agent','guardrail'):_healthy(adapter,writers[service],service,record['site'])
        current=journal.read(adapter.home)
        if current['phase']!='writers_resuming' or read_intent(adapter.home,adapter.backup_key,current)!=intent:
            raise ValueError
        journal.advance(adapter.home,operation=record['operation'],expected='writers_resuming',next_phase='writers_resumed')
    except Exception:
        # No automatic stop, retry or older-snapshot restore on unknown outcome.
        raise ResumeError('FENCE_RESUME_INCOMPLETE') from None
