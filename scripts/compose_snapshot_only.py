"""Experimental signed snapshot-only Compose sequence; never an update gate.

The controller, host, Docker daemon and root are trusted; no concurrent exec,
old controller or outside writers are allowed. The caller holds the existing
controller lock. This code does not establish session ownership, migrate data,
restart application writers, or authorize changing releases. An uncertain result
leaves the journals and writers stopped. The independently signed executor
bundle binds the running source to a trusted ephemeral key in CI; this is not a
published or production recovery tool.
"""
import hashlib
import json
import os
from pathlib import Path
import stat

import uterctl
from scripts import (backup_snapshot, backup_store, compose_nsfirewall_adapter as fence,
                     compose_nsfirewall_checkpoint as checkpoint, redis_fence_journal as journal,
                     snapshot_only_receipts as receipts)

ROOT=Path(__file__).resolve().parents[1]


class SnapshotOnlyError(ValueError): pass


def _hash(raw): return hashlib.sha256(raw).hexdigest()


def _assert_adapter(adapter):
    # No public callback, subclass or caller-supplied backend can establish a
    # snapshot-only proof. Trusted signed controller creates this exact class.
    if type(adapter) is not fence.Adapter:raise SnapshotOnlyError('SNAPSHOT_ADAPTER_UNVERIFIED')


def _file(path, limit=16*1024*1024):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>limit:raise ValueError
            raw=stream.read(limit+1)
        if len(raw)>limit:raise ValueError
        return raw
    except (OSError,ValueError):raise SnapshotOnlyError('SNAPSHOT_FILE_UNVERIFIED') from None


def _executor(bundle,publisher):
    """Verify signed bundle and exact running source, not just an asserted hash."""
    try:
        bundle=Path(bundle).resolve(strict=True)
        uterctl.verify(bundle,publisher)
        signed=json.loads(_file(bundle/'checksums.json'))
        sources=[Path('uterctl.py'),*(p.relative_to(ROOT) for p in (ROOT/'scripts').glob('*.py'))]
        for relative in sources:
            expected=signed.get(relative.as_posix())
            if not isinstance(expected,str) or _hash(_file(ROOT/relative))!=expected:
                raise ValueError
        return _hash(_file(bundle/'checksums.json'))
    except Exception:raise SnapshotOnlyError('SNAPSHOT_EXECUTOR_UNVERIFIED') from None


def _bound(adapter,record,executor_bundle,executor_publisher,destination):
    """Re-establish signed product, plan, checkpoint, executor and backup scope."""
    try:
        plan=adapter._plan(record)
        adapter._signed(plan)
        current=uterctl.read(adapter.home/'state.json')['current']
        cfg=uterctl.read(adapter.home/'install.json')
        site=uterctl.site_config(adapter.home)
        if cfg.get('backend')!='compose' or site.get('backend')!='compose':raise ValueError
        checkpoint.read(adapter.home,record,adapter.backup_key)
        destination=Path(destination).resolve()
        if destination==adapter.home.resolve() or destination.is_relative_to(adapter.home.resolve()):raise ValueError
        return {'plan':plan,'current':current,'site':site,
                'bundle':_hash(_file(adapter.bundle/'checksums.json')),
                'checkpoint':_hash(_file(adapter.home/checkpoint.NAME)),
                'executor':_executor(executor_bundle,executor_publisher),
                'destination':_hash(str(destination).encode())}
    except Exception:raise SnapshotOnlyError('SNAPSHOT_IDENTITY_UNVERIFIED') from None


def capture(adapter,record,executor_bundle,executor_publisher,destination):
    """Capture only; leave Redis fenced and writers stopped on any outcome."""
    try:
        _assert_adapter(adapter)
        if journal.read(adapter.home)!=record or record['phase']!='isolated':raise ValueError
        binding=_bound(adapter,record,executor_bundle,executor_publisher,destination)
        if adapter.verify_fenced(record) is not True:raise ValueError
        writer=backup_store.BackupWriter(destination,adapter.backup_key,adapter.home,binding['site'],binding['current']['version'])
        descriptor={'schema':1,'operation':record['operation'],'backend':'compose','site':record['site'],
                    'resource':record['resource'],'release_version':binding['current']['version'],
                    'bundle_sha256':binding['bundle'],'fence_checkpoint_sha256':binding['checkpoint'],
                    'identity_sha256':record['plan_sha256'],'backup_id':writer.manifest['id'],
                    'backup_location_sha256':binding['destination'],'executor_sha256':binding['executor']}
        descriptor_hash=receipts.write_descriptor(adapter.home,adapter.backup_key,descriptor)
        journal.advance(adapter.home,operation=record['operation'],expected='isolated',next_phase='capturing')
        backup_snapshot.archive_runtime(adapter.home,writer)
        plan=binding['plan'];redis=plan['container_id']
        guard=adapter._run('ps','-aq','--filter','label=com.docker.compose.project='+plan['site'],
                           '--filter','label=com.docker.compose.service=guardrail')
        if not guard or len(guard.splitlines())!=1:raise ValueError
        redis_cmd=['docker','--context','default','exec',redis,'sh','-ec',
                   'export REDISCLI_AUTH="$(cat /run/secrets/redis_password)"; exec redis-cli --rdb -']
        audit=['docker','--context','default','cp',guard+':/var/lib/uter/audit/.','-']
        check=['docker','--context','default','exec','-i',redis,'redis-check-rdb','/dev/stdin']
        backup_snapshot.process_component(writer,'redis',redis_cmd,prefix=b'REDIS')
        backup_snapshot.process_component(writer,'audit',audit)
        backup_snapshot.verify_encrypted_tar(writer,'runtime');backup_snapshot.verify_encrypted_tar(writer,'audit')
        backup_snapshot.verify_redis_snapshot(writer,check)
        if adapter.verify_fenced(record) is not True:raise ValueError
        manifest=writer.finish()
        verified=backup_store.verify_set(destination,adapter.backup_key,home=adapter.home,
                                         site=binding['site'],version=binding['current']['version'])
        if verified!=manifest or adapter.verify_fenced(record) is not True:raise ValueError
        receipt={'schema':1,'operation':record['operation'],'descriptor_sha256':descriptor_hash,
                 'backup_id':manifest['id'],'manifest_sha256':_hash(_file(Path(destination)/'manifest.json'))}
        receipts.write_receipt(adapter.home,adapter.backup_key,receipt)
        receipts.write_decision(adapter.home,adapter.backup_key,'release')
        journal.advance(adapter.home,operation=record['operation'],expected='capturing',next_phase='captured')
        return manifest['id']
    except Exception:raise SnapshotOnlyError('SNAPSHOT_CAPTURE_INCOMPLETE') from None


def recover(adapter,executor_bundle,executor_publisher,destination):
    """Only restore original Redis after proven snapshot-only decision; no writers."""
    try:
        _assert_adapter(adapter)
        record=journal.read(adapter.home)
        if record['backend']!='compose' or record['phase'] not in ('captured','snapshot_releasing'):raise ValueError
        binding=_bound(adapter,record,executor_bundle,executor_publisher,destination)
        descriptor,_=receipts.read_descriptor(adapter.home,adapter.backup_key)
        receipt,_=receipts.read_receipt(adapter.home,adapter.backup_key)
        decision,_=receipts.read_decision(adapter.home,adapter.backup_key)
        if (descriptor['operation']!=record['operation'] or descriptor['backend']!='compose'
                or descriptor['site']!=record['site'] or descriptor['resource']!=record['resource']
                or descriptor['identity_sha256']!=record['plan_sha256']
                or descriptor['release_version']!=binding['current']['version']
                or descriptor['bundle_sha256']!=binding['bundle']
                or descriptor['fence_checkpoint_sha256']!=binding['checkpoint']
                or descriptor['backup_location_sha256']!=binding['destination']
                or descriptor['executor_sha256']!=binding['executor'] or decision['action']!='release'):
            raise ValueError
        manifest_raw=_file(Path(destination)/'manifest.json')
        verified=backup_store.verify_set(destination,adapter.backup_key,home=adapter.home,
                                         site=binding['site'],version=binding['current']['version'])
        if (verified['id']!=descriptor['backup_id'] or verified['id']!=receipt['backup_id']
                or _hash(manifest_raw)!=receipt['manifest_sha256']
                or _file(Path(destination)/'manifest.json')!=manifest_raw):raise ValueError
        if adapter._attach_snapshot_recovery(record) is not True:raise ValueError
        if record['phase']=='captured':
            if adapter.verify_fenced(record) is not True:raise ValueError
            record=journal.advance(adapter.home,operation=record['operation'],expected='captured',next_phase='snapshot_releasing')
        if adapter._recover_snapshot_only(record) is not True:raise ValueError
        journal.advance(adapter.home,operation=record['operation'],expected='snapshot_releasing',next_phase='redis_released')
        return verified['id']
    except Exception:raise SnapshotOnlyError('SNAPSHOT_RECOVERY_INCOMPLETE') from None
