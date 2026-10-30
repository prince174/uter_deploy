"""Experimental checked cleanup after the original Compose writers resume.

Never restores a backup or changes a workload. Traffic may have changed data
since Redis release. Trust the signed executor, filesystem owner and ancestors,
host/root, daemon and administrators; old or parallel controllers must not run.
Partial cleanup leaves the blocking journal for inspection and is not retried.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import select
import stat

import uterctl
from scripts import (compose_fence_origin as origin, compose_fence_recovery_plan as plans,
                     compose_fence_resume as resume, compose_fence_start as start,
                     compose_nsfirewall_checkpoint as checkpoint, compose_redis_diagnostic as diagnostic,
                     compose_snapshot_only as snapshot, redis_fence_journal as journal,
                     snapshot_only_receipts as receipts)


class FinalizeError(ValueError): pass


@contextmanager
def _pin_files(home,names):
    """Pin each validated path; never delete a replaced inode."""
    directory=journal._directory(home);files={}
    try:
        for name in names:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077
                    or info.st_nlink!=1 or info.st_size>16384):
                os.close(fd);raise FinalizeError('FENCE_FINALIZE_EVIDENCE_UNSAFE')
            files[name]=(fd,info)
        yield directory,files
    except OSError:raise FinalizeError('FENCE_FINALIZE_EVIDENCE_UNSAFE') from None
    finally:
        for fd,_ in files.values():os.close(fd)
        os.close(directory)


def _same_inode(directory,name,pinned):
    fd,before=pinned
    current=os.fstat(fd);named=os.stat(name,dir_fd=directory,follow_symlinks=False)
    signature=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_nlink)
    if signature(current)!=signature(before) or signature(named)!=signature(before):
        raise FinalizeError('FENCE_FINALIZE_EVIDENCE_CHANGED')


def _attach_running_redis(adapter,record,plan,saved):
    """Pin and inspect the original Redis/netns without requiring stopped writers."""
    if checkpoint.boot_id()!=saved['boot_id'] or checkpoint.process_start(saved['pid'])!=saved['pid_start']:
        raise FinalizeError('FENCE_FINALIZE_REDIS_CHANGED')
    adapter.operation=record['operation'];adapter.redis_pid=saved['pid'];adapter.initial_hash=saved['firewall_sha256']
    adapter.daemon_pid=adapter._daemon_identity()
    adapter.daemon_pidfd=os.pidfd_open(adapter.daemon_pid,0)
    if select.select([adapter.daemon_pidfd],[],[],0)[0] or adapter._daemon_identity()!=adapter.daemon_pid:
        raise FinalizeError('FENCE_FINALIZE_DAEMON_CHANGED')
    adapter.daemon_fd=os.open('/proc/'+str(adapter.daemon_pid)+'/ns/net',os.O_RDONLY)
    adapter.fd=os.open('/proc/'+str(adapter.redis_pid)+'/ns/net',os.O_RDONLY)
    adapter.net_identity=adapter._fd_nonhost()
    if (adapter.net_identity!=(saved['net_dev'],saved['net_ino'])
            or checkpoint.process_start(adapter.redis_pid)!=saved['pid_start']):
        raise FinalizeError('FENCE_FINALIZE_REDIS_CHANGED')
    adapter._live_namespace(plan,restart='unless-stopped')
    adapter._network_and_volume(plan);adapter._peers(plan);adapter._redis_config(plan)
    adapter._check_firewall(installed=False)


def _validate_live(adapter,record,executor_key,destination):
    """Recheck signed installation, original IDs, Redis, health and all HMACs."""
    if journal.read(adapter.home)!=record or record['phase']!='writers_resumed':raise ValueError
    for name in (journal.FINALIZE_ANCHOR,journal.UPDATE_INTENT,journal.UPDATE_START,journal.UPDATE_RESULT,'backup-operation.json','recovery-operation.json','session-migration-block.json',
                 'redis-loopback-intent.json','redis-loopback-attempt.json'):
        if os.path.lexists(adapter.home/name):raise ValueError
    diagnostic.inspect_installation(adapter.home,adapter.bundle,adapter.publisher_key)
    signed=uterctl.verify(adapter.bundle,adapter.publisher_key)
    installed=adapter.home/'releases'/signed['version']
    if (uterctl.verify(installed,adapter.publisher_key)!=signed
            or (installed/'checksums.json').read_bytes()!=(adapter.bundle/'checksums.json').read_bytes()):raise ValueError
    state=uterctl.read(adapter.home/'state.json')
    if state.get('current')!=signed or state.get('pending') is not None or state.get('adopted_installer') is not True:
        raise ValueError
    adapter._lock();adapter._config(installed)
    plan=adapter._plan(record);saved=checkpoint.read(adapter.home,record,adapter.backup_key)
    _attach_running_redis(adapter,record,plan,saved)
    bundle_hash=hashlib.sha256(snapshot._file(adapter.bundle/'checksums.json')).hexdigest()
    original=start.read_intent(adapter.home,adapter.backup_key,record,bundle_hash)
    resumed=resume.read_intent(adapter.home,adapter.backup_key,record)
    released=origin.read(adapter.home,adapter.backup_key,record)
    resume._current_writer_ids(adapter,plan,original)
    for name in ('agent','guardrail'):resume._healthy(adapter,original[name],name,record['site'])
    executor_hash=snapshot._executor(uterctl.ROOT,executor_key)
    site=uterctl.site_config(adapter.home)
    binding={'current':signed,'site':site,'bundle':bundle_hash,
             'checkpoint':hashlib.sha256(snapshot._file(adapter.home/checkpoint.NAME)).hexdigest(),
             'executor':executor_hash,'destination':hashlib.sha256(str(Path(destination).resolve()).encode()).hexdigest() if destination else None}
    receipt_hash=resume._backup_evidence(adapter,record,executor_key,destination,released,binding=binding)
    if (resumed['start_intent_sha256']!=hashlib.sha256(start._canonical(original)).hexdigest()
            or resumed['bundle_sha256']!=bundle_hash or resumed['executor_sha256']!=executor_hash
            or resumed['backup_receipt_sha256']!=receipt_hash):raise ValueError
    return released


def finalize(adapter,record,executor_key,destination):
    """Validate first; remove only authenticated operation files, journal last."""
    try:
        # Select files by an authenticated origin; absent snapshot receipts are
        # never interpreted as proof of a pre-capture release.
        released=origin.read(adapter.home,adapter.backup_key,record)
        names=[plans.NAME,checkpoint.NAME,start.NAME,origin.NAME,resume.NAME,journal.NAME]
        if released['origin']=='snapshot':names += [receipts.DESCRIPTOR,receipts.RECEIPT,receipts.DECISION]
        with _pin_files(adapter.home,names) as (directory,files):
            if _validate_live(adapter,record,executor_key,destination)!=released:raise ValueError
            for name in names:_same_inode(directory,name,files[name])
            # Durable marker is written before any deletion. An interrupted or
            # uncertain cleanup cannot be replayed automatically.
            final=journal.advance(adapter.home,operation=record['operation'],expected='writers_resumed',next_phase='finalizing')
            with _pin_files(adapter.home,[journal.NAME]) as (last_directory,last_files):
                if journal.read(adapter.home)!=final:raise ValueError
                for name in names:
                    if name==journal.NAME:continue
                    _same_inode(directory,name,files[name]);os.unlink(name,dir_fd=directory);os.fsync(directory)
                if journal.read(adapter.home)!=final:raise ValueError
                _same_inode(last_directory,journal.NAME,last_files[journal.NAME])
                # A durable hardlink blocks current controllers even if the
                # original marker is unlinked and the following fsync fails.
                # Old released controllers do not know this extra guard.
                os.link(journal.NAME,journal.FINALIZE_ANCHOR,src_dir_fd=last_directory,
                        dst_dir_fd=last_directory,follow_symlinks=False)
                os.fsync(last_directory)
                try:
                    os.unlink(journal.NAME,dir_fd=last_directory);os.fsync(last_directory)
                except OSError:
                    # Best effort only; if this fails the anchor itself still
                    # blocks the current controller and requires inspection.
                    try:
                        os.link(journal.FINALIZE_ANCHOR,journal.NAME,src_dir_fd=last_directory,
                                dst_dir_fd=last_directory,follow_symlinks=False)
                        os.fsync(last_directory)
                    except OSError:pass
                    raise
                # Journal deletion is now durable. Failure removing this extra
                # anchor leaves a safe blocking marker unless unlink succeeded.
                os.unlink(journal.FINALIZE_ANCHOR,dir_fd=last_directory);os.fsync(last_directory)
    except Exception:
        # Never stop/start containers, replay deletion, or restore old data.
        raise FinalizeError('FENCE_FINALIZE_INCOMPLETE') from None
