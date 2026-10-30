"""Experimental encrypted Kubernetes backup set under the pinned session.

Not a user CLI, upgrade permission, or proof of the operator's independent
control-plane, node, CSI, CNI, admission and exclusive-writer assumptions. The
backup requires an authenticated completion receipt; an interrupted operation
and any unreceipted set must be inspected, never automatically replayed.
"""
import hashlib
import os
from pathlib import Path
import re
from types import SimpleNamespace
import time

import uterctl
from scripts import (backup_installation, backup_snapshot, backup_store,
                     kubernetes_audit_reader as audit, kubernetes_audit_writer_guard as writer_guard,
                     kubernetes_config_snapshot as config, kubernetes_loopback_snapshot as redis,
                     kubernetes_runtime_pin as runtime_pin,
                     kubernetes_writer_quiesce as storage)

ATTEMPT='kubernetes-backup-attempt.json'
RECEIPT='kubernetes-backup-receipt.json'


class BackupCoordinatorError(ValueError):pass


def _wait(check,timeout):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            value=check()
            if value:return value
        except Exception:pass
        time.sleep(.5)
    raise BackupCoordinatorError('KUBE_BACKUP_OBSERVATION_UNCERTAIN')


def capture(session,operation,redis_pod,redis_uid,destination,*,timeout=180):
    """Capture one set and record a receipt only after all component checks."""
    try:
        if session._executor is None or session._record['schema']!=2 or type(timeout) is not int or not 1<=timeout<=180:
            raise ValueError
        home=session.home;key_path=session._key_path
        key=backup_installation.safe_file(key_path,private=True,limit=32)
        if len(key)!=32:raise ValueError
        destination=Path(destination)
        if not destination.is_absolute() or '..' in destination.parts or not destination.name:raise ValueError
        parent=backup_installation.private_directory(destination.parent);destination=parent/destination.name
        if (destination==home or destination.is_relative_to(home) or key_path==destination
                or key_path.is_relative_to(destination) or os.path.lexists(destination)):raise ValueError
        session._scope();writer_guard.verify(session,operation,key);config.reverify(session,operation,key)
        expected_runtime=runtime_pin.verify(session,operation,key)
        redis.assert_loopback(session,operation,redis_pod,redis_uid)
        audit_plan=storage._read(home,'kubernetes-audit-reader-plan.json',key)
        audit.pod_spec(audit_plan)
        if audit_plan['operation']!=operation:raise ValueError
        site=uterctl.site_config(home)
        if site.get('backend')!='helm' or site.get('name')!=session.site or site.get('namespace')!=session.site:raise ValueError
        intent={'operation':operation,'profile_sha256':session._profile_digest,
                'destination_sha256':hashlib.sha256(os.fsencode(destination)).hexdigest()}
        storage._write(home,ATTEMPT,intent,key)
        writer=backup_store.BackupWriter(destination,key,home,site,session.manifest['version'])
        backup_snapshot.archive_runtime(home,writer)
        runtime_pin.verify_archive(writer,key,expected_runtime)
        if runtime_pin.verify(session,operation,key)!=expected_runtime:raise ValueError
        config.capture(session,operation,key,writer)
        redis.capture_component(session,operation,redis_pod,redis_uid,writer)
        redis.verify_component(session,operation,redis_pod,redis_uid,writer)
        redis.assert_loopback(session,operation,redis_pod,redis_uid)
        audit.create(session,operation,key)
        created=storage._read(home,audit.CREATED,key)
        def ready():
            writer_guard.verify(session,operation,key)
            pod=session._query(['get','pod',audit_plan['reader_name']])
            image_id=session.manifest.get('image_config_ids',{}).get('guardrail')
            return audit.verify_pod(audit_plan,pod,created['uid'],ready=True,image_config_id=image_id)
        _wait(ready,timeout)
        audit.capture_audit(session,operation,key,writer)
        audit.delete(session,operation,key)
        _wait(lambda:audit.observe_deletion(session,operation,key)['reader_old_uid_gone'],timeout)
        writer_guard.verify(session,operation,key);config.reverify(session,operation,key)
        if runtime_pin.verify(session,operation,key)!=expected_runtime:raise ValueError
        redis.assert_loopback(session,operation,redis_pod,redis_uid)
        completed=writer.finish()
        verified=backup_store.verify_set(destination,key,home=home,site=site,version=session.manifest['version'])
        if completed!=verified:raise ValueError
        writer_guard.verify(session,operation,key);config.reverify(session,operation,key)
        if runtime_pin.verify(session,operation,key)!=expected_runtime:raise ValueError
        redis.assert_loopback(session,operation,redis_pod,redis_uid)
        if audit.observe_deletion(session,operation,key)['reader_old_uid_gone'] is not True:raise ValueError
        digest=hashlib.sha256(backup_installation.safe_file(destination/'manifest.json',private=True,limit=1024*1024)).hexdigest()
        receipt={'operation':operation,'backup_id':verified['id'],'manifest_sha256':digest,
                 'destination_sha256':intent['destination_sha256'],'profile_sha256':session._profile_digest,
                 'runtime_hmac':expected_runtime,'audit_integrity':'structure_only'}
        storage._write(home,RECEIPT,receipt,key)
        return {'backup_set_verified':True,'backup_id':verified['id'],'safe_to_update':False}
    except Exception:raise BackupCoordinatorError('KUBE_BACKUP_UNCERTAIN_INSPECTION_REQUIRED') from None


def verify_receipt(session,operation,redis_pod,redis_uid,destination):
    """Reauthenticate the exact receipt and complete encrypted set.

    Audit verification here covers archive structure and encryption, not the
    application's audit HMAC chain. This cannot authorize an update.
    """
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        home=session.home;key=backup_installation.safe_file(session._key_path,private=True,limit=32)
        if len(key)!=32:raise ValueError
        destination=Path(destination)
        if not destination.is_absolute() or '..' in destination.parts:raise ValueError
        destination=backup_installation.private_directory(destination)
        if destination==home or destination.is_relative_to(home):raise ValueError
        digest=hashlib.sha256(os.fsencode(destination)).hexdigest()
        intent=storage._read(home,ATTEMPT,key);receipt=storage._read(home,RECEIPT,key)
        if intent!={'operation':operation,'profile_sha256':session._profile_digest,'destination_sha256':digest}:raise ValueError
        fields={'operation','backup_id','manifest_sha256','destination_sha256','profile_sha256','runtime_hmac','audit_integrity'}
        if (set(receipt)!=fields or receipt['operation']!=operation or receipt['profile_sha256']!=session._profile_digest
                or receipt['destination_sha256']!=digest or receipt['audit_integrity']!='structure_only'
                or not isinstance(receipt['backup_id'],str) or not re.fullmatch(r'[0-9a-f]{32}',receipt['backup_id'])
                or any(not isinstance(receipt[field],str) or not re.fullmatch(r'[0-9a-f]{64}',receipt[field])
                       for field in ('manifest_sha256','runtime_hmac'))):raise ValueError
        session._scope();writer_guard.verify(session,operation,key);config.reverify(session,operation,key)
        if runtime_pin.verify(session,operation,key)!=receipt['runtime_hmac']:raise ValueError
        redis.assert_loopback(session,operation,redis_pod,redis_uid)
        site=uterctl.site_config(home)
        if site.get('backend')!='helm' or site.get('name')!=session.site or site.get('namespace')!=session.site:raise ValueError
        manifest=backup_store.verify_set(destination,key,home=home,site=site,version=session.manifest['version'])
        if manifest['id']!=receipt['backup_id']:raise ValueError
        manifest_raw=backup_installation.safe_file(destination/'manifest.json',private=True,limit=1024*1024)
        if hashlib.sha256(manifest_raw).hexdigest()!=receipt['manifest_sha256']:raise ValueError
        writer=SimpleNamespace(path=destination,key=key,manifest=manifest)
        runtime_pin.verify_archive(writer,key,receipt['runtime_hmac'])
        backup_snapshot.verify_encrypted_tar(writer,'audit')
        redis.verify_component(session,operation,redis_pod,redis_uid,writer)
        if audit.observe_deletion(session,operation,key)['reader_old_uid_gone'] is not True:raise ValueError
        writer_guard.verify(session,operation,key);config.reverify(session,operation,key)
        if runtime_pin.verify(session,operation,key)!=receipt['runtime_hmac']:raise ValueError
        redis.assert_loopback(session,operation,redis_pod,redis_uid)
        return {'backup_receipt_verified':True,'audit_integrity':'structure_only','safe_to_update':False}
    except Exception:raise BackupCoordinatorError('KUBE_BACKUP_RECEIPT_UNVERIFIED') from None
