"""Persist and reauthenticate a bounded Kubernetes recovery session.

The caller holds the installation lock and uses independently provisioned pins,
keys and a signed, isolated executor. This provides neither isolation nor data
durability and cannot authorize an update. No mutation is performed here.
"""
from contextlib import ExitStack,contextmanager
import hashlib
import hmac
import os
from pathlib import Path

import uterctl
from scripts import (backup_installation, backup_snapshot, kubernetes_fence_coordinator as coordinator,
                     kubernetes_fence_finalizer as finalizer, kubernetes_fence_pin as pin,
                     kubernetes_fence_profile_store as store, kubernetes_pinned_preflight as preflight,
                     kubernetes_sealed_config as sealed, kubernetes_writer_quiesce as storage,
                     kubernetes_trusted_kubectl as kubectl_binary, redis_fence_journal as journal)

NAME='kubernetes-fence-recovery-auth.json'


class RecoverySessionError(ValueError):pass


def _evidence(session,operation,plan):
    root,key,identity=session._executor
    return {'schema':1,'operation':operation,'site':session.site,'pod_uid':plan['uid'],
            'pod_plan_sha256':finalizer.plan_hash(plan),'profile_sha256':session._profile_digest,
            'config_sha256':session.config_sha256,'inventory_sha256':session.inventory_digest,
            'publisher_sha256':session.key_digest,'executor_inventory_sha256':identity[1],
            'executor_publisher_sha256':identity[2]}


def seal_before_mutation(session,operation,key):
    """Create one authenticated recovery binding while the original Pod is live."""
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        session.reverify()
        plan=finalizer.read_plan(session.home)
        finalizer._check_journal(session.home,plan,operation,'prepared')
        actual=backup_installation.safe_file(session._key_path,private=True,limit=32)
        if not hmac.compare_digest(actual,key):raise ValueError
        record=_evidence(session,operation,plan)
        storage._write(session.home,NAME,record,key)
        session._guard()
        return {'recovery_binding_saved':True,'safe_to_update':False}
    except Exception:raise RecoverySessionError('KUBE_RECOVERY_BINDING_UNVERIFIED') from None


@contextmanager
def checked_recovery_session(home,bundle,publisher_key,kubeconfig_path,profile_path,backup_key_path,
                             *,executor_bundle,executor_key,kubectl_path):
    """Reauthenticate changed workloads without treating them as pristine."""
    with ExitStack() as stack:
        try:
            home=backup_installation.private_directory(home)
            backup_snapshot._require_legacy_operation_lock(home)
            paths=[backup_installation.checked_existing_path(x) for x in
                   (kubeconfig_path,profile_path,backup_key_path,publisher_key,executor_key)]
            config,profile,key_path,publisher,executor_key_path=paths
            signed_bundle=Path(bundle).resolve(strict=True);executor_root=Path(executor_bundle).resolve(strict=True)
            if (len(set(paths[:3]))!=3 or any(x.is_relative_to(home) or x.is_relative_to(signed_bundle)
                                              for x in paths[:3])
                    or executor_key_path in paths[:3] or executor_key_path.is_relative_to(home)):
                raise ValueError
            key=backup_installation.safe_file(key_path,private=True,limit=32)
            if len(key)!=32:raise ValueError
            record,digest=store.read(profile,key)
            if record['schema']!=2:raise ValueError
            raw=backup_installation.safe_file(config,private=True,limit=pin.MAX_CONFIG)
            executor=(executor_root,executor_key_path,coordinator._executor_identity(executor_root,executor_key_path))
            manifest=uterctl.verify(signed_bundle,publisher)
            publisher_digest=hashlib.sha256(backup_installation.safe_file(publisher,limit=65536)).hexdigest()
            inventory_digest=hashlib.sha256(backup_installation.safe_file(signed_bundle/'checksums.json',limit=1024*1024)).hexdigest()
            state=uterctl.read(home/'state.json');cfg=uterctl.read(home/'install.json');site=uterctl.site_config(home)
            name=site['name']
            if (state.get('current')!=manifest or state.get('pending') is not None or state.get('adopted_installer') is not True
                    or cfg.get('backend')!='kubernetes' or site.get('backend')!='helm'
                    or cfg.get('name')!=name or site.get('namespace')!=name or name!=record['site']
                    or cfg.get('context')!=site.get('context') or cfg.get('context')!=record['api']['context']
                    or manifest.get('version')!=record['release_version']
                    or inventory_digest!=record['inventory_sha256'] or publisher_digest!=record['publisher_sha256']):
                raise ValueError
            fd,config_digest=stack.enter_context(sealed.sealed(raw,record['api']))
            binary_fd=kubectl_binary.open_binary(kubectl_path,record['kubectl_sha256'])
            stack.callback(os.close,binary_fd)
            api=finalizer.Kubectl(context=record['api']['context'],namespace=name,config_fd=fd,config_sha256=config_digest,
                                  binary_fd=binary_fd,binary_sha256=record['kubectl_sha256'])
            inner=preflight.Session(home,api,manifest,record['api'],name,fd,config_digest,signed_bundle,publisher,
                                    publisher_digest,inventory_digest)
            session=coordinator.BoundSession(inner,profile,key_path,record,digest,hashlib.sha256(key).hexdigest(),executor)
            state=journal.read(home);plan=finalizer.read_plan(home)
            if state['phase'] not in ('prepared','isolating','aborting') or state['site']!=name:raise ValueError
            finalizer._check_journal(home,plan,state['operation'],state['phase'])
            if storage._read(home,NAME,key)!=_evidence(session,state['operation'],plan):raise ValueError
            session._scope()
        except Exception:raise RecoverySessionError('KUBE_RECOVERY_SESSION_UNVERIFIED') from None
        yield session
