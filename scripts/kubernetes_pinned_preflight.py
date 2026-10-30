"""Read-only pinned Kubernetes preflight for a future fencing coordinator.

Pins must be provisioned independently by a trusted administrator. A matching
pin or live snapshot is not proof of exclusive writers, admission/RBAC/GitOps,
CNI/CSI behaviour, data durability or safe update. Control plane, nodes, host
and all cluster administrators remain trusted. The same sealed kubeconfig fd
is used for each child kubectl; no secret is placed on a command line or disk.
"""
from contextlib import contextmanager
import copy
import hashlib
import json
from pathlib import Path
import re

import uterctl
from scripts import (backup_installation, backup_snapshot, kubernetes_fence_finalizer as finalizer,
                     kubernetes_fence_pin as pin, kubernetes_redis_identity as identity,
                     kubernetes_sealed_config as sealed)


class PreflightError(ValueError): pass


class Session:
    """A checked connection; reverify before each dependent operation."""
    def __init__(self,home,api,manifest,profile,site,config_fd,config_sha256,bundle,publisher_key,key_digest):
        self.home=Path(home);self.api=api;self.manifest=copy.deepcopy(manifest);self.profile=copy.deepcopy(profile);self.site=site
        self.config_fd=config_fd;self.config_sha256=config_sha256
        self.bundle=Path(bundle);self.publisher_key=Path(publisher_key);self.key_digest=key_digest

    def _query(self,args):
        try:
            backup_snapshot._require_legacy_operation_lock(self.home)
            sealed.verify_sealed(self.config_fd,self.config_sha256)
            return json.loads(self.api._call(['--request-timeout=20s',*args,'-o','json']))
        except Exception:raise PreflightError('KUBE_PREFLIGHT_QUERY_UNVERIFIED') from None

    def reverify(self):
        try:
            if (hashlib.sha256(backup_installation.safe_file(self.publisher_key,limit=65536)).hexdigest()!=self.key_digest
                    or uterctl.verify(self.bundle,self.publisher_key)!=self.manifest):raise ValueError
            kube_system=self._query(['get','namespace','kube-system'])
            namespace=self._query(['get','namespace',self.site])
            if namespace.get('metadata',{}).get('name')!=self.site:raise ValueError
            pvc=self._query(['get','pvc',self.site+'-redis'])
            deployment=self._query(['get','deployment',self.site+'-redis'])
            pin.verify_resources(self.profile,kube_system=kube_system,namespace=namespace,
                                 pvc=pvc,deployment=deployment)
            labels='app.kubernetes.io/instance='+self.site+',app.kubernetes.io/name=redis'
            pods=self._query(['get','pods','-l',labels])['items']
            if not isinstance(pods,list) or len(pods)!=1:raise ValueError
            pod=pods[0]
            owners=[x for x in pod['metadata']['ownerReferences'] if x.get('kind')=='ReplicaSet' and x.get('controller') is True]
            if len(owners)!=1 or not re.fullmatch(re.escape(self.site)+r'-redis-[a-z0-9]{1,32}',owners[0]['name']):raise ValueError
            replica=self._query(['get','replicaset',owners[0]['name']])
            identity.verify_snapshot(site=self.site,manifest=self.manifest,
                cluster_uid=kube_system['metadata']['uid'],expected_cluster_uid=self.profile['kube_system_uid'],
                expected_pvc_uid=self.profile['redis_pvc_uid'],deployment=deployment,
                replicaset=replica,pod=pod,pvc=pvc)
            backup_snapshot._require_legacy_operation_lock(self.home)
            sealed.verify_sealed(self.config_fd,self.config_sha256)
        except Exception:raise PreflightError('KUBE_PREFLIGHT_IDENTITY_UNVERIFIED') from None
        return {'result':'pinned_live_identity_observed','redis_isolated':False,'safe_to_update':False}


@contextmanager
def checked_session(home,bundle,publisher_key,raw_config,profile):
    """Verify signed installed version + independent pins before yielding API.

    The caller retains the operation lock and this context throughout all
    requests. This only supports a pristine signed Redis deployment; absence of
    a pin or a changed identity fails closed. No mutation is performed here.
    """
    home=Path(home)
    try:
        backup_snapshot._require_legacy_operation_lock(home)
        key_digest=hashlib.sha256(backup_installation.safe_file(publisher_key,limit=65536)).hexdigest()
        manifest=uterctl.verify(bundle,publisher_key)
        state=uterctl.read(home/'state.json');cfg=uterctl.read(home/'install.json');site=uterctl.site_config(home)
        name=site['name']
        if (state.get('current')!=manifest or state.get('pending') is not None or state.get('adopted_installer') is not True
                or cfg.get('backend')!='kubernetes' or site.get('backend')!='helm'
                or cfg.get('name')!=name or site.get('namespace')!=name
                or cfg.get('context')!=site.get('context') or cfg.get('context')!=profile.get('context')):
            raise ValueError
    except Exception:raise PreflightError('KUBE_PREFLIGHT_INSTALLATION_UNVERIFIED') from None
    with sealed.sealed(raw_config,profile) as (fd,digest):
        api=finalizer.Kubectl(context=profile['context'],namespace=name,config_fd=fd,config_sha256=digest)
        session=Session(home,api,manifest,profile,name,fd,digest,bundle,publisher_key,key_digest)
        session.reverify()
        yield session
