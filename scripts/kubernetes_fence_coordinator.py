"""Profile-bound Kubernetes session for a narrowly scoped fence coordinator.

This does not start a fence, create a backup or authorize an update. A profile
must be provided and independently verified by an administrator. The selected
control plane, nodes, admission/RBAC, CNI and CSI and privileged operators are
trusted; the profile and point-in-time checks do not establish those premises.
"""
from contextlib import ExitStack,contextmanager
import copy
import hashlib
import hmac
import os
from pathlib import Path

import uterctl
from scripts import (backup_installation, backup_snapshot, kubernetes_fence_pin as pin,
                     kubernetes_fence_profile_store as store,
                     kubernetes_pinned_preflight as preflight, kubernetes_sealed_config as sealed)


class CoordinatorError(ValueError):pass


class _BoundAPI:
    """Recheck the signed operator profile around every selected API request."""
    def __init__(self,owner,api):
        self.owner=owner;self._api=api;self.context=api.context;self.namespace=api.namespace

    def _invoke(self,name,*args):
        self.owner._scope()
        value=getattr(self._api,name)(*args)
        self.owner._scope()  # Unknown result if the identity changed during a request.
        return value

    def _call(self,args):return self._invoke('_call',args)
    def get(self,name):return self._invoke('get',name)
    def patch(self,name,ops):return self._invoke('patch',name,ops)
    def get_deployment(self,name):return self._invoke('get_deployment',name)
    def patch_deployment(self,name,ops):return self._invoke('patch_deployment',name,ops)


class BoundSession:
    """Pinned session, not a Redis fence or a backup capability."""
    def __init__(self,inner,profile_path,key_path,record,digest,key_digest):
        self._inner=inner;self._profile_path=profile_path;self._key_path=key_path
        self._record=copy.deepcopy(record);self._profile_digest=digest;self._key_digest=key_digest
        self.home=inner.home;self.site=inner.site;self.manifest=copy.deepcopy(inner.manifest)
        self.profile=copy.deepcopy(inner.profile);self.inventory_digest=inner.inventory_digest
        self.config_sha256=inner.config_sha256;self.key_digest=inner.key_digest
        self.writer_uids=copy.deepcopy(record['writer_uids']);self.api=_BoundAPI(self,inner.api)

    def _guard(self):
        try:
            backup_snapshot._require_legacy_operation_lock(self.home)
            sealed.verify_sealed(self._inner.config_fd,self.config_sha256)
            raw=backup_installation.safe_file(self._key_path,private=True,limit=32)
            if len(raw)!=32 or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(),self._key_digest):raise ValueError
            current,digest=store.read(self._profile_path,raw)
            if not hmac.compare_digest(digest,self._profile_digest) or current!=self._record:raise ValueError
            if (self._inner.profile!=self.profile or self._inner.manifest!=self.manifest
                    or self._inner.inventory_digest!=self.inventory_digest or self._inner.key_digest!=self.key_digest
                    or self._inner.config_sha256!=self.config_sha256):raise ValueError
            if (hashlib.sha256(backup_installation.safe_file(self._inner.publisher_key,limit=65536)).hexdigest()!=self.key_digest
                    or hashlib.sha256(backup_installation.safe_file(self._inner.bundle/'checksums.json',limit=1024*1024)).hexdigest()!=self.inventory_digest
                    or uterctl.verify(self._inner.bundle,self._inner.publisher_key)!=self.manifest):raise ValueError
        except Exception:raise CoordinatorError('KUBE_OPERATOR_PROFILE_CHANGED') from None

    def _scope(self):
        """Compare live pinned namespace/PVC/Deployment around a request."""
        try:
            self._guard()
            system=self._inner._query(['get','namespace','kube-system'])
            namespace=self._inner._query(['get','namespace',self.site])
            pvc=self._inner._query(['get','pvc',self.site+'-redis'])
            deployment=self._inner._query(['get','deployment',self.site+'-redis'])
            if namespace.get('metadata',{}).get('name')!=self.site:raise ValueError
            pin.verify_resources(self.profile,kube_system=system,namespace=namespace,pvc=pvc,deployment=deployment)
            self._guard()
        except Exception:raise CoordinatorError('KUBE_OPERATOR_SCOPE_UNVERIFIED') from None

    def _query(self,args):
        self._guard();value=self._inner._query(args);self._guard();return value

    def reverify(self):
        self._guard();value=self._inner.reverify();self._guard();return value


@contextmanager
def checked_session(home,bundle,publisher_key,kubeconfig_path,profile_path,backup_key_path):
    """Establish a profile-bound, sealed API connection under an existing lock.

    Configuration, pin and backup key must be separate trusted private files;
    no credential is printed or written to a temporary file. An absent or
    changed profile never permits any cluster mutation. The calling coordinator
    must still establish the actual Redis fence and independently verify data.
    """
    try:
        home=backup_installation.private_directory(home)
        config=backup_installation.checked_existing_path(kubeconfig_path)
        profile=backup_installation.checked_existing_path(profile_path)
        key_path=backup_installation.checked_existing_path(backup_key_path)
        publisher=backup_installation.checked_existing_path(publisher_key)
        signed_bundle=Path(bundle).resolve(strict=True)
        if (len({config,profile,key_path,publisher})!=4
                or any(x.is_relative_to(home) or x.is_relative_to(signed_bundle) for x in (config,profile,key_path))):
            raise ValueError
        key=backup_installation.safe_file(key_path,private=True,limit=32)
        if len(key)!=32:raise ValueError
        raw=backup_installation.safe_file(config,private=True,limit=pin.MAX_CONFIG)
        record,digest=store.read(profile,key)
        key_digest=hashlib.sha256(key).hexdigest()
    except Exception:raise CoordinatorError('KUBE_OPERATOR_PROFILE_UNVERIFIED') from None
    with ExitStack() as stack:
        try:
            inner=stack.enter_context(preflight.checked_session(home,bundle,publisher_key,raw,record['api']))
            if (inner.site!=record['site'] or inner.manifest.get('version')!=record['release_version']
                    or inner.inventory_digest!=record['inventory_sha256'] or inner.key_digest!=record['publisher_sha256']):
                raise ValueError
            session=BoundSession(inner,profile,key_path,record,digest,key_digest)
            session.reverify()
        except CoordinatorError:raise
        except Exception:raise CoordinatorError('KUBE_OPERATOR_SESSION_UNVERIFIED') from None
        yield session
