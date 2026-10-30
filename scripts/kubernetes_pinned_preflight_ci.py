"""Pinned kubeconfig exercise for a signed install on disposable hosted CI.

The test synthesizes pins from its own freshly created cluster; this is not
independent cluster authentication or authorization for an actual update.
Credential-bearing bytes stay in memory and never appear in diagnostics.
"""
import base64
import hashlib
import json
import os
from pathlib import Path

from scripts import (adopt_backup_ci, install_recovery, kubernetes_pinned_preflight as preflight,
                     kubernetes_fence_pin as pin,
                     kubernetes_redis_identity_ci as snapshot)

ROOT=Path(__file__).resolve().parents[1]


class PinnedCITestError(ValueError): pass


def _query(args):return snapshot._query(args)


def verify(home,bundle,key,manifest):
    try:
        adopt_backup_ci.runner_guard(os.environ,ROOT)
        if (os.environ.get('UTER_CI_STRICT_RUNNER')!='true'
                or os.environ.get('UTER_CI_VERIFY_KUBE_LOOPBACK')!='true'
                or os.environ.get('BACKEND')!='kubernetes'):
            raise ValueError
        for path in (home,bundle,key):
            if not Path(path).resolve(strict=True).is_relative_to(ROOT/'work'):raise ValueError
        # CI owns this newly created kind cluster and test namespace. The
        # generated pin is not external trust and is never published as one.
        raw=install_recovery.run_readonly(['kubectl','--context='+snapshot.CONTEXT,
            'config','view','--raw','--minify','-o','json'],timeout=30).encode('utf-8')
        value=json.loads(raw)
        if len(value['clusters'])!=1 or len(value['contexts'])!=1:raise ValueError
        cluster=value['clusters'][0]['cluster'];server=cluster['server']
        ca=base64.b64decode(cluster['certificate-authority-data'],validate=True)
        namespace=_query(['get','namespace',snapshot.SITE])
        system=_query(['get','namespace','kube-system'])
        pvc=_query(['-n',snapshot.SITE,'get','pvc',snapshot.SITE+'-redis'])
        deployment=_query(['-n',snapshot.SITE,'get','deployment',snapshot.SITE+'-redis'])
        profile={'schema':1,'context':snapshot.CONTEXT,'server_sha256':hashlib.sha256(server.encode()).hexdigest(),
                 'ca_sha256':hashlib.sha256(ca).hexdigest(),'kube_system_uid':system['metadata']['uid'],
                 'namespace_uid':namespace['metadata']['uid'],'redis_pvc_uid':pvc['metadata']['uid'],
                 'redis_deployment_uid':deployment['metadata']['uid']}
        # A different pinned CA is rejected before any API object is created.
        wrong=dict(profile,ca_sha256='0'*64)
        refused=False
        try:
            with preflight.checked_session(home,bundle,key,raw,wrong):pass
        except pin.PinError:refused=True
        if not refused:raise ValueError
        with preflight.checked_session(home,bundle,key,raw,profile) as session:
            if session.manifest!=manifest or session.reverify()['safe_to_update'] is not False:raise ValueError
    except Exception:raise PinnedCITestError('KUBE_PINNED_CI_UNVERIFIED') from None
    return {'result':'sealed_pinned_queries_exercised','cluster_authenticated':False,'safe_to_update':False}
