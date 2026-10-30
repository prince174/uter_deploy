"""Read-only Redis identity check for a disposable published-install CI run.

Never queries Secret resources, session values, credentials or logs. This fixture
does not authenticate its cluster by deriving the expected UID independently;
it checks snapshot consistency only and never supplies a production fence.
"""
import json
import os
import re

from scripts import install_recovery, kubernetes_redis_identity as identity

CONTEXT = 'kind-uter-upgrade-ci'
SITE = 'uter-upgrade-ci'
LABEL = 'app.kubernetes.io/instance='+SITE+',app.kubernetes.io/name=redis'


class IdentityCheckFailure(ValueError):
    pass


def _query(args):
    try:
        cmd=['kubectl','--context',CONTEXT,'--request-timeout=20s',*args,'-o','json']
        result=install_recovery.run_readonly(cmd,timeout=30)
        return json.loads(result)
    except (OSError,ValueError,TypeError):
        raise IdentityCheckFailure('KUBE_IDENTITY_CI_QUERY_FAILED') from None


def verify(manifest):
    """Observe only the explicit disposable kind namespace and a signed manifest."""
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'
            or os.environ.get('RUNNER_OS')!='Linux' or os.environ.get('BACKEND')!='kubernetes'
            or os.environ.get('UTER_CI_STRICT_RUNNER')!='true' or os.environ.get('DOCKER_HOST')
            or os.environ.get('DOCKER_CONTEXT') not in (None,'','default')):
        raise IdentityCheckFailure('KUBE_IDENTITY_CI_RUNNER_REQUIRED')
    try:
        cluster=_query(['get','namespace','kube-system'])['metadata']['uid']
        deployment=_query(['-n',SITE,'get','deployment',SITE+'-redis'])
        items=_query(['-n',SITE,'get','pods','-l',LABEL])['items']
        if not isinstance(items,list) or len(items)!=1:
            raise ValueError
        pod=items[0]
        owners=[x for x in pod['metadata']['ownerReferences'] if x.get('kind')=='ReplicaSet' and x.get('controller') is True]
        if len(owners)!=1 or not re.fullmatch(re.escape(SITE)+r'-redis-[a-z0-9]{1,32}',owners[0]['name']):
            raise ValueError
        replica=_query(['-n',SITE,'get','replicaset',owners[0]['name']])
        pvc=_query(['-n',SITE,'get','persistentvolumeclaim',SITE+'-redis'])
        result=identity.verify_snapshot(site=SITE,manifest=manifest,cluster_uid=cluster,expected_cluster_uid=cluster,
                                        expected_pvc_uid=pvc['metadata']['uid'],deployment=deployment,
                                        replicaset=replica,pod=pod,pvc=pvc)
        if result.get('result')!='matching_snapshot_observed' or any(result.get(x) is not False for x in
                ('redis_isolated','cluster_authenticated','writers_excluded','safe_to_upgrade')):
            raise ValueError
    except (KeyError,TypeError,ValueError,identity.KubernetesRedisIdentityError):
        raise IdentityCheckFailure('KUBE_IDENTITY_CI_UNVERIFIED') from None
