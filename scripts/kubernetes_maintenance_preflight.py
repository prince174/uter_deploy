"""Read-only Kubernetes maintenance-capability inspection.

The signed release and operator profile must already be trusted. This check is
not an ingress fence, a durable operation proof or permission to send POST.
"""
import base64
import re

from scripts import (kubernetes_fence_finalizer as common, kubernetes_redis_identity as identity,
                     kubernetes_writer_quiesce as writers, maintenance_protocol)


class PreflightError(ValueError):
    pass


def observe(session):
    """Verify exact signed service Pods and a separately pinned secret."""
    try:
        if session._executor is None or session._record.get('schema') != 2:
            raise ValueError
        session.reverify()
        signed = maintenance_protocol.verify_capability(session._inner.bundle, session._inner.publisher_key)
        if signed != session.manifest:
            raise ValueError
        secret_name = session.site+'-maintenance'
        expected_uid = session._record['object_uids']['secret/'+secret_name]
        secret = session._get_configured_object('secret', secret_name)
        if (secret.get('kind') != 'Secret' or secret.get('type') != 'Opaque'
                or secret.get('metadata', {}).get('uid') != expected_uid
                or set(secret.get('data', {})) != {'key'}):
            raise ValueError
        decoded = base64.b64decode(secret['data']['key'], validate=True)
        key = decoded.decode('utf-8').strip()
        if not 32 <= len(key) <= 4096 or any(not 32 <= ord(char) <= 126 for char in key):
            raise ValueError
        del decoded, secret, key
        result = {}
        for service in ('agent', 'guardrail'):
            meta, spec = writers._deployment(session, service, session.writer_uids[service])
            if spec['replicas'] != 1:
                raise ValueError
            selector = 'app.kubernetes.io/instance='+session.site+',app.kubernetes.io/name='+service
            pods = session._query(['get', 'pods', '-l', selector])['items']
            if not isinstance(pods, list) or len(pods) != 1:
                raise ValueError
            pod = pods[0]; metadata = pod['metadata']; pod_spec = pod['spec']; status = pod['status']
            if (pod.get('kind') != 'Pod' or metadata.get('namespace') != session.site
                    or metadata.get('deletionTimestamp') or metadata.get('finalizers') not in (None, [])
                    or not identity.UUID.fullmatch(metadata.get('uid', ''))
                    or not re.fullmatch(re.escape(session.site+'-'+service)+r'-[a-z0-9-]{1,64}', metadata.get('name', ''))
                    or status.get('phase') != 'Running' or pod_spec.get('initContainers') not in (None, [])
                    or pod_spec.get('ephemeralContainers') not in (None, [])
                    or any(pod_spec.get(name, False) is not False for name in ('hostNetwork', 'hostPID', 'hostIPC'))
                    or pod_spec.get('automountServiceAccountToken') is not False):
                raise ValueError
            security = pod_spec.get('securityContext', {})
            if (security.get('runAsNonRoot') is not True or security.get('runAsUser') != 10001
                    or security.get('runAsGroup') != 10001 or security.get('fsGroup') != 10001
                    or security.get('seccompProfile') != {'type':'RuntimeDefault'}):
                raise ValueError
            owners = [x for x in metadata.get('ownerReferences', []) if x.get('kind') == 'ReplicaSet' and x.get('controller') is True]
            if len(owners) != 1 or not re.fullmatch(re.escape(session.site+'-'+service)+r'-[a-z0-9]{1,32}', owners[0].get('name', '')):
                raise ValueError
            rs = session._query(['get', 'replicaset', owners[0]['name']]); rsmeta = rs['metadata']
            parents = [x for x in rsmeta.get('ownerReferences', []) if x.get('kind') == 'Deployment' and x.get('controller') is True]
            if (rs.get('kind') != 'ReplicaSet' or rsmeta.get('namespace') != session.site
                    or rsmeta.get('uid') != owners[0].get('uid') or len(parents) != 1
                    or parents[0].get('uid') != meta['uid'] or parents[0].get('name') != session.site+'-'+service):
                raise ValueError
            containers = pod_spec.get('containers'); statuses = status.get('containerStatuses')
            if not isinstance(containers, list) or len(containers) != 1 or not isinstance(statuses, list) or len(statuses) != 1:
                raise ValueError
            container, running = containers[0], statuses[0]
            env = container.get('env', [])
            if not isinstance(env, list) or any(not isinstance(x, dict) or not isinstance(x.get('name'), str) for x in env):
                raise ValueError
            names = [x['name'] for x in env]
            if len(names) != len(set(names)):
                raise ValueError
            explicit = {x['name']: x for x in env}
            for name, expected in (('UTER_MAINTENANCE_ENABLED', 'true'),
                                   ('UTER_MAINTENANCE_KEY_FILE', '/run/uter-maintenance/key'),
                                   ('WEB_CONCURRENCY', '1')):
                if explicit.get(name) != {'name': name, 'value': expected}:
                    raise ValueError
            if (container.get('name') != service or container.get('image') != signed['images'][service]
                    or container.get('command') not in (None, []) or container.get('args') not in (None, [])
                    or container.get('livenessProbe') is not None or container.get('lifecycle') is not None
                    or container.get('securityContext', {}).get('allowPrivilegeEscalation') is not False
                    or container.get('securityContext', {}).get('readOnlyRootFilesystem') is not True
                    or container.get('securityContext', {}).get('privileged', False) is not False
                    or container.get('securityContext', {}).get('capabilities', {}).get('drop') != ['ALL']
                    or running.get('name') != service or running.get('ready') is not True
                    or type(running.get('restartCount')) is not int or running['restartCount'] != 0
                    or not isinstance(running.get('state', {}).get('running'), dict)
                    or not isinstance(running.get('imageID'), str)
                    or '@sha256:' not in signed['images'][service]
                    or not running['imageID'].endswith(signed['images'][service].rsplit('@', 1)[1])
                    or not re.fullmatch(r'(?:containerd|cri-o|docker)://[0-9a-f]{64}', running.get('containerID', ''))):
                raise ValueError
            mounts = [x for x in container.get('volumeMounts', []) if x.get('mountPath') == '/run/uter-maintenance']
            volumes = [x for x in pod_spec.get('volumes', []) if x.get('name') == 'maintenance-key']
            if (len(mounts) != 1 or mounts[0] != {'name': 'maintenance-key', 'mountPath': '/run/uter-maintenance', 'readOnly': True}
                    or len(volumes) != 1 or volumes[0] != {'name': 'maintenance-key',
                        'secret': {'secretName': secret_name, 'defaultMode': 288}}):
                raise ValueError
            result[service] = {'pod': metadata['name'], 'uid': metadata['uid'],
                               'container_id': running['containerID'], 'pod_spec_sha256': common._digest(pod_spec),
                               'deployment_uid': meta['uid'], 'secret_uid': expected_uid}
        session.reverify()
        return {'writers': result, 'ingress_fenced': False, 'restart_fenced': False,
                'redis_isolated': False, 'safe_to_start': False, 'safe_to_update': False}
    except Exception:
        raise PreflightError('KUBE_MAINTENANCE_PREFLIGHT_UNVERIFIED') from None
