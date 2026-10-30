"""Test actual product maintenance on a disposable kind cluster only.

This probe does not establish continuous external-writer isolation, backup,
update, data migration, or recovery. Its ingress and deployment are fixtures.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch
import urllib.request

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import (kubernetes_maintenance_preflight, kubernetes_sealed_config, kubernetes_trusted_kubectl,
                     maintenance_evidence, maintenance_protocol, maintenance_transport, redis_fence_journal)

NODE = 'kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0'
REGISTRY = 'registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'
PYTHON = 'python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea'
REDIS = 'ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc'
CLUSTER = 'uter-maint-ci'
CONTEXT = 'kind-'+CLUSTER
SITE = 'uter-maint-ci'
PHASE = 'GUARD'


class ProbeError(ValueError):
    pass


def install_failure(kube):
    """Classify only fixed pod failure states; never report manifests or secrets."""
    allowed = {'ErrImagePull', 'ImagePullBackOff', 'InvalidImageName', 'CreateContainerConfigError',
               'ContainerCreating', 'CrashLoopBackOff', 'CreateContainerError', 'RunContainerError'}
    try:
        raw = run(kube+['-n', SITE, 'get', 'pods', '-o', 'json'], timeout=20)
        pods = json.loads(raw)['items']
        for service in ('redis', 'agent', 'guardrail'):
            matches = [p for p in pods if p.get('metadata', {}).get('labels', {}).get('app.kubernetes.io/name') == service]
            if len(matches) != 1: return service.upper()+'_POD_MISSING'
            status = matches[0].get('status', {})
            if status.get('phase') == 'Pending' and not status.get('containerStatuses'): return service.upper()+'_PENDING'
            for item in status.get('containerStatuses', []):
                reason = item.get('state', {}).get('waiting', {}).get('reason')
                if reason in allowed: return service.upper()+'_'+reason.upper()
                if item.get('ready') is not True: return service.upper()+'_NOT_READY'
        return 'UNKNOWN'
    except Exception:
        return 'INSPECTION_UNCERTAIN'


def run(args, *, data=None, timeout=300):
    try:
        p = subprocess.run([str(x) for x in args], input=data, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=timeout, check=True)
        if len(p.stdout) > 1024*1024:
            raise ValueError
        return p.stdout
    except Exception:
        raise ProbeError('MAINTENANCE_KUBE_COMMAND_UNCERTAIN') from None


def _registry_image(service):
    tag = 'localhost:5055/uter-maint-'+service+':test'
    run(['docker', '--context', 'default', 'tag', 'uter-'+service+'-protected', tag])
    run(['docker', '--context', 'default', 'push', tag], timeout=600)
    media = ', '.join(('application/vnd.oci.image.manifest.v1+json',
                       'application/vnd.docker.distribution.manifest.v2+json',
                       'application/vnd.oci.image.index.v1+json',
                       'application/vnd.docker.distribution.manifest.list.v2+json'))
    req = urllib.request.Request('http://127.0.0.1:5055/v2/uter-maint-'+service+'/manifests/test',
                                 method='HEAD', headers={'Accept': media})
    with urllib.request.urlopen(req, timeout=20) as response:
        digest = response.headers.get('Docker-Content-Digest', '')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise ProbeError('MAINTENANCE_KUBE_IMAGE_UNVERIFIED')
    return 'localhost:5055/uter-maint-'+service+'@'+digest


def _patch_fixture(home, key):
    """Add a test-only secret mount; the released chart is never modified."""
    chart = home/'charts/uter/templates/workloads.yaml'
    content = chart.read_text(encoding='utf-8')
    mount = '            - {name: tmp, mountPath: /tmp}\n'
    volume = '        - name: tmp\n          emptyDir: {sizeLimit: 128Mi}\n'
    if content.count(mount) != 1 or content.count(volume) != 1:
        raise ProbeError('MAINTENANCE_KUBE_FIXTURE_UNVERIFIED')
    content = content.replace(mount, mount+'''            {{- if ne $name "redis" }}
            - {name: maintenance-key, mountPath: /run/uter-maintenance, readOnly: true}
            {{- end }}
''').replace(volume, volume+'''        {{- if ne $name "redis" }}
        - name: maintenance-key
          secret: {secretName: uter-maint-ci-maintenance, defaultMode: 288}
        {{- end }}
''')
    chart.write_text(content, encoding='utf-8')
    values_path = home/'values.yaml'
    values = yaml.safe_load(values_path.read_text(encoding='utf-8'))
    for field in ('guardrailEnv', 'agentEnv'):
        values.setdefault(field, {}).update({'UTER_MAINTENANCE_ENABLED': 'true',
                                             'UTER_MAINTENANCE_KEY_FILE': '/run/uter-maintenance/key',
                                             'WEB_CONCURRENCY': '1'})
    values_path.write_text(yaml.safe_dump(values), encoding='utf-8')
    resources_path = home/'resources.yaml'
    resources = list(yaml.safe_load_all(resources_path.read_text(encoding='utf-8')))
    resources.append({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': SITE+'-maintenance',
                      'namespace': SITE}, 'type': 'Opaque', 'stringData': {'key': key}})
    resources_path.write_text(yaml.safe_dump_all(resources), encoding='utf-8')


def _sealed(raw):
    fd = os.memfd_create('uter-ci-kubeconfig', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0: raise ValueError
            view = view[count:]
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, kubernetes_sealed_config.SEALS)
        digest = hashlib.sha256(raw).hexdigest()
        kubernetes_sealed_config.verify_sealed(fd, digest)
        return fd, digest
    except BaseException:
        os.close(fd)
        raise


def main():
    global PHASE
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('RUNNER_OS') != 'Linux' or os.environ.get('DOCKER_HOST')
            or os.environ.get('DOCKER_CONTEXT', 'default') != 'default'):
        raise ProbeError('MAINTENANCE_KUBE_ENVIRONMENT_UNVERIFIED')
    existing = subprocess.run(['docker', '--context', 'default', 'inspect', 'uter-maint-registry'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    if existing.returncode == 0 or CLUSTER in run(['kind', 'get', 'clusters']).decode().splitlines():
        raise ProbeError('MAINTENANCE_KUBE_FIXTURE_ALREADY_EXISTS')
    work = ROOT/'work/maintenance-kubernetes'; work.mkdir(mode=0o700, parents=True, exist_ok=False)
    kubeconfig = work/'kubeconfig'; cluster = False; registry = False; fds = []
    try:
        PHASE = 'REGISTRY'
        registry = True
        run(['docker', '--context', 'default', 'run', '-d', '--name', 'uter-maint-registry', '--restart', 'no',
             '-p', '127.0.0.1:5055:5000', REGISTRY], timeout=300)
        deadline = time.monotonic()+30
        while True:
            try:
                with urllib.request.urlopen('http://127.0.0.1:5055/v2/', timeout=2) as response:
                    if response.status == 200: break
            except (OSError, TimeoutError):
                pass
            if time.monotonic() >= deadline: raise ProbeError('MAINTENANCE_KUBE_REGISTRY_UNVERIFIED')
            time.sleep(.5)
        PHASE = 'IMAGES'
        images = {service: _registry_image(service) for service in ('agent', 'guardrail')}
        images['redis'] = REDIS
        config = work/'kind.yaml'
        config.write_text('''kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
''', encoding='utf-8')
        PHASE = 'CLUSTER'
        cluster = True
        run(['kind', 'create', 'cluster', '--name', CLUSTER, '--image', NODE, '--kubeconfig', kubeconfig,
             '--config', config, '--wait', '180s'], timeout=420)
        run(['docker', '--context', 'default', 'network', 'connect', 'kind', 'uter-maint-registry'])
        hosts = b'server = "http://uter-maint-registry:5000"\n[host."http://uter-maint-registry:5000"]\n  capabilities = ["pull", "resolve"]\n'
        run(['docker', '--context', 'default', 'exec', CLUSTER+'-control-plane', 'mkdir', '-p',
             '/etc/containerd/certs.d/localhost:5055'])
        run(['docker', '--context', 'default', 'exec', '-i', CLUSTER+'-control-plane', 'sh', '-c',
             'cat > /etc/containerd/certs.d/localhost:5055/hosts.toml'], data=hosts)
        PHASE = 'FIXTURE'
        kube = ['/usr/bin/uter-ci-kubectl', '--kubeconfig', str(kubeconfig), '--context', CONTEXT]
        run(kube+['create', 'namespace', 'uter-fixtures'])
        run(kube+['-n', 'uter-fixtures', 'create', 'configmap', 'llm-code',
                  '--from-file=fixture.py='+str(ROOT/'tests/fixtures/upstream.py')])
        fixture = {'apiVersion':'apps/v1', 'kind':'Deployment', 'metadata':{'name':'llm','namespace':'uter-fixtures'},
                   'spec':{'selector':{'matchLabels':{'app':'llm'}}, 'template':{'metadata':{'labels':{'app':'llm'}},
                     'spec':{'containers':[{'name':'llm','image':PYTHON,'command':['python','/fixture/fixture.py'],
                       'ports':[{'containerPort':8080}], 'readinessProbe':{'httpGet':{'path':'/health','port':8080}},
                       'volumeMounts':[{'name':'code','mountPath':'/fixture','readOnly':True}]}],
                       'volumes':[{'name':'code','configMap':{'name':'llm-code'}}]}}}}
        run(kube+['-n', 'uter-fixtures', 'create', '-f', '-'], data=json.dumps(fixture).encode())
        run(kube+['-n', 'uter-fixtures', 'expose', 'deployment', 'llm', '--port=8080'])
        run(kube+['-n', 'uter-fixtures', 'rollout', 'status', 'deployment/llm', '--timeout=180s'])
        images_path = work/'images.json'; images_path.write_text(json.dumps(images))
        llm_key = work/'llm-key'; llm_key.write_text(''); os.chmod(llm_key, 0o600)
        home = work/'installation'; source = ROOT/'work/images/protected-guardrail/evidence'
        PHASE = 'PREPARE'
        run([sys.executable, ROOT/'scripts/install.py', 'prepare', '--home', home, '--backend', 'kubernetes',
             '--name', SITE, '--context', CONTEXT, '--images', images_path,
             '--policy', source/'policies/default.toml', '--profiles', source/'profiles/model_profiles.toml',
             '--llm-url', 'http://llm.uter-fixtures.svc.cluster.local:8080', '--llm-model', 'test-model',
             '--llm-key-file', llm_key, '--allow-http-llm'])
        _patch_fixture(home, secrets.token_hex(32))
        PHASE = 'CHECK'
        run([sys.executable, ROOT/'scripts/install.py', 'check', '--home', home])
        # The fixture uses a dedicated kubeconfig, not a developer context.
        env = dict(os.environ, KUBECONFIG=str(kubeconfig))
        PHASE = 'INSTALL'
        result = subprocess.run([sys.executable, str(ROOT/'scripts/install.py'), 'install', '--home', str(home)],
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
        if result.returncode:
            print('MAINTENANCE_KUBE_INSTALL_'+install_failure(kube), file=sys.stderr)
            raise ProbeError('MAINTENANCE_KUBE_INSTALL_UNVERIFIED')
        def snapshot():
            result = {}
            for service in ('agent', 'guardrail', 'redis'):
                selector = 'app.kubernetes.io/instance='+SITE+',app.kubernetes.io/name='+service
                value = json.loads(run(kube+['-n', SITE, 'get', 'pods', '-l', selector, '-o', 'json']))
                if len(value.get('items', [])) != 1: raise ProbeError('MAINTENANCE_KUBE_IDENTITY_UNVERIFIED')
                pod = value['items'][0]; meta = pod['metadata']; spec = pod['spec']; statuses = pod['status']['containerStatuses']
                if (meta.get('deletionTimestamp') or len(spec.get('containers', [])) != 1 or len(statuses) != 1
                        or spec['containers'][0].get('name') != service or spec['containers'][0].get('image') != images[service]
                        or statuses[0].get('restartCount') != 0 or not isinstance(statuses[0].get('state', {}).get('running'), dict)
                        or not re.fullmatch(r'[0-9a-f-]{36}', meta.get('uid', ''))
                        or not re.fullmatch(r'(?:containerd|cri-o|docker)://[0-9a-f]{64}', statuses[0].get('containerID', ''))):
                    raise ProbeError('MAINTENANCE_KUBE_IDENTITY_UNVERIFIED')
                result[service] = {'name': meta['name'], 'uid': meta['uid'], 'container_id': statuses[0]['containerID'],
                                   'image': spec['containers'][0]['image'], 'restart_count': statuses[0]['restartCount']}
            return result
        PHASE = 'IDENTITY'
        pinned = snapshot()
        for service in ('agent', 'guardrail'):
            expected = run(['docker', '--context', 'default', 'image', 'inspect', '--format', '{{.Id}}',
                            'uter-'+service+'-protected']).decode().strip()
            pod = json.loads(run(kube+['-n', SITE, 'get', 'pod', pinned[service]['name'], '-o', 'json']))
            image_id = pod['status']['containerStatuses'][0].get('imageID', '')
            if not isinstance(image_id, str) or not (image_id.endswith(expected) or image_id.endswith(images[service].split('@')[1])):
                raise ProbeError('MAINTENANCE_KUBE_IMAGE_UNVERIFIED')
        identities = {s: (pinned[s]['uid']+'/'+pinned[s]['container_id'],) for s in ('agent', 'guardrail')}
        def stable(): return snapshot() == pinned
        def inventory():
            if not stable(): raise ProbeError('MAINTENANCE_KUBE_IDENTITY_CHANGED')
            return dict(identities)
        PHASE = 'TRUSTED_EXEC'
        config_fd, config_hash = _sealed(kubeconfig.read_bytes()); fds.append(config_fd)
        PHASE = 'TRUSTED_BINARY_READ'
        binary_path = Path('/usr/bin/uter-ci-kubectl')
        binary_hash = hashlib.sha256(binary_path.read_bytes()).hexdigest()
        for item in (binary_path, *binary_path.parents):
            metadata = item.lstat()
            PHASE = 'TRUSTED_BINARY_PATH_OWNER'
            if metadata.st_uid != 0: raise ValueError
            PHASE = 'TRUSTED_BINARY_PATH_WRITABLE'
            if metadata.st_mode & 0o022: raise ValueError
            PHASE = 'TRUSTED_BINARY_PATH_SYMLINK'
            if stat.S_ISLNK(metadata.st_mode): raise ValueError
        PHASE = 'TRUSTED_BINARY_SIZE'
        if not 0 < binary_path.stat().st_size <= 128*1024*1024: raise ValueError
        PHASE = 'TRUSTED_BINARY_OPEN'
        binary_fd = kubernetes_trusted_kubectl.open_binary(binary_path, binary_hash); fds.append(binary_fd)
        PHASE = 'TRUSTED_JOURNAL_CREATE'
        session = SimpleNamespace(site=SITE, _executor=object(), _record={'schema':2,'kubectl_sha256':binary_hash},
            config_sha256=config_hash, _inner=SimpleNamespace(config_fd=config_fd,
                api=SimpleNamespace(binary_fd=binary_fd, context=CONTEXT)), _scope=lambda: inventory())
        # Real Kubernetes objects with a fixture-only signing shim: source
        # images were identity checked above, but this does not test release
        # signature verification or the production profile/lock.
        def query(args):
            return json.loads(run(kube+['-n', SITE]+args+['-o', 'json']))
        session._query = query
        session._get_configured_object = lambda kind, name: query(['get', kind, name])
        session.reverify = lambda: None
        session.manifest = {'images':images}
        session._inner.bundle = None
        session._inner.publisher_key = None
        session.writer_uids = {service:query(['get', 'deployment', SITE+'-'+service])['metadata']['uid']
                               for service in ('agent', 'guardrail')}
        secret_name = SITE+'-maintenance'
        session._record['object_uids'] = {'secret/'+secret_name:query(['get', 'secret', secret_name])['metadata']['uid']}
        PHASE = 'KUBE_PREFLIGHT_INITIAL'
        with patch.object(maintenance_protocol, 'verify_capability', return_value=session.manifest):
            preflight_initial = kubernetes_maintenance_preflight.observe(session)
        PHASE = 'TRUSTED_JOURNAL_CREATE'
        proof = work/'proof'; proof.mkdir(mode=0o700); operation = secrets.token_hex(16); plan = secrets.token_hex(32)
        redis_fence_journal.create(proof, backend='kubernetes', site=SITE, resource=pinned['redis']['uid'],
                                   plan_sha256=plan, operation=operation)
        PHASE = 'TRUSTED_RECORDER_CREATE'
        recorder = maintenance_evidence.Recorder(proof, secrets.token_bytes(32), operation=operation,
            backend='kubernetes', plan_sha256=plan, lock_guard=lambda: True)
        def request(service, instance, method, timeout):
            if instance != identities[service][0]: raise ProbeError('MAINTENANCE_KUBE_IDENTITY_CHANGED')
            return maintenance_transport.request(service=service, method=method, session=session,
                pod=pinned[service]['name'], identity_guard=stable)
        PHASE = 'MAINTENANCE'
        receipts = maintenance_protocol.collect(identities, observe_inventory=inventory, request=request,
                                                record_intent=recorder.intent, record_receipt=recorder.receipt)
        if set(receipts) != {identities['agent'][0], identities['guardrail'][0]} or not stable():
            raise ProbeError('MAINTENANCE_KUBE_RECEIPTS_UNVERIFIED')
        PHASE = 'KUBE_PREFLIGHT_QUIESCED'
        with patch.object(maintenance_protocol, 'verify_capability', return_value=session.manifest):
            preflight_final = kubernetes_maintenance_preflight.observe(session, require_ready=False)
        if preflight_final != preflight_initial:
            raise ProbeError('MAINTENANCE_KUBE_PREFLIGHT_CHANGED')
        PHASE = 'RESTART_IDENTITY_TEST'
        # Fault injection only in this disposable kind cluster: replacement of a
        # receipted writer must invalidate the entire inventory before any next
        # action. This is not a Redis fence or a live recovery test.
        run(kube+['-n', SITE, 'delete', 'pod', pinned['agent']['name'], '--wait=false'])
        invalidated = False
        try:
            inventory()
        except Exception:
            invalidated = True
        if not invalidated:
            raise ProbeError('MAINTENANCE_KUBE_RESTART_NOT_DETECTED')
        evidence = ROOT/'work/maintenance-kubernetes-evidence'; evidence.mkdir(mode=0o700)
        (evidence/'maintenance.txt').write_text('Agent and Guardrail receipts verified on exact kind Pods.\n'
            'Read-only preflight checked real Pod identity before and after quiescence using a fixture signing shim.\n'
            'Deleting a receipted Agent Pod invalidated the inventory.\n'
            'Redis fence, backup, update and recovery were not tested by this probe.\n', encoding='utf-8')
    finally:
        for fd in fds: os.close(fd)
        if cluster:
            subprocess.run(['kind','delete','cluster','--name',CLUSTER,'--kubeconfig',str(kubeconfig)],
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120)
        if registry:
            subprocess.run(['docker','--context','default','rm','-f','uter-maint-registry'],
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('MAINTENANCE_KUBERNETES_PRODUCT_CI_'+PHASE+'_FAILED', file=sys.stderr)
        raise SystemExit(1)
