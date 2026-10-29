"""Exercise chart ingress NetworkPolicy with pinned Calico on disposable CI.

The ingress source is a test Pod in the allowed namespace, not an ingress
controller. The upstream is a deterministic HTTP fixture, not a real LLM.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from urllib import error, request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml
from scripts.corporate_tls_ci import (NODE_IMAGE, StageError, call, ci_only, cleanup,
                                      free_port, gateway_address, terminate, verify_published_inputs)


CALICO_SHA256 = '2de8f47595fb9c41b3f47d7b767a1f8e72ecf84057af834738ff12689a234da5'
CALICO_IMAGES = {
    'quay.io/calico/calico:v3.33.0': 'quay.io/calico/calico@sha256:4ebc20730127bc9e8bf1db5f5a2d8b58cf37fe0e891b3c7b5471992221d213e5',
    'quay.io/calico/node:v3.33.0': 'quay.io/calico/node@sha256:565d8db3200e443955557f8f28ff44ab8a4a456754bc74a19c4f2f3444af9b1c',
    'quay.io/calico/third-party-cni-plugins:v3.33.0': 'quay.io/calico/third-party-cni-plugins@sha256:0f32f48279484c0d6f0e0d0e767b2d0e1a6c6ca34cb3421a61b989d992f3df41',
}
CLIENT_IMAGE = 'python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea'


def calico_manifest(path):
    """Reject changed upstream bytes or unexpected image references."""
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise StageError('CALICO_MANIFEST_INVALID')
        data = source.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != CALICO_SHA256:
        raise StageError('CALICO_MANIFEST_HASH_MISMATCH')
    text = data.decode('utf-8')
    images = re.findall(r'^\s*image:\s*([^\s#]+)\s*$', text, re.MULTILINE)
    if not images or set(images) != set(CALICO_IMAGES):
        raise StageError('CALICO_MANIFEST_IMAGE_SET_INVALID')
    for original, pinned in CALICO_IMAGES.items():
        text = text.replace('image: ' + original, 'image: ' + pinned)
    final_images = re.findall(r'^\s*image:\s*([^\s#]+)\s*$', text, re.MULTILINE)
    if set(final_images) != set(CALICO_IMAGES.values()):
        raise StageError('CALICO_IMAGE_PINNING_FAILED')
    return text.encode('utf-8')


def client_pod(namespace):
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'network-client', 'namespace': namespace},
            'spec': {'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                     'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001,
                                         'seccompProfile': {'type': 'RuntimeDefault'}},
                     'containers': [{'name': 'client', 'image': CLIENT_IMAGE,
                         'command': ['python', '-c', 'import time;time.sleep(1200)'],
                         'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                             'capabilities': {'drop': ['ALL']}},
                         'resources': {'requests': {'cpu': '50m', 'memory': '32Mi'},
                                       'limits': {'cpu': '250m', 'memory': '128Mi'}}}]}}


def wait_fixture(base, process):
    opener = request.build_opener(request.ProxyHandler({}))
    for _ in range(60):
        if process.poll() is not None:
            raise StageError('FIXTURE_EXITED')
        try:
            with opener.open(base + '/health', timeout=2) as response:
                if response.status == 200:
                    return
        except error.HTTPError as exc:
            exc.close()
        except (error.URLError, TimeoutError, OSError):
            pass
        time.sleep(1)
    raise StageError('FIXTURE_NOT_READY')


def run_probe(kube, namespace, target, source, env):
    args = [*kube, '-n', namespace, 'exec', '-i', target, '--', 'python', '-']
    data = call(args, 'NETWORK_PROBE_EXEC_FAILED', env=env, input_data=source.encode(), timeout=40)
    try:
        value = data.decode('ascii').strip()
    except UnicodeError:
        raise StageError('NETWORK_PROBE_OUTPUT_INVALID') from None
    if value not in ('CONNECTED', 'TIMEOUT', 'READY', 'DNS_OK', 'EGRESS_OK'):
        raise StageError('NETWORK_PROBE_OUTPUT_INVALID')
    return value


def tcp_probe(kube, namespace, target, hostname, port, env):
    source = '''import socket\ntry:\n with socket.create_connection((HOST,PORT),timeout=5): pass\n print('CONNECTED')\nexcept socket.timeout:\n print('TIMEOUT')\nexcept Exception:\n print('ERROR')\n'''.replace('HOST', repr(hostname)).replace('PORT', repr(port))
    return run_probe(kube, namespace, target, source, env)


def require_probe(actual, expected, stage):
    if actual != expected:
        raise StageError(stage)


def main():
    ci_only()
    work = Path(os.environ['TEST_WORKSPACE']).resolve(strict=True)
    python = work/'venv/bin/python'
    unique = secrets.token_hex(6)
    name = 'uter-net-' + unique
    cluster = name + '-kind'
    allowed, denied = name + '-allowed', name + '-denied'
    context = 'kind-' + cluster
    kube = ['kubectl', '--context', context]
    fixture = None
    cluster_attempted = False
    with tempfile.TemporaryDirectory(prefix='uter-networkpolicy-ci-', dir=work) as temporary:
        temporary = Path(temporary)
        inputs = temporary/'inputs'
        manifest = verify_published_inputs(work, inputs)
        env = os.environ.copy()
        for key in list(env):
            if key.startswith('COMPOSE_') or key in ('DOCKER_HOST', 'DOCKER_CONTEXT') or key.lower() in ('http_proxy','https_proxy','all_proxy','no_proxy'):
                del env[key]
        env['KUBECONFIG'] = str(temporary/'kubeconfig')
        docker_config = temporary/'docker-config'; docker_config.mkdir(mode=0o700)
        env['DOCKER_CONFIG'] = str(docker_config)
        config = temporary/'kind.yaml'
        config.write_text('kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnetworking:\n  disableDefaultCNI: true\n  podSubnet: 192.168.0.0/16\n')
        try:
            existing = call(['kind','get','clusters'], 'KIND_DISCOVERY_FAILED', env=env).decode().splitlines()
            if cluster in existing:
                raise StageError('CLUSTER_NAME_ALREADY_EXISTS')
            cluster_attempted = True
            # No --wait: without a CNI, nodes cannot become Ready until Calico is installed.
            call(['kind','create','cluster','--name',cluster,'--image',NODE_IMAGE,
                  '--config',config,'--kubeconfig',env['KUBECONFIG']], 'KIND_CREATE_FAILED', env=env)
            call(kube + ['apply','-f','-'], 'CALICO_APPLY_FAILED', env=env,
                 input_data=calico_manifest(work/'download/calico.yaml'))
            call(kube + ['-n','kube-system','rollout','status','daemonset/calico-node','--timeout=360s'],
                 'CALICO_NODE_NOT_READY', env=env, timeout=390)
            call(kube + ['-n','kube-system','rollout','status','deployment/calico-kube-controllers','--timeout=360s'],
                 'CALICO_CONTROLLERS_NOT_READY', env=env, timeout=390)
            call(kube + ['wait','--for=condition=Ready','nodes','--all','--timeout=300s'],
                 'NODES_NOT_READY', env=env, timeout=330)
            call(kube + ['-n','kube-system','rollout','status','deployment/coredns','--timeout=300s'],
                 'DNS_NOT_READY', env=env, timeout=330)
            print('Stage: pinned Calico CNI and CoreDNS ready', flush=True)
            gateway = gateway_address('kubernetes', cluster, env)
            port = free_port(gateway)
            fixture = subprocess.Popen([str(python), str(ROOT/'tests/fixtures/scheduled_backup_upstream.py'),
                                        '--host', gateway, '--port', str(port)], env=env,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            base = 'http://' + gateway + ':' + str(port)
            wait_fixture(base, fixture)
            for namespace in (allowed, denied):
                call(kube + ['create','namespace',namespace], 'TEST_NAMESPACE_CREATE_FAILED', env=env)
            keyfile = temporary/'empty-key'; keyfile.write_bytes(b''); keyfile.chmod(0o600)
            home = temporary/'home'
            installer = ROOT/'scripts/install.py'
            call([python, installer, 'prepare', '--home', home, '--backend', 'kubernetes', '--name', name,
                  '--context', context, '--inputs', inputs, '--llm-url', base + '/v1', '--llm-model', 'test-model',
                  '--llm-key-file', keyfile, '--allow-http-llm'], 'PREPARE_FAILED', env=env)
            values_path = home/'values.yaml'
            values = yaml.safe_load(values_path.read_text())
            values['ingressNamespace'] = allowed
            values_path.write_text(yaml.safe_dump(values))
            cfg = json.loads((home/'install.json').read_text())
            if cfg['images'] != manifest['images']:
                raise StageError('SIGNED_IMAGE_MISMATCH')
            call([python, installer, 'check', '--home', home], 'CHECK_FAILED', env=env)
            call([python, installer, 'install', '--home', home], 'INSTALL_FAILED', env=env, timeout=600)
            for namespace in (allowed, denied):
                call(kube + ['create','-f','-'], 'CLIENT_POD_CREATE_FAILED', env=env,
                     input_data=json.dumps(client_pod(namespace)).encode())
                call(kube + ['-n',namespace,'wait','--for=condition=Ready','pod/network-client','--timeout=240s'],
                     'CLIENT_POD_NOT_READY', env=env, timeout=270)

            services = {service: name + '-' + service + '.' + name + '.svc.cluster.local'
                        for service in ('guardrail','agent','redis')}
            allowed_target = 'pod/network-client'
            guard_target, agent_target = 'deployment/' + name + '-guardrail', 'deployment/' + name + '-agent'
            dns = "import socket\nsocket.getaddrinfo('kubernetes.default.svc.cluster.local',443)\nprint('DNS_OK')\n"
            require_probe(run_probe(kube, name, guard_target, dns, env), 'DNS_OK', 'GUARDRAIL_DNS_FAILED')
            outbound = "from urllib import request\nopener=request.build_opener(request.ProxyHandler({}))\nwith opener.open(URL,timeout=5) as response:\n assert response.status==200\nprint('EGRESS_OK')\n".replace('URL', repr(base + '/health'))
            require_probe(run_probe(kube, name, guard_target, outbound, env), 'EGRESS_OK', 'GUARDRAIL_EGRESS_FAILED')
            ready = "import json\nfrom urllib import request\nopener=request.build_opener(request.ProxyHandler({}))\nwith opener.open(URL,timeout=10) as response:\n value=json.load(response)\n assert response.status==200 and value.get('ready') is True\nprint('READY')\n".replace('URL', repr('http://' + services['guardrail'] + ':8000/ready'))
            require_probe(run_probe(kube, allowed, allowed_target, ready, env), 'READY', 'INGRESS_NAMESPACE_NOT_ALLOWED')
            require_probe(tcp_probe(kube, name, agent_target, services['guardrail'], 8000, env), 'CONNECTED', 'AGENT_TO_GUARDRAIL_BLOCKED')
            for service, svc_port in (('agent',8001), ('redis',6379)):
                require_probe(tcp_probe(kube, name, guard_target, services[service], svc_port, env), 'CONNECTED', 'GUARDRAIL_INTERNAL_TRAFFIC_BLOCKED')
            for namespace in (allowed, denied):
                targets = [('agent',8001), ('redis',6379)]
                if namespace == denied:
                    targets.append(('guardrail',8000))
                for service, svc_port in targets:
                    require_probe(tcp_probe(kube, namespace, allowed_target, services[service], svc_port, env),
                                  'TIMEOUT', 'UNAUTHORIZED_NAMESPACE_NOT_BLOCKED')
            print(json.dumps({'calico':'v3.33.0', 'guardrail_ingress_namespace':'pass',
                'other_namespace_denied':'pass', 'agent_redis_external_denied':'pass',
                'internal_traffic':'pass', 'dns_and_fixture_egress':'pass',
                'ingress_controller':'not_tested; source is a Pod in allowed namespace',
                'upstream':'deterministic HTTP fixture; not a real LLM',
                'corporate_cni_tls_and_policies':'not_tested'}))
        finally:
            failed = False
            if cluster_attempted:
                failed |= not cleanup(['kind','delete','cluster','--name',cluster,'--kubeconfig',env['KUBECONFIG']], env)
            try:
                terminate(fixture)
            except (OSError, subprocess.TimeoutExpired):
                failed = True
            if failed:
                raise StageError('CI_CLEANUP_FAILED')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        category = str(exc) if isinstance(exc, StageError) else 'NETWORKPOLICY_VALIDATION_FAILED'
        print('Isolated network policy test failed: ' + category + '; raw details withheld', file=sys.stderr)
        sys.exit(1)
