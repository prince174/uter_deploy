"""Check candidate chart egress using pinned Calico, on a disposable hosted runner.

The upstream is an HTTP protocol fixture, not a real LLM or corporate network.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import yaml
from scripts.corporate_tls_ci import NODE_IMAGE, StageError, call, ci_only, cleanup, verify_published_inputs
from scripts.networkpolicy_ci import CLIENT_IMAGE, calico_manifest, client_pod, require_probe, run_probe, tcp_probe

FIXTURE_PORT = 8080
DENIED_PORT = 8081


def fixture_pod(namespace, name, label):
    """Two real listeners on each destination let timeouts prove policy enforcement."""
    containers = []
    for port in (FIXTURE_PORT, DENIED_PORT):
        containers.append({'name': 'http-' + str(port), 'image': CLIENT_IMAGE,
            'command': ['python', '/fixture/fixture.py', '--host', '0.0.0.0', '--port', str(port)],
            'env': [{'name': 'GITHUB_ACTIONS', 'value': 'true'},
                    {'name': 'RUNNER_ENVIRONMENT', 'value': 'github-hosted'}],
            'readinessProbe': {'tcpSocket': {'port': port}, 'periodSeconds': 2},
            'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                'capabilities': {'drop': ['ALL']}},
            'resources': {'requests': {'cpu': '30m', 'memory': '32Mi'},
                          'limits': {'cpu': '250m', 'memory': '128Mi'}},
            'volumeMounts': [{'name': 'fixture', 'mountPath': '/fixture', 'readOnly': True}]})
    return {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': name, 'namespace': namespace, 'labels': {'app': label}},
            'spec': {'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                     'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001,
                                         'seccompProfile': {'type': 'RuntimeDefault'}},
                     'containers': containers,
                     'volumes': [{'name': 'fixture', 'configMap': {'name': 'llm-fixture'}}]}}


def egress_values(namespace):
    return {'enabled': True,
            'dns': {'mode': 'pod', 'namespace': 'kube-system', 'podLabelKey': 'k8s-app',
                    'podLabelValue': 'kube-dns', 'port': 53},
            'llm': {'mode': 'pod', 'namespace': namespace, 'podLabelKey': 'app',
                    'podLabelValue': 'upstream-allowed', 'port': FIXTURE_PORT}}


def dns_probe_source(protocol):
    if protocol not in ('udp', 'tcp'):
        raise ValueError('invalid DNS protocol')
    # Query the resolver actually configured in the selected pod; require a valid answer.
    return '''import socket,struct\nserver=next(x.split()[1] for x in open('/etc/resolv.conf') if x.startswith('nameserver '))\nq=b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00'\nfor label in 'kubernetes.default.svc.cluster.local'.split('.'):\n q+=bytes([len(label)])+label.encode()\nq+=b'\\x00\\x00\\x01\\x00\\x01'\ns=socket.socket(socket.AF_INET, TYPE);s.settimeout(5)\nif TYPE==socket.SOCK_STREAM:\n s.connect((server,53));s.sendall(struct.pack('!H',len(q))+q)\n hdr=s.recv(2)\n assert len(hdr)==2\n length=struct.unpack('!H',hdr)[0];response=b''\n while len(response)<length:\n  chunk=s.recv(length-len(response));assert chunk;response+=chunk\nelse:\n s.sendto(q,(server,53));response=s.recv(4096)\nassert len(response)>=12 and response[:2]==b'\\x12\\x34' and response[3]&15==0 and int.from_bytes(response[6:8],'big')>0\nprint('DNS_OK')\n'''.replace('TYPE', 'socket.SOCK_DGRAM' if protocol == 'udp' else 'socket.SOCK_STREAM')


def completion_probe_source(base, password):
    """Sent only over kubectl stdin; credentials and responses are never logged."""
    return '''import json,urllib.request,urllib.parse\nbase=BASE\nopener=urllib.request.build_opener(urllib.request.ProxyHandler({}))\nauth=urllib.parse.urlencode({'username':'admin','password':PASSWORD}).encode()\nwith opener.open(urllib.request.Request(base+'/auth/token',data=auth,headers={'Content-Type':'application/x-www-form-urlencoded'}),timeout=30) as r:\n token=json.load(r)['access_token']\nbody=json.dumps({'message':'Explain safe software deployment.','user_id':'egress-ci'}).encode()\nreq=urllib.request.Request(base+'/chat',data=body,headers={'Content-Type':'application/json','Authorization':'Bearer '+token})\nwith opener.open(req,timeout=60) as r:\n assert json.load(r).get('blocked') is False\nprint('EGRESS_OK')\n'''.replace('BASE',repr(base)).replace('PASSWORD',repr(password))


def pod_ip(kube, namespace, name, env):
    data = call(kube + ['-n', namespace, 'get', 'pod', name, '-o', 'jsonpath={.status.podIP}'],
                'FIXTURE_IP_FAILED', env=env)
    try:
        value = ipaddress.ip_address(data.decode('ascii'))
    except (ValueError, UnicodeError):
        raise StageError('FIXTURE_IP_INVALID') from None
    if value.version != 4:
        raise StageError('FIXTURE_IP_INVALID')
    return str(value)


def redis_egress_probe(kube, namespace, release, address, env):
    """Probe inside Redis's network namespace without changing its image."""
    selector = 'app.kubernetes.io/instance='+release+',app.kubernetes.io/name=redis'
    name = call(kube + ['-n',namespace,'get','pods','-l',selector,'-o','jsonpath={.items[0].metadata.name}'],
                'REDIS_POD_DISCOVERY_FAILED',env=env).decode('ascii')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', name):
        raise StageError('REDIS_POD_DISCOVERY_FAILED')
    target = 'pod/'+name
    call(kube + ['-n',namespace,'debug',target,'--image='+CLIENT_IMAGE,'--container=egress-probe',
                 '--','python','-c','import time; time.sleep(300)'], 'REDIS_DEBUG_START_FAILED',env=env)
    # A debug container shares the pod's network and hence its NetworkPolicy.
    probe = "import socket\ntry:\n socket.create_connection((HOST,PORT),timeout=5).close();print('CONNECTED')\nexcept socket.timeout:\n print('TIMEOUT')\nexcept Exception:\n print('ERROR')\n".replace('HOST',repr(address)).replace('PORT',repr(FIXTURE_PORT))
    args = kube + ['-n',namespace,'exec','-i',target,'-c','egress-probe','--','python','-']
    for attempt in range(30):
        try:
            result=call(args,'REDIS_DEBUG_EXEC_FAILED',env=env,input_data=probe.encode(),timeout=15)
            break
        except StageError:
            if attempt == 29:
                raise
            time.sleep(2)
    try:
        result=result.decode('ascii').strip()
    except UnicodeError:
        raise StageError('REDIS_DEBUG_OUTPUT_INVALID') from None
    require_probe(result,'TIMEOUT','REDIS_OUTBOUND_NOT_DENIED')


def run():
    ci_only()
    work = Path(os.environ['TEST_WORKSPACE']).resolve(strict=True)
    python = work / 'venv/bin/python'
    suffix = secrets.token_hex(6)
    name = 'uter-egress-' + suffix
    cluster = name + '-kind'
    fixture_ns = name + '-fixtures'
    ingress_ns = name + '-ingress'
    kube = ['kubectl', '--context', 'kind-' + cluster]
    attempted = False
    with tempfile.TemporaryDirectory(prefix='uter-egress-ci-', dir=work) as temp:
        temp = Path(temp)
        inputs = temp/'inputs'
        manifest = verify_published_inputs(work, inputs)
        env = os.environ.copy()
        for key in list(env):
            if key.startswith('COMPOSE_') or key in ('DOCKER_HOST', 'DOCKER_CONTEXT') or key.lower() in ('http_proxy','https_proxy','all_proxy','no_proxy'):
                del env[key]
        env['KUBECONFIG'] = str(temp/'kubeconfig')
        docker_config = temp/'docker-config'; docker_config.mkdir(mode=0o700)
        env['DOCKER_CONFIG'] = str(docker_config)
        config = temp/'kind.yaml'
        config.write_text('kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnetworking:\n  disableDefaultCNI: true\n  podSubnet: 192.168.0.0/16\n')
        try:
            existing = call(['kind','get','clusters'], 'KIND_DISCOVERY_FAILED', env=env).decode().splitlines()
            if cluster in existing:
                raise StageError('CLUSTER_NAME_ALREADY_EXISTS')
            attempted = True
            call(['kind','create','cluster','--name',cluster,'--image',NODE_IMAGE,'--config',config,
                  '--kubeconfig',env['KUBECONFIG']], 'KIND_CREATE_FAILED', env=env)
            call(kube + ['apply','-f','-'], 'CALICO_APPLY_FAILED', env=env,
                 input_data=calico_manifest(work/'download/calico.yaml'))
            for resource in ('daemonset/calico-node','deployment/calico-kube-controllers','deployment/coredns'):
                call(kube + ['-n','kube-system','rollout','status',resource,'--timeout=360s'],
                     'NETWORK_COMPONENT_NOT_READY', env=env, timeout=390)
            call(kube + ['wait','--for=condition=Ready','nodes','--all','--timeout=300s'],
                 'NODES_NOT_READY', env=env, timeout=330)
            for namespace in (fixture_ns, ingress_ns):
                call(kube + ['create','namespace',namespace], 'NAMESPACE_CREATE_FAILED', env=env)
            fixture = ROOT/'tests/fixtures/scheduled_backup_upstream.py'
            call(kube + ['-n',fixture_ns,'create','configmap','llm-fixture','--from-file=fixture.py='+str(fixture)],
                 'FIXTURE_CONFIG_FAILED', env=env)
            for pod, label in (('llm-allowed','upstream-allowed'),('llm-denied','upstream-denied')):
                call(kube + ['create','-f','-'], 'FIXTURE_CREATE_FAILED', env=env,
                     input_data=json.dumps(fixture_pod(fixture_ns,pod,label)).encode())
                call(kube + ['-n',fixture_ns,'wait','--for=condition=Ready','pod/'+pod,'--timeout=240s'],
                     'FIXTURE_NOT_READY', env=env, timeout=270)
            call(kube + ['-n',fixture_ns,'expose','pod','llm-allowed','--name=llm','--port=8080'],
                 'FIXTURE_SERVICE_FAILED', env=env)
            allowed_ip = pod_ip(kube,fixture_ns,'llm-allowed',env)
            denied_ip = pod_ip(kube,fixture_ns,'llm-denied',env)
            if allowed_ip == denied_ip:
                raise StageError('FIXTURE_IP_INVALID')
            call(kube + ['create','-f','-'], 'CLIENT_POD_CREATE_FAILED', env=env,
                 input_data=json.dumps(client_pod(ingress_ns)).encode())
            call(kube + ['-n',ingress_ns,'wait','--for=condition=Ready','pod/network-client','--timeout=240s'],
                 'CLIENT_POD_NOT_READY', env=env, timeout=270)
            for addr, port in ((allowed_ip,FIXTURE_PORT),(allowed_ip,DENIED_PORT),(denied_ip,FIXTURE_PORT)):
                require_probe(tcp_probe(kube,ingress_ns,'pod/network-client',addr,port,env),
                              'CONNECTED','FIXTURE_CONTROL_CONNECTION_FAILED')
            key = temp/'empty-key'; key.write_bytes(b''); key.chmod(0o600)
            home = temp/'home'
            base = 'http://llm.'+fixture_ns+'.svc.cluster.local:8080'
            installer = ROOT/'scripts/install.py'
            call([python, installer, 'prepare', '--home', home, '--backend','kubernetes','--name',name,
                  '--context','kind-'+cluster, '--inputs',inputs, '--llm-url',base+'/v1', '--llm-model','test-model',
                  '--llm-key-file',key,'--allow-http-llm'], 'PREPARE_FAILED', env=env)
            values_path = home/'values.yaml'
            values = yaml.safe_load(values_path.read_text())
            values['ingressNamespace'] = ingress_ns
            values['networkPolicy'] = {'egress': egress_values(fixture_ns)}
            values_path.write_text(yaml.safe_dump(values))
            cfg = json.loads((home/'install.json').read_text())
            if cfg['images'] != manifest['images']:
                raise StageError('SIGNED_IMAGE_MISMATCH')
            call([python,installer,'check','--home',home], 'CHECK_FAILED', env=env)
            call([python,installer,'install','--home',home], 'INSTALL_FAILED', env=env, timeout=600)
            guard = 'deployment/'+name+'-guardrail'
            agent = 'deployment/'+name+'-agent'
            for target in (guard, agent):
                for protocol in ('udp','tcp'):
                    require_probe(run_probe(kube,name,target,dns_probe_source(protocol),env), 'DNS_OK','DNS_FAILED')
            for service, port in (('agent',8001),('redis',6379)):
                host=name+'-'+service+'.'+name+'.svc.cluster.local'
                require_probe(tcp_probe(kube,name,guard,host,port,env),'CONNECTED','INTERNAL_TRAFFIC_FAILED')
            host=name+'-guardrail.'+name+'.svc.cluster.local'
            require_probe(tcp_probe(kube,name,agent,host,8000,env),'CONNECTED','AGENT_TO_GUARDRAIL_FAILED')
            require_probe(tcp_probe(kube,name,guard,allowed_ip,FIXTURE_PORT,env),'CONNECTED','LLM_NOT_ALLOWED')
            for target, addr, port in ((guard,allowed_ip,DENIED_PORT),(guard,denied_ip,FIXTURE_PORT),
                                       (agent,allowed_ip,FIXTURE_PORT)):
                require_probe(tcp_probe(kube,name,target,addr,port,env),'TIMEOUT','OUTBOUND_NOT_DENIED')
            redis_egress_probe(kube,name,name,allowed_ip,env)
            ready = "import json\nfrom urllib import request\nwith request.urlopen(URL,timeout=10) as r:\n assert json.load(r).get('ready') is True\nprint('READY')\n".replace('URL',repr('http://'+host+':8000/ready'))
            require_probe(run_probe(kube,ingress_ns,'pod/network-client',ready,env),'READY','GUARDRAIL_NOT_READY')
            credentials = json.loads((home/'credentials.json').read_text())
            # Timeout accommodates the full guardrail pipeline and protocol fixture.
            source = completion_probe_source('http://'+host+':8000',credentials['admin'])
            output = call(kube+['-n',ingress_ns,'exec','-i','pod/network-client','--','python','-'],
                          'COMPLETION_FAILED',env=env,input_data=source.encode(),timeout=90)
            if output.strip() != b'EGRESS_OK':
                raise StageError('COMPLETION_FAILED')
            print(json.dumps({'egress_policy':'enabled','calico':'v3.33.0','dns_tcp_udp':'pass',
                'internal_connections':'pass','llm_pod_and_port':'pass','denied_pod_port_and_agent':'pass',
                'readiness':'pass','redis_outbound':'pass via ephemeral debug container',
                'completion':'pass against deterministic fixture; not a real LLM',
                'corporate_cni_dns_and_policies':'not tested'}))
        finally:
            if attempted and not cleanup(['kind','delete','cluster','--name',cluster,'--kubeconfig',env['KUBECONFIG']],env):
                raise StageError('CI_CLEANUP_FAILED')


if __name__ == '__main__':
    try:
        run()
    except Exception as exc:
        category = str(exc) if isinstance(exc, StageError) else 'EGRESS_VALIDATION_FAILED'
        print('Isolated egress test failed: '+category+'; raw details withheld', file=sys.stderr)
        sys.exit(1)
