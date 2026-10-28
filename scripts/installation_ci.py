"""Real registry-to-installation test. Runs only on disposable GitHub-hosted Linux."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error

import install as installer
from smoke_http import check as smoke_http

ROOT = Path(__file__).resolve().parents[1]
PYTHON_IMAGE = 'python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea'
NODE_IMAGE = 'kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0'


def run(argv, **kw):
    result = subprocess.run([str(x) for x in argv], capture_output=True, **kw)
    if result.returncode:
        # Callers only get sanitized diagnostics, never process output with credentials.
        message = f'{argv[0]} failed with exit {result.returncode}'
        if len(argv) > 1 and str(argv[1]).endswith('adopt_managed.py'):
            diagnostic = result.stderr.decode(errors='replace')
            allowed = ('Current bundle does not match installed images', 'Installation deployment assets do not match signed bundle', 'Image configuration ID mismatch', 'does not match the signed image', 'Pre-adoption smoke failed', 'Bundle inventory mismatch', 'No module named', 'Permission denied', 'No such file or directory', 'Expected exactly one running', 'Expected one ready', 'installation context', 'runtime file', 'Unsupported tooling schema', 'InvalidSignature')
            match = next((item for item in allowed if item in diagnostic), 'unclassified adoption failure')
            message += ': ' + match
        raise RuntimeError(message)
    return result.stdout


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.name != 'posix':
        raise SystemExit('Disposable GitHub-hosted Linux runner required')
    backend = os.environ['BACKEND']
    assert backend in ('compose', 'kubernetes')
    home = ROOT / 'work/installation'
    evidence = ROOT / 'work/installation-evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    inputs = ROOT / 'work/published'
    fixture = None
    forward = None
    cfg = None
    cluster_created = False
    name = 'uter-install-ci'
    cluster = 'uter-ci'
    kube = ['kubectl', '--context', 'kind-' + cluster]
    registry = ROOT / 'work/registry'
    registry.mkdir(mode=0o700)
    public = os.environ.get('PUBLIC_REGISTRY') == '1'
    token = auth = ''
    if not public:
        token = os.environ['REGISTRY_TOKEN']
        registry_host = os.environ.get('REGISTRY_HOST', 'ghcr.io')
        registry_user = os.environ.get('REGISTRY_USER', os.environ['GITHUB_ACTOR'])
        auth = base64.b64encode(f'{registry_user}:{token}'.encode()).decode()
        installer.save(registry / 'config.json', json.dumps({'auths': {('https://index.docker.io/v1/' if registry_host == 'docker.io' else registry_host): {'auth': auth}}}))
    os.environ['DOCKER_CONFIG'] = str(registry)
    installer.save(ROOT / 'work/llm-key', '')
    try:
        if backend == 'compose':
            gateway = json.loads(run(['docker', 'network', 'inspect', 'bridge']))[0]['IPAM']['Config'][0]['Gateway']
            fixture = subprocess.Popen([sys.executable, str(ROOT / 'tests/fixtures/upstream.py')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            url = f'http://{gateway}:8080'
        else:
            run(['kind', 'create', 'cluster', '--name', cluster, '--image', NODE_IMAGE, '--wait', '180s'])
            cluster_created = True
            run(kube + ['create', 'namespace', 'uter-fixtures'])
            run(kube + ['-n', 'uter-fixtures', 'create', 'configmap', 'llm-code', '--from-file=fixture.py=' + str(ROOT / 'tests/fixtures/upstream.py')])
            fixture_doc = {
                'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'llm', 'namespace': 'uter-fixtures'},
                'spec': {'selector': {'matchLabels': {'app': 'llm'}}, 'template': {'metadata': {'labels': {'app': 'llm'}},
                    'spec': {'containers': [{'name': 'llm', 'image': PYTHON_IMAGE, 'command': ['python', '/fixture/fixture.py'],
                        'ports': [{'containerPort': 8080}], 'readinessProbe': {'httpGet': {'path': '/health', 'port': 8080}},
                        'volumeMounts': [{'name': 'code', 'mountPath': '/fixture', 'readOnly': True}]}],
                        'volumes': [{'name': 'code', 'configMap': {'name': 'llm-code'}}]}}}}
            run(kube + ['create', '-f', '-'], input=json.dumps(fixture_doc).encode())
            run(kube + ['-n', 'uter-fixtures', 'expose', 'deployment', 'llm', '--port=8080'])
            run(kube + ['-n', 'uter-fixtures', 'rollout', 'status', 'deployment/llm', '--timeout=180s'])
            url = 'http://llm.uter-fixtures.svc.cluster.local:8080'
        installer_script = Path(os.environ['SIGNED_BUNDLE_PATH']) / 'scripts/install.py' if os.environ.get('SIGNED_BUNDLE_PATH') else ROOT / 'scripts/install.py'
        prepare = [sys.executable, installer_script, 'prepare', '--home', home,
            '--backend', backend, '--name', name, '--inputs', inputs,
            '--llm-url', url, '--llm-model', 'test-model', '--llm-key-file', ROOT / 'work/llm-key', '--allow-http-llm']
        if backend == 'compose':
            prepare += ['--guardrail-cpus', '2']
        else:
            prepare += ['--context', 'kind-' + cluster]
            if not public: prepare += ['--registry-config', registry / 'config.json']
        run(prepare)
        cfg = json.loads((home / 'install.json').read_text())
        run([sys.executable, installer_script, 'check', '--home', home])
        run([sys.executable, installer_script, 'install', '--home', home])
        signed=os.environ.get('SIGNED_BUNDLE_PATH');trusted=os.environ.get('PUBLISHER_KEY_PATH')
        if bool(signed)!=bool(trusted):raise ValueError('Both signed bundle and trusted publisher key are required')
        if signed:
            run([sys.executable,Path(signed)/'scripts/adopt_managed.py','--home',home,
                 '--bundle',signed,'--publisher-key',trusted])
            state=json.loads((home/'state.json').read_text())
            if not state.get('adopted_installer'):raise ValueError('Signed installation adoption did not complete')
        if backend == 'kubernetes':
            forward = subprocess.Popen(kube + ['-n', name, 'port-forward', 'service/' + name + '-guardrail', '18000:8000'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for attempt in range(30):
            try:
                with urllib.request.urlopen('http://127.0.0.1:18000/ready', timeout=2) as response:
                    assert response.status == 200
                break
            except (urllib.error.URLError, TimeoutError):
                if attempt == 29:
                    raise
                time.sleep(1)
        credentials = json.loads((home / 'credentials.json').read_text())
        (evidence / 'http-smoke.json').write_text(json.dumps(smoke_http('http://127.0.0.1:18000', 'admin', credentials['admin']), indent=2))
        code = ('import os\nos.environ["CI_ADMIN_PASSWORD"]=' + repr(credentials['admin']) + '\n').encode()
        code += (ROOT / 'scripts/container_acceptance.py').read_bytes()
        cmd, env = installer.commands(home, cfg)
        def acceptance():
            if backend == 'compose':
                raw = run(cmd + ['exec', '-T', 'guardrail', 'python', '-'], env=env, input=code)
            else:
                raw = run(kube + ['-n', name, 'exec', '-i', 'deployment/' + name + '-guardrail', '--', 'python', '-'], input=code)
            return json.loads(raw)
        first = acceptance()
        (evidence / 'acceptance.json').write_text(json.dumps(first, indent=2))
        if backend == 'compose':
            run(cmd + ['restart'], env=env)
            run(cmd + ['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '300'], env=env)
        else:
            for service in ('redis', 'agent', 'guardrail'):
                run(kube + ['-n', name, 'rollout', 'restart', 'deployment/' + name + '-' + service])
                run(kube + ['-n', name, 'rollout', 'status', 'deployment/' + name + '-' + service, '--timeout=300s'])
        second = acceptance()
        assert second['audit_first_sha256'] == first['audit_first_sha256']
        assert second['audit_lines'] > first['audit_lines']
        (evidence / 'after-restart.json').write_text(json.dumps(second, indent=2))
        (evidence / 'result.json').write_text(json.dumps(dict(backend=backend, install='pass', restart='pass',
            registry_pull='anonymous by digest' if public else 'authenticated by digest', images=cfg['images'], configuration='installer generated; no runtime overrides',
            signed_adoption='pass' if signed else 'not requested',
            exposed_ready_endpoint='pass', restarted_services=['redis', 'agent', 'guardrail'],
            llm='deterministic HTTP fixture', judge='disabled; optional Ollama not exercised',
            kubernetes=NODE_IMAGE if backend == 'kubernetes' else None,
            network_policy='rendered; kind default CNI does not enforce policies' if backend == 'kubernetes' else None), indent=2))
        print(f'{backend}: installation, authenticated API, toxicity, input/output blocks and persistent audit after restart passed')
    finally:
        if forward:
            forward.terminate()
            forward.wait(timeout=10)
        # No raw Kubernetes Secrets, rendered config, kubeconfig or registry credentials in artifacts.
        sensitive = [token, auth]
        if home.exists():
            for f in (home / 'runtime').glob('*.env'):
                sensitive += [line.split('=', 1)[1] for line in f.read_text().splitlines() if '=' in line]
            if (home / 'credentials.json').exists():
                sensitive += list(json.loads((home / 'credentials.json').read_text()).values())
        def diagnostic(label, argv, env=None):
            result = subprocess.run([str(x) for x in argv], env=env, capture_output=True)
            text = (result.stdout + result.stderr).decode(errors='replace')
            for secret in sorted(sensitive, key=len, reverse=True):
                if secret:
                    text = text.replace(secret, '[REDACTED]')
            text = re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED-JWT]', text)
            (evidence / (label + '.txt')).write_text(text)
        if cfg and backend == 'compose':
            cmd, env = installer.commands(home, cfg)
            diagnostic('services', cmd + ['ps', '-a'], env)
            diagnostic('logs', cmd + ['logs', '--no-color', '--tail', '100'], env)
            subprocess.run(cmd + ['down', '--volumes', '--remove-orphans'], env=env, capture_output=True)
        if cluster_created:
            diagnostic('pods', kube + ['-n', name, 'get', 'pods,pvc', '-o', 'wide'])
            diagnostic('events', kube + ['-n', name, 'get', 'events', '--sort-by=.lastTimestamp'])
            for service in ('guardrail', 'agent', 'redis'):
                diagnostic(service + '-logs', kube + ['-n', name, 'logs', 'deployment/' + name + '-' + service, '--tail=100'])
            subprocess.run(['kind', 'delete', 'cluster', '--name', cluster], capture_output=True)
        if fixture:
            fixture.terminate()
            fixture.wait(timeout=10)


if __name__ == '__main__':
    main()
