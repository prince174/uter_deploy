#!/usr/bin/env python3
"""Exercise the published install wizard with isolated LiteLLM and CPU vLLM.

Only disposable GitHub-hosted Linux workflow_dispatch runners are supported. No
product source, operator credentials, existing local workloads or raw logs are used.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts')]
from scripts import extract_release_inputs, extract_signed_bundle
from scripts import litellm_vllm_ci as llm, wizard_ci as common
import uterctl

LABEL = 'uter.ci.operation'
ID = re.compile(r'[0-9a-f]{64}\Z')


class Failure(Exception):
    """Fixed error category; external output is never displayed."""


def command(argv, category, *, timeout=900, env=None, capture=True, allowed_failure=False):
    try:
        result = subprocess.run([str(item) for item in argv], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure(category) from None
    if result.returncode and not allowed_failure:
        raise Failure(category)
    output = result.stdout or b''
    if len(output) > 1024 * 1024:
        raise Failure(category)
    return result.returncode, output


def checked_id(raw):
    try:
        value = raw.decode('ascii').strip()
    except UnicodeError:
        raise Failure('RESOURCE_ID_INVALID') from None
    if not ID.fullmatch(value):
        raise Failure('RESOURCE_ID_INVALID')
    return value


def require_local_docker():
    """Check the configured endpoint before any container or cluster mutation."""
    _, raw = command(['docker', 'context', 'inspect', 'default'], 'DOCKER_CONTEXT_UNAVAILABLE', timeout=30)
    try:
        contexts = json.loads(raw)
        if not isinstance(contexts, list) or len(contexts) != 1:
            raise ValueError
        context = contexts[0]
        endpoint = context['Endpoints']['docker']['Host']
        parts = urllib.parse.urlsplit(endpoint)
        if (context['Name'] != 'default' or parts.scheme != 'unix' or parts.netloc
                or parts.query or parts.fragment or not parts.path.startswith('/')
                or os.path.normpath(parts.path) != parts.path):
            raise ValueError
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise Failure('LOCAL_DOCKER_REQUIRED') from None
    _, current = command(['docker', 'context', 'show'], 'DOCKER_CONTEXT_UNAVAILABLE', timeout=30)
    if current.strip() != b'default':
        raise Failure('LOCAL_DOCKER_REQUIRED')


def owned(kind, ident, name, operation):
    if not ID.fullmatch(ident):
        return False
    expression = ('{{.Id}}|{{.Name}}|{{index .Config.Labels "' + LABEL + '"}}'
                  if kind == 'container' else
                  '{{.Id}}|{{.Name}}|{{index .Labels "' + LABEL + '"}}')
    status, raw = command(['docker', '--context', 'default', kind, 'inspect', '--format', expression, ident],
                          'RESOURCE_INSPECT_FAILED', timeout=30, allowed_failure=True)
    if status:
        return False
    expected_name = '/' + name if kind == 'container' else name
    return raw.decode('utf-8', 'replace').strip() == '|'.join((ident, expected_name, operation))


def project_resources(name):
    expected = {'container': {f'{name}-{role}-1' for role in ('guardrail', 'agent', 'redis')},
                'network': {name+'_backend', name+'_outbound'},
                'volume': {name+'_redis-data', name+'_audit-data'}}
    for kind, names in expected.items():
        base = ['docker', '--context', 'default', kind, 'ls']
        if kind == 'container': base.append('--all')
        format_arg = '{{.Names}}' if kind == 'container' else '{{.Name}}'
        _, all_raw = command(base + ['--format', format_arg], 'PROJECT_IDENTITY_UNAVAILABLE', timeout=30)
        _, owned_raw = command(base + ['--filter', 'label=com.docker.compose.project='+name,
                                      '--format', format_arg], 'PROJECT_IDENTITY_UNAVAILABLE', timeout=30)
        all_names = set(all_raw.decode('utf-8', 'replace').splitlines())
        found = set(owned_raw.decode('utf-8', 'replace').splitlines())
        # A reserved name without our Compose project label must never be removed.
        if not found <= names or all_names.intersection(names) != found:
            raise Failure('PROJECT_IDENTITY_CHANGED')
    return expected


def require_project_absent(name):
    reserved = project_resources(name)
    for kind in ('container', 'network', 'volume'):
        argv = ['docker', '--context', 'default', kind, 'ls']
        if kind == 'container': argv.append('--all')
        format_arg = '{{.Names}}' if kind == 'container' else '{{.Name}}'
        found = command(argv + ['--format', format_arg], 'PROJECT_LOOKUP_FAILED', timeout=30)[1]
        if set(found.decode('utf-8', 'replace').splitlines()).intersection(reserved[kind]):
            raise Failure('PROJECT_ALREADY_EXISTS')


def cleanup_compose(home, name, manifest):
    # The signed installer writes pending state immediately before any Docker
    # mutation; a failed prepare/check has nothing to clean up.
    if not home.exists() or not (home/'install-state.json').exists():
        return
    config = json.loads((home/'install.json').read_text())
    if config.get('name') != name or config.get('backend') != 'compose' or config.get('context') != 'default':
        raise Failure('PROJECT_IDENTITY_CHANGED')
    project_resources(name)
    env = {k: v for k, v in os.environ.items() if not k.startswith('COMPOSE_') and k != 'DOCKER_HOST'}
    env.update({role.upper()+'_IMAGE': value for role, value in manifest['images'].items()})
    env.update(RUNTIME_DIR=str(home/'runtime'), GUARDRAIL_PORT=str(llm.UTER_PORT), GUARDRAIL_CPUS='2')
    command(['docker', '--context', 'default', 'compose', '--project-name', name,
             '--env-file', home/'empty.env', '-f', home/'compose/compose.yaml', 'down', '--volumes'],
            'PROJECT_CLEANUP_FAILED', timeout=300, env=env, capture=False)


def remove_owned(kind, ident, name, operation):
    if ident is None:
        return
    if not owned(kind, ident, name, operation):
        raise Failure('RESOURCE_IDENTITY_CHANGED')
    if kind == 'network':
        _, raw = command(['docker', '--context', 'default', 'network', 'inspect', '--format',
                          '{{json .Containers}}', ident], 'RESOURCE_INSPECT_FAILED', timeout=30)
        if json.loads(raw or b'{}'):
            raise Failure('NETWORK_HAS_UNEXPECTED_ATTACHMENTS')
    command(['docker', '--context', 'default', kind, 'rm', '-f', ident] if kind == 'container' else
            ['docker', '--context', 'default', kind, 'rm', ident], 'RESOURCE_CLEANUP_FAILED',
            timeout=120, capture=False)


def release_stage(root, temporary, tag, version):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', tag):
        raise Failure('RELEASE_TAG_INVALID')
    if not uterctl.VERSION.fullmatch(version):
        raise Failure('RELEASE_VERSION_INVALID')
    release = temporary/'verified-release'
    release.mkdir(mode=0o700)
    downloads = release/'downloads'; downloads.mkdir(mode=0o700)
    source = root/'work/pair/new'
    for item in ('signed-bundle.tar.gz', 'publisher-public.pem',
                 'installation-inputs.tar.gz', 'installation-inputs.tar.gz.sha256'):
        common.copy_file(source/item, downloads/item)
    key = downloads/'publisher-public.pem'
    if hashlib.sha256(key.read_bytes()).hexdigest() != common.FINGERPRINT:
        raise Failure('PUBLISHER_FINGERPRINT_MISMATCH')
    bundle = release/'bundle'
    manifest = extract_signed_bundle.extract(downloads/'signed-bundle.tar.gz', key, bundle)
    if (manifest.get('version') != version or not manifest.get('installation_archive_sha256')
            or manifest.get('deployment_commit') != common.tag_commit(root, tag)):
        raise Failure('SIGNED_RELEASE_IDENTITY_MISMATCH')
    extract_release_inputs.extract(downloads/'installation-inputs.tar.gz', downloads/'installation-inputs.tar.gz.sha256',
                                   temporary/'checked-inputs', bundle=bundle, key=key)
    checkout = common.trusted_tag_checkout(root, temporary/'trusted-checkout', tag, bundle, manifest)
    return release, bundle, manifest, checkout


def metric(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(url+'/metrics', timeout=15) as response:
        return llm.metric_total(response.read(1024*1024).decode('utf-8'))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, message, headers, newurl):
        return None


def local_json(url, payload=None, *, token=None, form=False, extra_headers=None, timeout=120):
    """Never send even temporary CI credentials to proxies or redirect targets."""
    parts = urllib.parse.urlsplit(url)
    try:
        addr = ipaddress.ip_address(parts.hostname or '')
        if (parts.scheme != 'http' or addr.version != 4 or not addr.is_private
                or parts.username or parts.password or parts.query or parts.fragment or not parts.port):
            raise ValueError
    except ValueError:
        raise Failure('LOCAL_ENDPOINT_INVALID') from None
    headers = dict(extra_headers or {})
    if token: headers['Authorization'] = 'Bearer '+token
    body = None
    if payload is not None:
        body = (urllib.parse.urlencode(payload) if form else json.dumps(payload)).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(urllib.request.Request(url, data=body, headers=headers), timeout=timeout) as response:
        data = response.read(65537)
    if len(data) > 65536: raise Failure('LOCAL_RESPONSE_TOO_LARGE')
    return json.loads(data)


def wait_local(url, *, token=None, attempts=150, state_probe=None, timeout_category):
    if timeout_category not in llm.READINESS_TIMEOUT_CATEGORIES:
        raise Failure('READINESS_CATEGORY_INVALID')
    for _ in range(attempts):
        try:
            return local_json(url, token=token, timeout=5)
        except (OSError, ValueError):
            if state_probe:
                category = state_probe(False)
                if category: raise Failure('SERVICE_EXITED')
            time.sleep(4)
    raise Failure(timeout_category)


def completion(base, model, *, token=None, extra_headers=None):
    result = local_json(base+'/v1/chat/completions',
                        {'model':model, 'messages':[{'role':'user', 'content':'Say hi.'}],
                         'max_tokens':4, 'temperature':0}, token=token,
                        extra_headers=extra_headers, timeout=360)
    choices = result.get('choices') if isinstance(result, dict) else None
    item = choices[0] if isinstance(choices, list) and choices else None
    message = item.get('message') if isinstance(item, dict) else None
    content = message.get('content') if isinstance(message, dict) else None
    if not isinstance(content, str) or not content.strip():
        raise Failure('COMPLETION_INVALID')


def forward_ready(context, name, port):
    proc = subprocess.Popen(['kubectl', '--context', context, '-n', name, 'port-forward', '--address',
                             '127.0.0.1', 'svc/'+name+'-guardrail', f'{port}:8000'],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    expected = f'Forwarding from 127.0.0.1:{port} -> 8000'.encode()
    data = b''; deadline = time.monotonic()+45
    while proc.poll() is None and time.monotonic() < deadline and len(data) < 8192:
        ready, _, _ = select.select([proc.stdout], [], [], 1)
        if ready:
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk: break
            data += chunk
            if expected in data and proc.poll() is None:
                return proc
    stop_forward(proc)
    raise Failure('PORT_FORWARD_FAILED')


def stop_forward(proc):
    if proc is None: return
    try:
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=5)
    finally:
        if proc.stdout: proc.stdout.close()


def main():
    common.runner_guard(os.environ, ROOT)
    if os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT') not in (None, '', 'default'):
        raise Failure('LOCAL_DOCKER_REQUIRED')
    require_local_docker()
    backend, tag, version = (os.environ.get(name, '') for name in ('BACKEND', 'RELEASE_TAG', 'RELEASE_VERSION'))
    operation = secrets.token_hex(16)
    name = 'uter-wizard-llm-' + operation[:12]
    cluster = name+'-kind'; network = name+'-llm'; vllm = name+'-vllm'; proxy = name+'-proxy'
    network_id = vllm_id = proxy_id = node_id = None
    attempted = cluster_created = install_finished = False
    pending_creates = set()
    forward = None
    with tempfile.TemporaryDirectory(prefix='uter-wizard-llm-', dir='/tmp') as folder:
        stage = Path(folder); os.chmod(stage, 0o700)
        release, bundle, manifest, checkout = release_stage(ROOT, stage, tag, version)
        llm.preflight_resources(backend, *llm.read_host_resources(stage))
        require_project_absent(name)
        for kind, resource in (('container', vllm), ('container', proxy), ('network', network)):
            _, raw = command(['docker', '--context', 'default', kind, 'ls', '--filter', 'name=^'+resource+'$',
                              '--quiet'], 'RESOURCE_LOOKUP_FAILED', timeout=30)
            if raw.strip(): raise Failure('RESOURCE_ALREADY_EXISTS')
        if backend == 'kubernetes':
            if cluster in command(['kind', 'get', 'clusters'], 'CLUSTER_LOOKUP_FAILED', timeout=30)[1].decode().splitlines():
                raise Failure('CLUSTER_ALREADY_EXISTS')
        key = 'sk-'+secrets.token_hex(32)
        keyfile = stage/'llm-key'; keyfile.write_text(key+'\n'); keyfile.chmod(0o600)
        envfile = stage/'llm-env'; envfile.write_text('LITELLM_MASTER_KEY='+key+'\n'); envfile.chmod(0o600)
        config = stage/'litellm.yaml'; config.write_text(llm.proxy_config()); config.chmod(0o644)
        cache = stage/'model-cache'; cache.mkdir(mode=0o700)
        home = stage/'home'; environment = stage/'venv'
        try:
            if backend == 'kubernetes':
                print('Stage: isolated kind cluster', flush=True)
                pending_creates.add('KIND')
                command(['kind', 'create', 'cluster', '--name', cluster, '--image', llm.KIND_IMAGE, '--wait', '180s'],
                        'CLUSTER_CREATE_FAILED', timeout=600, capture=False)
                cluster_created = True
                _, raw = command(['docker', '--context', 'default', 'container', 'inspect', '--format', '{{.Id}}',
                                  cluster+'-control-plane'], 'CLUSTER_ID_UNAVAILABLE', timeout=30)
                node_id = checked_id(raw)
                pending_creates.remove('KIND')
                command(llm.kind_resource_limit_command(cluster), 'CLUSTER_LIMIT_FAILED', timeout=30, capture=False)
                _, raw = command(['docker', '--context', 'default', 'inspect', cluster+'-control-plane'],
                                 'CLUSTER_GATEWAY_UNAVAILABLE', timeout=30)
            else:
                _, raw = command(['docker', '--context', 'default', 'network', 'inspect', 'bridge'],
                                 'BRIDGE_GATEWAY_UNAVAILABLE', timeout=30)
            gateway = llm.docker_gateway(backend, json.loads(raw))
            print('Stage: vLLM and LiteLLM', flush=True)
            pending_creates.add('NETWORK')
            _, raw = command(['docker', '--context', 'default', 'network', 'create', '--label',
                              LABEL+'='+operation, network], 'LLM_NETWORK_CREATE_FAILED', timeout=90)
            network_id = checked_id(raw)
            pending_creates.remove('NETWORK')
            create_vllm = llm.vllm_container_command(vllm, network, cache)
            create_vllm[3:3] = ['--label', LABEL+'='+operation]
            pending_creates.add('VLLM')
            _, raw = command(create_vllm, 'VLLM_START_FAILED', timeout=900)
            vllm_id = checked_id(raw)
            pending_creates.remove('VLLM')
            vllm_url = 'http://127.0.0.1:'+str(llm.VLLM_PORT)
            models = wait_local(vllm_url+'/v1/models', attempts=225,
                                state_probe=lambda timed: llm.container_state_category(vllm, 'VLLM', timeout=timed),
                                timeout_category='VLLM_MODELS_READY_TIMEOUT')
            if not any(item.get('id') == llm.MODEL for item in models.get('data', [])):
                raise Failure('VLLM_MODEL_MISMATCH')
            completion(vllm_url, llm.MODEL)
            pending_creates.add('LITELLM')
            _, raw = command(['docker', '--context', 'default', 'run', '-d', '--name', proxy, '--network', network,
                              '--label', LABEL+'='+operation, '--memory', '2g', '--cpus', '1', '--cap-drop', 'ALL',
                              '--security-opt', 'no-new-privileges', '-p', f'{gateway}:{llm.PROXY_PORT}:4000',
                              '--env-file', envfile, '-v', f'{config}:/app/uter-ci.yaml:ro', llm.LITELLM_IMAGE,
                              '--config', '/app/uter-ci.yaml', '--num_workers', '1'], 'LITELLM_START_FAILED', timeout=900)
            proxy_id = checked_id(raw)
            pending_creates.remove('LITELLM')
            proxy_url = f'http://{gateway}:{llm.PROXY_PORT}'
            wait_local(proxy_url+'/v1/models', token=key,
                       state_probe=lambda timed: llm.container_state_category(proxy, 'LITELLM', timeout=timed),
                       timeout_category='LITELLM_MODELS_READY_TIMEOUT')
            completion(proxy_url, llm.MODEL_ALIAS, token=key)
            print('Stage: signed installation wizard and real LLM acceptance', flush=True)
            wizard = checkout/'scripts/install_wizard.py'
            values = [sys.executable, wizard, '--non-interactive', '--release', tag, '--version', version,
                      '--fingerprint', common.FINGERPRINT, '--release-dir', release, '--reuse-release',
                      '--backend', backend, '--home', home, '--name', name, '--llm-url', proxy_url+'/v1',
                      '--llm-model', llm.MODEL_ALIAS, '--llm-key-file', keyfile, '--allow-http-llm',
                      '--health-url', proxy_url+'/v1/models', '--port', str(llm.UTER_PORT), '--guardrail-cpus', '2']
            if backend == 'kubernetes': values += ['--context', 'kind-'+cluster]
            before = metric(vllm_url)
            attempted = True
            command(common.bootstrap_command(sys.executable, checkout, environment, 'install', values),
                    'SIGNED_WIZARD_FAILED', timeout=1800, capture=False)
            install_finished = True
            state = json.loads((home/'install-state.json').read_text())
            if state != {'status': 'ready', 'acceptance': 'passed'}:
                raise Failure('WIZARD_ACCEPTANCE_NOT_PASSED')
            if metric(vllm_url) <= before:
                raise Failure('WIZARD_LLM_TOKENS_UNCHANGED')
            if backend == 'kubernetes':
                forward = forward_ready('kind-'+cluster, name, llm.UTER_PORT)
            base = 'http://127.0.0.1:'+str(llm.UTER_PORT)
            wait_local(base+'/ready', attempts=45, timeout_category='UTER_READY_TIMEOUT')
            credentials = json.loads((home/'credentials.json').read_text())
            auth = local_json(base+'/auth/token', {'username':'admin', 'password':credentials['admin']}, form=True)
            before = metric(vllm_url)
            completion(base, 'uter-guardrail-chat', token=auth['access_token'],
                       extra_headers={'X-Uter-Ingress-Secret':credentials['openai_ingress_key']})
            if metric(vllm_url) <= before:
                raise Failure('UTER_LLM_TOKENS_UNCHANGED')
            print('Stage: wizard acceptance and independent Uter completion passed', flush=True)
        finally:
            # Failure or timeout before a create returns its ID may still leave
            # daemon-side operations running; never assert complete cleanup.
            cleanup_errors = ['CREATE_UNCERTAIN'] if pending_creates else []
            if attempted and not install_finished:
                cleanup_errors.append('INSTALL_UNCERTAIN')
            try: stop_forward(forward)
            except (OSError, subprocess.SubprocessError): cleanup_errors.append('FORWARD')
            if attempted and backend == 'compose':
                try: cleanup_compose(home, name, manifest)
                except Exception: cleanup_errors.append('COMPOSE')
            if cluster_created:
                try:
                    _, raw = command(['docker', '--context', 'default', 'container', 'inspect', '--format',
                                      '{{.Id}}|{{index .Config.Labels "io.x-k8s.kind.cluster"}}', node_id],
                                     'CLUSTER_ID_UNAVAILABLE', timeout=30)
                    if raw.decode().strip() != node_id+'|'+cluster: raise Failure('CLUSTER_IDENTITY_CHANGED')
                    command(['kind', 'delete', 'cluster', '--name', cluster], 'CLUSTER_CLEANUP_FAILED',
                            timeout=180, capture=False)
                except Exception: cleanup_errors.append('KIND')
            for kind, ident, resource in (('container', proxy_id, proxy), ('container', vllm_id, vllm),
                                          ('network', network_id, network)):
                try: remove_owned(kind, ident, resource, operation)
                except Exception: cleanup_errors.append('RESOURCE')
            if cleanup_errors:
                print('Cleanup inconclusive; resources or daemon operations may remain on the disposable runner.', file=sys.stderr)
                raise Failure('ISOLATED_CLEANUP_INCONCLUSIVE')
    evidence = {'backend': backend, 'public_signed_wizard': 'pass', 'vllm_direct': 'pass',
                'litellm_direct': 'pass', 'wizard_acceptance': 'pass', 'uter_completion': 'pass',
                'vllm_tokens_increased': 'pass', 'model_revision': llm.MODEL_REVISION,
                'environment': 'disposable GitHub-hosted runner', 'release_version': version}
    path = ROOT/'work/wizard-real-llm-evidence.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream: json.dump(evidence, stream, indent=2)
    print(json.dumps(evidence))


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        # Exception text from HTTP, processes and credentials must never be echoed.
        code = str(exc) if isinstance(exc, Failure) else 'ISOLATED_WIZARD_LLM_FAILED'
        print('Wizard real-LLM check failed: '+code, file=sys.stderr)
        sys.exit(1)
