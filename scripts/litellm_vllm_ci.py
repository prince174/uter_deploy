"""Disposable, public-release Compose and Kubernetes acceptance with real LiteLLM and CPU vLLM.

This CI-only driver refuses local execution. It never uses product source or an
existing installation; output deliberately excludes commands, credentials and LLM text.
"""
import json
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

VLLM_IMAGE = 'vllm/vllm-openai-cpu@sha256:827ef38187f9b52f2bb838695ef815ec5b65f4bf3e4c061b002b2b0a19cb0701'
LITELLM_IMAGE = 'ghcr.io/berriai/litellm@sha256:c169fb3adc514fcf210377c203f3de406d54f10bfdacf13948a4a839db9af7de'
MODEL = 'Qwen/Qwen2.5-0.5B-Instruct'
MODEL_REVISION = '2b01de6d1108f9b2b5e46a726aa678a359b6c03b'
MODEL_ALIAS = 'uter-ci-qwen'
KIND_IMAGE = 'kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0'
VLLM_PORT = 18081
PROXY_PORT = 18082
UTER_PORT = 18083
GIB = 1024 ** 3


class DiagnosticError(Exception):
    def __init__(self, category):
        super().__init__(category)
        self.category = category


def proxy_config():
    return ('model_list:\n  - model_name: ' + MODEL_ALIAS + '\n    litellm_params:\n'
            '      model: hosted_vllm/' + MODEL + '\n      api_base: http://vllm:8000\n'
            'general_settings:\n  master_key: os.environ/LITELLM_MASTER_KEY\n')


def preflight_resources(backend, flags, mem_available, disk_available):
    if backend not in ('compose', 'kubernetes'):
        raise DiagnosticError('BACKEND_INVALID')
    if not {'avx2', 'avx512f'}.intersection(flags):
        raise DiagnosticError('CPU_FLAGS_UNSUPPORTED')
    minimum_disk = 10 if backend == 'kubernetes' else 8
    minimum_memory = 10 if backend == 'kubernetes' else 8
    if disk_available < minimum_disk * GIB:
        raise DiagnosticError('DISK_SPACE_INSUFFICIENT')
    if mem_available < minimum_memory * GIB:
        raise DiagnosticError('AVAILABLE_MEMORY_INSUFFICIENT')


def read_host_resources(root):
    flags = set()
    for line in Path('/proc/cpuinfo').read_text().splitlines():
        if line.startswith('flags') and ':' in line:
            flags.update(line.split(':', 1)[1].split())
            break
    match = re.search(r'^MemAvailable:\s*(\d+)\s+kB$',
                      Path('/proc/meminfo').read_text(), re.MULTILINE)
    if not match:
        raise DiagnosticError('RESOURCE_INFORMATION_UNAVAILABLE')
    paths = [root, Path('/var/lib/docker')]
    available = []
    for path in paths:
        stat = os.statvfs(path)
        available.append(stat.f_bavail * stat.f_frsize)
    return flags, int(match.group(1)) * 1024, min(available)


def kind_resource_limit_command(cluster):
    # Docker defines memory-swap as combined RAM+swap. Set both together to
    # establish a 7 GiB RAM limit with no swap on the isolated kind node.
    return ['docker', 'update', '--memory', '7g', '--memory-swap', '7g',
            '--cpus', '2', cluster + '-control-plane']


def docker_gateway(backend, info):
    if backend == 'compose':
        value = info[0]['IPAM']['Config'][0]['Gateway']
    elif backend == 'kubernetes':
        value = info[0]['NetworkSettings']['Networks']['kind']['Gateway']
    else:
        raise ValueError('Unknown backend')
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_private:
        raise ValueError('Expected an isolated private IPv4 Docker gateway')
    return str(address)


def metric_total(body):
    """Sum Prometheus generation counters for all model/engine label sets."""
    result = 0.0
    found = False
    for line in body.splitlines():
        match = re.fullmatch(r'vllm:generation_tokens_total(?:\{[^{}]*\})?\s+([0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)\s*', line)
        if match:
            result += float(match.group(1))
            found = True
    if not found:
        raise ValueError('vLLM generation metric missing')
    return result


def json_request(url, payload=None, *, token=None, form=False, timeout=120, extra_headers=None):
    headers = dict(extra_headers or {})
    if token:
        headers['Authorization'] = 'Bearer ' + token
    body = None
    if payload is not None:
        if form:
            body = urllib.parse.urlencode(payload).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        else:
            body = json.dumps(payload).encode()
            headers['Content-Type'] = 'application/json'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(url, data=body, headers=headers), timeout=timeout) as response:
        return json.load(response)


def completion(base, model, *, token=None, extra_headers=None):
    result = json_request(base + '/v1/chat/completions', {
        'model': model, 'messages': [{'role': 'user', 'content': 'Reply with a short greeting.'}],
        'max_tokens': 12, 'temperature': 0,
    }, token=token, extra_headers=extra_headers)
    choices = result.get('choices')
    if not choices or not isinstance(choices[0].get('message', {}).get('content'), str) or not choices[0]['message']['content'].strip():
        raise ValueError('Completion had no message content')
    return True


LOG_LIMIT = 128 * 1024
# Fixed, non-interpolated categories. Never return any matching log text.
LOG_PATTERNS = (
    ('CPU_INSTRUCTION_UNSUPPORTED', r'illegal instruction|cpu (?:does not|doesn.t|must|should) support (?:avx|sse)|(?:avx2|avx512)[^\n]{0,80}(?:not supported|required|missing)'),
    ('MEMORY_ALLOCATION_FAILED', r'outofmemoryerror|out of memory|cannot allocate memory|std::bad_alloc|memoryerror'),
    ('DISK_FULL', r'no space left on device|errno[ :=\[]+28(?:\]|\b)|disk quota exceeded'),
    ('CLI_ARGUMENT_INVALID', r'unrecognized arguments:|no such option:|unknown option:'),
    ('MODEL_REVISION_NOT_FOUND', r'revisionnotfounderror|revision not found|invalid revision|revision [^\n]{0,100} not found'),
    ('MODEL_REPOSITORY_NOT_FOUND', r'repositorynotfounderror|repository not found|model repository [^\n]{0,80} not found'),
    ('MODEL_ARCHITECTURE_UNSUPPORTED', r'unsupported model architecture|model architectures? [^\n]{0,80} not supported|does not support model architecture'),
    ('MODEL_CONFIG_INVALID', r'cannot load (?:model )?config|failed to load (?:model )?config|config\.json[^\n]{0,80}(?:not found|invalid)|model config[^\n]{0,80}(?:invalid|failed|error)'),
    ('DTYPE_OR_PLATFORM_UNSUPPORTED', r'unsupported (?:dtype|data type|platform)|(?:dtype|float16|bfloat16)[^\n]{0,100}not supported|no supported device found|failed to infer device type'),
    ('MODULE_OR_LIBRARY_IMPORT_FAILED', r'modulenotfounderror|importerror|undefined symbol|cannot open shared object file'),
    ('KV_CACHE_INSUFFICIENT', r'kv cache[^\n]{0,120}(?:too small|insufficient|not enough|greater than)|no available memory for the cache blocks'),
    ('DNS_RESOLUTION_FAILED', r'temporary failure in name resolution|name or service not known|failed to resolve|nodename nor servname provided'),
    ('TLS_CERTIFICATE_FAILED', r'certificate_verify_failed|certificate verify failed|sslcertificateerror'),
    ('NETWORK_TIMEOUT', r'connecttimeout|readtimeout|connection timed out|timed out while requesting|read timed out'),
    ('NETWORK_CONNECTION_FAILED', r'connection refused|failed to establish a new connection|network is unreachable|connectionerror'),
    ('ENGINE_INITIALIZATION_FAILED', r'engine core initialization failed|engine process failed to start'),
)


def classify_container_log(text):
    # HTTP code alone is ambiguous: classify as Hugging Face only with Hub context.
    if re.search(r'huggingface|hf\.co|hfhub', text, re.IGNORECASE):
        for code in (401, 403, 429):
            if re.search(r'(?:\b' + str(code) + r'\s+(?:client error|error|unauthorized|forbidden|too many)|'
                         r'(?:http|status(?: code)?)[^\n0-9]{0,16}' + str(code) + r'\b)', text, re.IGNORECASE):
                return 'HF_HTTP_' + str(code)
    for category, pattern in LOG_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return category
    return None


def container_log_category(container):
    # Docker emits container stdout and stderr separately; combine them in an
    # unlinked temporary file, inspect a bounded tail, and never emit raw bytes.
    try:
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(['docker', 'logs', '--tail', '100', container],
                                    stdout=output, stderr=subprocess.STDOUT, timeout=15)
            if result.returncode:
                return None
            size = output.tell()
            output.seek(max(0, size - LOG_LIMIT))
            return classify_container_log(output.read(LOG_LIMIT).decode('utf-8', errors='replace'))
    except (OSError, subprocess.TimeoutExpired):
        return None


def container_state_category(container, component, *, timeout=False):
    """Inspect only fixed State fields; never fetch logs, Config or environment."""
    if component not in ('VLLM', 'LITELLM'):
        raise ValueError('Invalid component')
    result = subprocess.run(
        ['docker', 'inspect', '--format', '{{.State.Status}} {{.State.OOMKilled}} {{.State.ExitCode}}', container],
        capture_output=True,
    )
    if result.returncode:
        return component + '_STATE_UNAVAILABLE' if timeout else None
    raw = result.stdout.decode('ascii', errors='replace').strip()
    match = re.fullmatch(r'(created|running|paused|restarting|removing|exited|dead) (true|false) ([0-9]{1,3})', raw)
    if not match or int(match.group(3)) > 255:
        return component + '_STATE_UNAVAILABLE' if timeout else None
    state, oom, code = match.groups()
    if oom == 'true':
        return component + '_OOM_KILLED_EXIT_' + code
    if state in ('exited', 'dead'):
        cause = container_log_category(container)
        return component + '_EXITED_' + code + ('_' + cause if cause else '')
    if timeout:
        return component + '_READINESS_TIMEOUT_' + state.upper()
    return None


def wait_json(url, *, token=None, attempts=150, interval=4, state_probe=None):
    for _ in range(attempts):
        try:
            return json_request(url, token=token, timeout=5)
        except (OSError, ValueError, urllib.error.HTTPError):
            if state_probe:
                category = state_probe(False)
                if category:
                    raise DiagnosticError(category)
            time.sleep(interval)
    if state_probe:
        category = state_probe(True)
        if category:
            raise DiagnosticError(category)
    raise TimeoutError('Service readiness timed out')


COMMAND_CATEGORIES = frozenset({
    'DOCKER_NETWORK_INSPECT_FAILED', 'KIND_CREATE_FAILED', 'KIND_RESOURCE_LIMIT_FAILED',
    'KIND_GATEWAY_INSPECT_FAILED', 'LLM_NETWORK_CREATE_FAILED', 'VLLM_START_FAILED',
    'LITELLM_START_FAILED', 'UTER_PREPARE_FAILED', 'UTER_CHECK_FAILED',
    'UTER_INSTALL_FAILED',
})


def call(argv, *, env=None, failure):
    if failure not in COMMAND_CATEGORIES:
        raise ValueError('Invalid diagnostic category')
    result = subprocess.run([str(x) for x in argv], env=env, capture_output=True)
    if result.returncode:
        raise DiagnosticError(failure)
    return result.stdout


def ci_only():
    if (os.name != 'posix' or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or not re.fullmatch(r'[0-9]+', os.environ.get('GITHUB_RUN_ID', ''))
            or os.geteuid() != 0 or os.environ.get('DOCKER_HOST')):
        raise RuntimeError('Disposable GitHub Actions Linux runner required')


def main():
    ci_only()
    root = Path(os.environ['TEST_WORKSPACE']).resolve(strict=True)
    backend = os.environ.get('BACKEND')
    preflight_resources(backend, *read_host_resources(root))
    print('Preflight: CPU flags, available memory and free disk passed', flush=True)
    bundle = root / 'signed'
    inputs = root / 'published'
    python = root / 'venv/bin/python'
    if not (bundle / 'manifest.json').is_file() or not (inputs / 'images.json').is_file():
        raise ValueError('Verified published release inputs required')
    suffix = uuid.uuid4().hex[:12]
    name = 'uter-vllm-' + suffix
    network = name + '-llm'
    vllm = name + '-vllm'
    proxy = name + '-proxy'
    home = root / name
    env = os.environ.copy()
    for key in list(env):
        if key.startswith('COMPOSE_') or key == 'DOCKER_HOST':
            del env[key]
    tmp = Path(tempfile.mkdtemp(prefix='uter-llm-ci-', dir=root))
    os.chmod(tmp, 0o700)
    key = 'sk-' + secrets.token_hex(32)
    keyfile = tmp / 'key'
    keyfile.write_text(key + '\n', encoding='utf-8'); os.chmod(keyfile, 0o600)
    envfile = tmp / 'env'
    envfile.write_text('LITELLM_MASTER_KEY=' + key + '\n', encoding='utf-8'); os.chmod(envfile, 0o600)
    config = tmp / 'litellm.yaml'
    config.write_text(proxy_config(), encoding='utf-8')
    os.chmod(config, 0o644)
    cache = tmp / 'hf'; cache.mkdir(mode=0o700)
    compose = None
    forward = None
    cluster = name + '-kind'
    try:
        if backend == 'kubernetes':
            print('Stage: isolated kind cluster', flush=True)
            call(['kind', 'create', 'cluster', '--name', cluster, '--image', KIND_IMAGE, '--wait', '180s'], failure='KIND_CREATE_FAILED')
            call(kind_resource_limit_command(cluster), failure='KIND_RESOURCE_LIMIT_FAILED')
            gateway_info = json.loads(call(['docker', 'inspect', cluster + '-control-plane'], failure='KIND_GATEWAY_INSPECT_FAILED'))
        else:
            gateway_info = json.loads(call(['docker', 'network', 'inspect', 'bridge'], failure='DOCKER_NETWORK_INSPECT_FAILED'))
        gateway = docker_gateway(backend, gateway_info)
        print('Stage: isolated CPU vLLM', flush=True)
        call(['docker', 'network', 'create', network], failure='LLM_NETWORK_CREATE_FAILED')
        call(['docker', 'run', '-d', '--name', vllm, '--network', network, '--network-alias', 'vllm',
              '--memory', '6g', '--cpus', '2', '--shm-size', '2g', '--cap-drop', 'ALL',
              '--security-opt', 'no-new-privileges', '-p', f'127.0.0.1:{VLLM_PORT}:8000',
              '-v', f'{cache}:/root/.cache/huggingface', '-e', 'VLLM_CPU_KVCACHE_SPACE=1',
              VLLM_IMAGE, '--model', MODEL, '--revision', MODEL_REVISION,
              '--tokenizer-revision', MODEL_REVISION, '--dtype', 'float32',
              '--max-model-len', '2048', '--max-num-seqs', '1'], failure='VLLM_START_FAILED')
        vllm_url = f'http://127.0.0.1:{VLLM_PORT}'
        models = wait_json(vllm_url + '/v1/models', attempts=225,
                           state_probe=lambda timeout: container_state_category(vllm, 'VLLM', timeout=timeout))
        if not any(x.get('id') == MODEL for x in models.get('data', [])):
            raise ValueError('Expected pinned vLLM model missing')
        completion(vllm_url, MODEL)
        print('Stage: isolated LiteLLM proxy', flush=True)
        call(['docker', 'run', '-d', '--name', proxy, '--network', network,
              '--memory', '2g', '--cpus', '1', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
              '-p', f'{gateway}:{PROXY_PORT}:4000', '--env-file', envfile,
              '-v', f'{config}:/app/uter-ci.yaml:ro', LITELLM_IMAGE, '--config', '/app/uter-ci.yaml', '--num_workers', '1'], failure='LITELLM_START_FAILED')
        proxy_url = f'http://{gateway}:{PROXY_PORT}'
        wait_json(proxy_url + '/v1/models', token=key,
                  state_probe=lambda timeout: container_state_category(proxy, 'LITELLM', timeout=timeout))
        completion(proxy_url, MODEL_ALIAS, token=key)
        print('Stage: public Uter ' + backend + ' installation', flush=True)
        installer = bundle / 'scripts/install.py'
        prepare = [python, installer, 'prepare', '--home', home, '--backend', backend, '--name', name,
                   '--inputs', inputs, '--llm-url', proxy_url + '/v1', '--llm-model', MODEL_ALIAS,
                   '--llm-key-file', keyfile, '--allow-http-llm', '--port', str(UTER_PORT), '--guardrail-cpus', '2']
        if backend == 'kubernetes':
            prepare += ['--context', 'kind-' + cluster]
        call(prepare, failure='UTER_PREPARE_FAILED')
        cfg = json.loads((home / 'install.json').read_text())
        if backend == 'compose':
            env.update({k.upper() + '_IMAGE': v for k, v in cfg['images'].items()})
            env.update(RUNTIME_DIR=(home / 'runtime').as_posix(), GUARDRAIL_PORT=str(UTER_PORT), GUARDRAIL_CPUS='2')
            compose = ['docker', '--context', 'default', 'compose', '--project-name', name,
                       '--env-file', str(home / 'empty.env'), '-f', str(home / 'compose/compose.yaml')]
        call([python, installer, 'check', '--home', home], failure='UTER_CHECK_FAILED')
        call([python, installer, 'install', '--home', home], failure='UTER_INSTALL_FAILED')
        if backend == 'kubernetes':
            forward = subprocess.Popen(['kubectl', '--context', 'kind-' + cluster, '-n', name,
                                        'port-forward', 'service/' + name + '-guardrail',
                                        str(UTER_PORT) + ':8000', '--address', '127.0.0.1'],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        base = f'http://127.0.0.1:{UTER_PORT}'
        wait_json(base + '/ready', attempts=45)
        credentials = json.loads((home / 'credentials.json').read_text())
        auth = json_request(base + '/auth/token', {'username': 'admin', 'password': credentials['admin']}, form=True)
        with urllib.request.urlopen(vllm_url + '/metrics', timeout=15) as response:
            before = metric_total(response.read().decode())
        completion(base, 'uter-guardrail-chat', token=auth['access_token'],
                   extra_headers={'X-Uter-Ingress-Secret': credentials['openai_ingress_key']})
        with urllib.request.urlopen(vllm_url + '/metrics', timeout=15) as response:
            after = metric_total(response.read().decode())
        if after <= before:
            raise ValueError('Uter request did not produce new vLLM generation tokens')
        print(json.dumps({'vllm_direct':'pass','litellm_direct':'pass','uter_chat':'pass',
                          'vllm_tokens_increased_after_uter':'pass','model_revision':MODEL_REVISION,
                          'backend':backend,'isolation':'disposable GitHub-hosted runner'}))
    finally:
        if forward:
            forward.terminate()
            try:
                forward.wait(timeout=10)
            except subprocess.TimeoutExpired:
                forward.kill()
                forward.wait()
        if compose:
            subprocess.run(compose + ['down', '--volumes', '--remove-orphans'], env=env, capture_output=True)
        if backend == 'kubernetes':
            subprocess.run(['kind', 'delete', 'cluster', '--name', cluster], capture_output=True)
        for container in (proxy, vllm):
            subprocess.run(['docker', 'rm', '-f', container], capture_output=True)
        subprocess.run(['docker', 'network', 'rm', network], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        category = (exc.category if isinstance(exc, DiagnosticError) else
                    'SERVICE_READINESS_TIMEOUT' if isinstance(exc, TimeoutError) else
                    'NETWORK_OR_HTTP_FAILURE' if isinstance(exc, (urllib.error.URLError, OSError)) else
                    'ISOLATED_COMMAND_FAILED' if isinstance(exc, RuntimeError) else
                    'VALIDATION_FAILED')
        print('Isolated inference test failed: ' + category + '; raw details withheld', file=sys.stderr)
        sys.exit(1)
