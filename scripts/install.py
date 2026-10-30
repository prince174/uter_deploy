#!/usr/bin/env python3
"""First-install instance wizard. Never upgrades an existing installation."""
import argparse
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tomllib
from urllib.parse import urlsplit

import bcrypt
import yaml
from cryptography import x509

ROOT = Path(__file__).resolve().parents[1]
IMAGE = re.compile(r'[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}\Z')
NAME = re.compile(r'[a-z][a-z0-9-]{0,38}[a-z0-9]\Z')
CA_FILE = 'upstream-ca.pem'
CA_PATH = '/app/policies/' + CA_FILE
CA_LIMIT = 1024 * 1024
PEM_CERT = re.compile(rb'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----')


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('x', encoding='utf-8', newline='\n') as f:
        os.chmod(path, 0o600)
        f.write(value)


def scalar(value):
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Empty values and control characters are not allowed')
    return value


def read_ca_bundle(path):
    """Accept only a bounded PEM certificate bundle, never private keys or extra data."""
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    if os.name == 'posix':
        source_path = Path(path)
        if '..' in source_path.parts:
            raise ValueError('Untrusted LLM CA path')
        source_path = source_path.absolute()
        directory = None
        try:
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
            directory = os.open('/', directory_flags)
            root = os.fstat(directory)
            if root.st_uid != 0 or root.st_mode & 0o022:
                raise ValueError('Untrusted LLM CA path')
            for part in source_path.parts[1:-1]:
                next_directory = os.open(part, directory_flags, dir_fd=directory)
                os.close(directory)
                directory = next_directory
                info = os.fstat(directory)
                sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
                        (info.st_mode & 0o022 and not sticky_root)):
                    raise ValueError('Untrusted LLM CA path')
            fd = os.open(source_path.name, flags, dir_fd=directory)
        finally:
            if directory is not None:
                os.close(directory)
    else:
        # Windows ACLs are not verified here; keep the existing Windows path support.
        fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('LLM CA bundle must be a regular file')
        if os.name == 'posix' and (info.st_uid not in (0, os.geteuid()) or
                                   info.st_mode & 0o022 or info.st_nlink != 1):
            raise ValueError('Untrusted LLM CA file')
        data = source.read(CA_LIMIT + 1)
    if not data or len(data) > CA_LIMIT or PEM_CERT.sub(b'', data).strip():
        raise ValueError('LLM CA bundle must contain only PEM certificates and be at most 1 MiB')
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError as exc:
        raise ValueError('Invalid PEM certificate in LLM CA bundle') from exc
    if not certs:
        raise ValueError('LLM CA bundle must contain at least one PEM certificate')
    return data.decode('ascii')


def prepare_ca_permissions(runtime):
    """Allow only the Guardrail uid to read an optional restored or prepared CA file."""
    path = Path(runtime) / 'policies' / CA_FILE
    if not path.exists() and not path.is_symlink():
        return
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('LLM CA bundle must be a regular file without hard links')
        os.fchown(fd, 10001, 10001)
        os.fchmod(fd, 0o400)
    finally:
        os.close(fd)


def prepare(args, api_key):
    home = args.home.resolve()
    if home.exists():
        raise ValueError('Destination exists; refusing to replace credentials. Choose a new directory.')
    if not NAME.fullmatch(args.name):
        raise ValueError('Name must contain 2-40 lowercase letters/digits/hyphens and start with a letter')
    images = json.loads(args.images.read_text(encoding='utf-8'))
    if set(images) != {'guardrail', 'agent', 'redis'} or any(not IMAGE.fullmatch(v) for v in images.values()):
        raise ValueError('images JSON must contain guardrail, agent, redis immutable registry@sha256 references')
    url = urlsplit(scalar(args.llm_url))
    if url.scheme not in ('https', 'http') or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('LLM URL must be HTTP(S), without credentials, query or fragment')
    if url.scheme != 'https' and not args.allow_http_llm:
        raise ValueError('HTTP LLM requires --allow-http-llm for a trusted private network')
    ca_path = getattr(args, 'llm_ca_bundle', None)
    if ca_path and url.scheme != 'https':
        raise ValueError('LLM CA bundle requires an HTTPS LLM URL')
    ca_bundle = read_ca_bundle(ca_path) if ca_path else None
    scalar(args.llm_model)
    if api_key:
        scalar(api_key)
    if not 1024 <= args.port <= 65535:
        raise ValueError('Port must be 1024..65535')
    cpus = getattr(args, 'guardrail_cpus', 4)
    if not 1 <= cpus <= 64:
        raise ValueError('Guardrail CPU limit must be 1..64')
    llm_max_tokens = getattr(args, 'llm_max_tokens', None)
    if llm_max_tokens is not None and (type(llm_max_tokens) is not int or not 1 <= llm_max_tokens <= 65536):
        raise ValueError('LLM max tokens must be an integer from 1 to 65536')
    policy = args.policy.read_text(encoding='utf-8')
    profiles = args.profiles.read_text(encoding='utf-8')
    tomllib.loads(policy)
    tomllib.loads(profiles)
    if (args.backend == 'kubernetes' and ca_bundle and
            len(policy.encode('utf-8')) + len(ca_bundle.encode('ascii')) + len('runtime.toml') + len(CA_FILE) > CA_LIMIT):
        raise ValueError('Combined policy and LLM CA bundle exceed the Kubernetes ConfigMap size limit')
    if args.backend == 'kubernetes' and not args.context:
        raise ValueError('An explicit --context is required for Kubernetes')
    dockerconfig = None
    if args.registry_config:
        dockerconfig = args.registry_config.read_text(encoding='utf-8')
        auths = json.loads(dockerconfig).get('auths', {})
        if not auths or not all(isinstance(v, dict) and (v.get('auth') or v.get('identitytoken')) for v in auths.values()):
            raise ValueError('Registry config requires inline credentials; credential helpers cannot run in Kubernetes')
    passwords = {name: secrets.token_hex(24) for name in ('admin', 'user', 'service')}
    guard = {name.upper() + '_PASSWORD_HASH': bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
             for name, pw in passwords.items()}
    guard.update(JWT_SECRET=secrets.token_hex(32), AGENT_INTERNAL_SHARED_SECRET=secrets.token_hex(32),
                 OPENAI_INGRESS_SHARED_SECRET=secrets.token_hex(32), UPSTREAM_MODE='litellm_openai',
                 UPSTREAM_URL=args.llm_url.rstrip('/'), UPSTREAM_OPENAI_MODEL=args.llm_model,
                 UPSTREAM_API_KEY=api_key, AUDIT_LOG_HMAC_KEY=secrets.token_hex(32), TOXICITY_FAIL_CLOSED='true')
    if llm_max_tokens is not None:
        guard['UPSTREAM_OPENAI_MAX_TOKENS'] = str(llm_max_tokens)
    if ca_bundle:
        # Pin OpenSSL's CA file AND directory: leaving the default CA directory
        # would silently retain the platform trust store for some clients.
        guard.update(SSL_CERT_FILE=CA_PATH, SSL_CERT_DIR='/app/policies', REQUESTS_CA_BUNDLE=CA_PATH)
    judge_url = getattr(args, 'judge_url', None)
    guard['JUDGE_ENABLED'] = 'true' if judge_url else 'false'
    if judge_url:
        scalar(judge_url)
        parsed_judge = urlsplit(judge_url)
        if parsed_judge.scheme not in ('http', 'https') or not parsed_judge.hostname or parsed_judge.username or parsed_judge.password:
            raise ValueError('Judge URL must be HTTP(S), without embedded credentials')
        guard.update(JUDGE_OLLAMA_URL=judge_url, JUDGE_MODEL=scalar(args.judge_model), JUDGE_FAIL_CLOSED='true')
    agent = dict(AGENT_INTERNAL_SHARED_SECRET=guard['AGENT_INTERNAL_SHARED_SECRET'],
                 GUARDRAIL_SERVICE_USERNAME='agent-service', GUARDRAIL_SERVICE_PASSWORD=passwords['service'])
    redis = secrets.token_hex(32)
    home.mkdir(parents=True, mode=0o700)
    runtime = home / 'runtime'
    runtime.mkdir(mode=0o700)
    for name, data in [('guardrail', guard), ('agent', agent)]:
        save(runtime / (name + '.env'), ''.join(f'{k}={v}\n' for k, v in data.items()))
    save(runtime / 'redis-password', redis)
    save(runtime / 'audit-hmac-key', guard['AUDIT_LOG_HMAC_KEY'])
    save(runtime / 'redis.conf', (ROOT / 'examples/redis.conf.example').read_text().replace('REPLACE', redis))
    save(runtime / 'policies/runtime.toml', policy)
    if ca_bundle:
        save(runtime / 'policies' / CA_FILE, ca_bundle)
    save(runtime / 'profiles/model_profiles.toml', profiles)
    (runtime / 'models').mkdir(mode=0o755)
    save(home / 'credentials.json', json.dumps({**passwords, 'openai_ingress_key': guard['OPENAI_INGRESS_SHARED_SECRET']}, indent=2))
    save(home / 'empty.env', '')
    # Freeze deployment assets so a git pull cannot silently change a prepared installation.
    shutil.copytree(ROOT / 'compose', home / 'compose')
    shutil.copytree(ROOT / 'charts', home / 'charts')
    config = dict(backend=args.backend, name=args.name, context=args.context or 'default', port=args.port, images=images, guardrail_cpus=cpus)
    save(home / 'install.json', json.dumps(config, indent=2))
    if args.backend == 'kubernetes':
        resources = []
        def resource(kind, name, **body):
            resources.append(dict(apiVersion='v1', kind=kind, metadata=dict(name=name, namespace=args.name), **body))
        resource('Secret', args.name + '-guardrail-env', type='Opaque', stringData=guard)
        resource('Secret', args.name + '-agent-env', type='Opaque', stringData=agent)
        resource('Secret', args.name + '-redis-secret', type='Opaque', stringData={'password': redis})
        policies = {'runtime.toml': policy}
        if ca_bundle:
            policies[CA_FILE] = ca_bundle
        resource('ConfigMap', args.name + '-policies', data=policies)
        resource('ConfigMap', args.name + '-profiles', data={'model_profiles.toml': profiles})
        if dockerconfig:
            resource('Secret', args.name + '-registry', type='kubernetes.io/dockerconfigjson',
                     stringData={'.dockerconfigjson': dockerconfig})
        save(home / 'resources.yaml', yaml.safe_dump_all(resources))
        values = dict(images=images, productVersion='instance', guardrailSecret=args.name + '-guardrail-env',
                      agentSecret=args.name + '-agent-env', redisSecret=args.name + '-redis-secret',
                      policyConfigMap=args.name + '-policies', profileConfigMap=args.name + '-profiles',
                      useEmbeddedModels=True, guardrailEnv={'UPSTREAM_MODE': 'litellm_openai',
                      'UPSTREAM_URL': guard['UPSTREAM_URL'], 'UPSTREAM_OPENAI_MODEL': args.llm_model},
                      storageClass=args.storage_class,
                      imagePullSecrets=[{'name': args.name + '-registry'}] if args.registry_config else [])
        save(home / 'values.yaml', yaml.safe_dump(values))
    return home


def run(command, env=None):
    # Capture output: rendered manifests, kubectl errors and Compose config can contain secrets.
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f'{command[0]} command failed (exit {result.returncode}); output suppressed to protect secrets')
    return result.stdout


def commands(home, cfg):
    if cfg['backend'] == 'compose':
        env = os.environ.copy()
        for key in list(env):
            if key.startswith('COMPOSE_'):
                del env[key]
        env.update({k.upper() + '_IMAGE': v for k, v in cfg['images'].items()})
        env.update(RUNTIME_DIR=(home / 'runtime').as_posix(), GUARDRAIL_PORT=str(cfg['port']))
        env['GUARDRAIL_CPUS'] = str(cfg.get('guardrail_cpus', 4))
        return ['docker', '--context', cfg['context'], 'compose', '--project-name', cfg['name'],
                '--env-file', str(home / 'empty.env'), '-f', str(home / 'compose/compose.yaml')], env
    return ['helm', '--kube-context', cfg['context'], '--namespace', cfg['name']], None


def check(home, cfg):
    cmd, env = commands(home, cfg)
    if cfg['backend'] == 'compose':
        run(cmd + ['config', '--quiet'], env)
    else:
        args = [str(home / 'charts/uter'), '-f', str(home / 'values.yaml')]
        run(cmd + ['lint'] + args)
        run(cmd + ['template', cfg['name']] + args)


def require_local_images(cfg):
    """Reject an offline install unless every exact image reference resolves locally."""
    if not isinstance(cfg.get('images'), dict) or set(cfg['images']) != {'guardrail', 'agent', 'redis'}:
        raise ValueError('Offline install requires exactly guardrail, agent and redis image references')
    for service, ref in cfg['images'].items():
        if not isinstance(ref, str) or not IMAGE.fullmatch(ref):
            raise ValueError('Offline install requires immutable image references')
        raw = run(['docker', '--context', 'default', 'image', 'inspect', ref])
        try:
            images = json.loads(raw)
            if not isinstance(images, list) or len(images) != 1:
                raise ValueError
            image = images[0]
            if not isinstance(image, dict):
                raise ValueError
            digest = ref.rsplit('@', 1)[-1]
            descriptor = image.get('Descriptor') or {}
            repos = image.get('RepoDigests') or []
            if not isinstance(repos, list) or not isinstance(descriptor, dict):
                raise ValueError
            if ref not in repos and not (
                    image.get('Id') == digest and descriptor.get('digest') == digest):
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ValueError(f'Offline image reference not verified locally: {service}') from None


def reject_reserved_compose_names(name):
    """Reject pre-existing names even when they have no Compose project label.

    Docker Compose can reuse a named volume without the expected labels. This
    preflight cannot exclude concurrent administrators racing the installation;
    use a dedicated daemon or coordinate other writers during installation.
    """
    reserved = {
        'container': {f'{name}-{service}-1' for service in ('guardrail', 'agent', 'redis')},
        'network': {name + '_backend', name + '_outbound'},
        'volume': {name + '_redis-data', name + '_audit-data'},
    }
    for kind, names in reserved.items():
        command = ['docker', '--context', 'default', kind, 'ls']
        if kind == 'container':
            command.append('--all')
        output = run(command + ['--format', '{{.Names}}' if kind == 'container' else '{{.Name}}'])
        if names.intersection(output.splitlines()):
            raise ValueError(f'Compose {kind} name already exists; refusing to reuse an existing resource')


def install(home, cfg, *, offline=False):
    if os.name != 'posix':
        raise ValueError('Install is supported on Linux; prepare/check can run elsewhere')
    if os.path.lexists(home/'redis-fence-operation.json') or os.path.lexists(home/'compose-fence-finalize-anchor.json'):
        raise ValueError('REDIS_FENCE_REQUIRES_INSPECTION')
    if (home / 'install-state.json').exists():
        raise ValueError('Install already attempted; preserve secrets/data and diagnose. Use uterctl for managed updates.')
    if offline and cfg['backend'] != 'compose':
        raise ValueError('Offline first install is supported for Compose only; Kubernetes nodes may pull images')
    if offline and (not isinstance(cfg.get('images'), dict) or set(cfg['images']) != {'guardrail', 'agent', 'redis'}):
        raise ValueError('Offline install requires exactly guardrail, agent and redis image references')
    check(home, cfg)
    cmd, env = commands(home, cfg)
    name = cfg['name']
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError('Invalid installation name')
    if cfg['backend'] == 'compose':
        if os.geteuid() != 0:
            raise ValueError('Compose install requires root for container-readable bind mount ownership')
        if cfg['context'] != 'default':
            raise ValueError('Compose install supports the local default Docker context only (bind mounts)')
        endpoint = json.loads(run(['docker', 'context', 'inspect', 'default']))[0]['Endpoints']['docker']['Host']
        if not endpoint.startswith('unix://') or os.environ.get('DOCKER_HOST'):
            raise ValueError('A local Unix Docker socket without DOCKER_HOST is required')
        if offline:
            require_local_images(cfg)
        for kind in ('container', 'volume', 'network'):
            if run(['docker', '--context', 'default', kind, 'ls', '-q', '--filter', f'label=com.docker.compose.project={name}']).strip():
                raise ValueError('Compose project already exists; select a new name, do not overwrite an existing stand')
        reject_reserved_compose_names(name)
        runtime = home / 'runtime'
        for folder in ('policies', 'profiles', 'models'):
            os.chmod(runtime / folder, 0o755)
        for path in (runtime / 'policies/runtime.toml', runtime / 'profiles/model_profiles.toml', runtime / 'audit-hmac-key'):
            os.chown(path, 10001, 10001)
            os.chmod(path, 0o400)
        prepare_ca_permissions(runtime)
        for filename in ('redis.conf', 'redis-password'):
            os.chown(runtime / filename, 999, 10001)
            os.chmod(runtime / filename, 0o440)
        save(home / 'install-state.json', '{"status":"pending"}\n')
        if not offline:
            run(cmd + ['pull'], env)
        run(cmd + ['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '300'], env)
    else:
        kube = ['kubectl', '--context', cfg['context']]
        # A fresh namespace is mandatory: no adoption or mutation of another installation.
        if run(kube + ['get', 'namespace', name, '--ignore-not-found', '-o', 'name']).strip():
            raise ValueError('Namespace already exists; choose a new dedicated namespace')
        run(kube + ['create', 'namespace', name, '--dry-run=server', '-o', 'name'])
        save(home / 'install-state.json', '{"status":"pending"}\n')
        run(kube + ['create', 'namespace', name])
        run(kube + ['-n', name, 'create', '-f', str(home / 'resources.yaml')])
        run(cmd + ['install', name, str(home / 'charts/uter'), '-f', str(home / 'values.yaml'), '--wait', '--timeout', '5m'])
    (home / 'install-state.json').write_text('{"status":"ready","acceptance":"not-run"}\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['prepare', 'check', 'install'])
    p.add_argument('--home', type=Path, required=True)
    p.add_argument('--backend', choices=['compose', 'kubernetes'], default='compose')
    p.add_argument('--name', default='uter-instance')
    p.add_argument('--context')
    p.add_argument('--images', type=Path)
    p.add_argument('--inputs', type=Path, help='Directory with images.json, policy.toml and model_profiles.toml')
    p.add_argument('--policy', type=Path)
    p.add_argument('--profiles', type=Path)
    p.add_argument('--llm-url')
    p.add_argument('--llm-model')
    p.add_argument('--llm-max-tokens', type=int, help='Optional upstream generation token setting, 1..65536')
    p.add_argument('--llm-key-file', type=Path)
    p.add_argument('--llm-ca-bundle', type=Path,
                   help='Complete PEM trust bundle for HTTPS LLM; replaces default trust roots')
    p.add_argument('--allow-http-llm', action='store_true')
    p.add_argument('--port', type=int, default=18000)
    p.add_argument('--guardrail-cpus', type=float, default=4, help='Compose CPU limit; use 2 for a small isolated test host')
    p.add_argument('--judge-url', help='Optional Ollama judge endpoint; without this the separate LLM judge is disabled')
    p.add_argument('--judge-model', default='qwen2.5:7b')
    p.add_argument('--storage-class', default='')
    p.add_argument('--registry-config', type=Path, help='Dedicated Docker auth config.json for Kubernetes image pulls')
    p.add_argument('--offline', action='store_true', help='Compose install only: require local digest images and never pull')
    args = p.parse_args()
    try:
        if args.offline and args.command != 'install':
            raise ValueError('--offline is supported only for the install command')
        if args.command == 'prepare':
            if args.inputs:
                args.images = args.images or args.inputs / 'images.json'
                args.policy = args.policy or args.inputs / 'policy.toml'
                args.profiles = args.profiles or args.inputs / 'model_profiles.toml'
            for field in ('images', 'policy', 'profiles'):
                if getattr(args, field) is None:
                    p.error('--' + field + ' is required for prepare')
            if not sys.stdin.isatty() and (not args.llm_url or not args.llm_model or not args.llm_key_file):
                p.error('Non-interactive prepare requires --llm-url, --llm-model and --llm-key-file (may be empty)')
            args.llm_url = args.llm_url or input('OpenAI-compatible LLM base URL: ').strip()
            args.llm_model = args.llm_model or input('LLM model name: ').strip()
            key = args.llm_key_file.read_text().rstrip('\r\n') if args.llm_key_file else getpass.getpass('LLM API key (empty if not required): ')
            prepare(args, key)
            print('Prepared. Credentials are in credentials.json; keep the entire home private and backed up.')
        else:
            home = args.home.resolve()
            cfg = json.loads((home / 'install.json').read_text())
            if args.command == 'check':
                check(home, cfg)
            else:
                install(home, cfg, offline=args.offline)
            print('Configuration checked (no workloads started).' if args.command == 'check' else 'Services ready. Run runtime acceptance before opening access.')
    except (ValueError, RuntimeError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
