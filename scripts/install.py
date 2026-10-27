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
import subprocess
import sys
import tomllib
from urllib.parse import urlsplit

import bcrypt
import yaml

ROOT = Path(__file__).resolve().parents[1]
IMAGE = re.compile(r'[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}\Z')
NAME = re.compile(r'[a-z][a-z0-9-]{0,38}[a-z0-9]\Z')


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('x', encoding='utf-8', newline='\n') as f:
        os.chmod(path, 0o600)
        f.write(value)


def scalar(value):
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Empty values and control characters are not allowed')
    return value


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
    scalar(args.llm_model)
    if api_key:
        scalar(api_key)
    if not 1024 <= args.port <= 65535:
        raise ValueError('Port must be 1024..65535')
    cpus = getattr(args, 'guardrail_cpus', 4)
    if not 1 <= cpus <= 64:
        raise ValueError('Guardrail CPU limit must be 1..64')
    policy = args.policy.read_text(encoding='utf-8')
    profiles = args.profiles.read_text(encoding='utf-8')
    tomllib.loads(policy)
    tomllib.loads(profiles)
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
    judge_url = getattr(args, 'judge_url', None)
    guard['JUDGE_ENABLED'] = 'true' if judge_url else 'false'
    if judge_url:
        scalar(judge_url)
        if urlsplit(judge_url).scheme not in ('http', 'https'):
            raise ValueError('Judge URL must be HTTP(S)')
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
        resource('ConfigMap', args.name + '-policies', data={'runtime.toml': policy})
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


def install(home, cfg):
    if os.name != 'posix':
        raise ValueError('Install is supported on Linux; prepare/check can run elsewhere')
    if (home / 'install-state.json').exists():
        raise ValueError('Install already attempted; preserve secrets/data and diagnose. Use uterctl for managed updates.')
    check(home, cfg)
    cmd, env = commands(home, cfg)
    name = cfg['name']
    if cfg['backend'] == 'compose':
        if os.geteuid() != 0:
            raise ValueError('Compose install requires root for container-readable bind mount ownership')
        if cfg['context'] != 'default':
            raise ValueError('Compose install supports the local default Docker context only (bind mounts)')
        endpoint = json.loads(run(['docker', 'context', 'inspect', 'default']))[0]['Endpoints']['docker']['Host']
        if not endpoint.startswith('unix://') or os.environ.get('DOCKER_HOST'):
            raise ValueError('A local Unix Docker socket without DOCKER_HOST is required')
        for kind in ('container', 'volume', 'network'):
            if run(['docker', '--context', 'default', kind, 'ls', '-q', '--filter', f'label=com.docker.compose.project={name}']).strip():
                raise ValueError('Compose project already exists; select a new name, do not overwrite an existing stand')
        runtime = home / 'runtime'
        for folder in ('policies', 'profiles', 'models'):
            os.chmod(runtime / folder, 0o755)
        for path in (runtime / 'policies/runtime.toml', runtime / 'profiles/model_profiles.toml', runtime / 'audit-hmac-key'):
            os.chown(path, 10001, 10001)
            os.chmod(path, 0o400)
        for filename in ('redis.conf', 'redis-password'):
            os.chown(runtime / filename, 999, 10001)
            os.chmod(runtime / filename, 0o440)
        save(home / 'install-state.json', '{"status":"pending"}\n')
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
    p.add_argument('--policy', type=Path)
    p.add_argument('--profiles', type=Path)
    p.add_argument('--llm-url')
    p.add_argument('--llm-model')
    p.add_argument('--llm-key-file', type=Path)
    p.add_argument('--allow-http-llm', action='store_true')
    p.add_argument('--port', type=int, default=18000)
    p.add_argument('--guardrail-cpus', type=float, default=4, help='Compose CPU limit; use 2 for a small isolated test host')
    p.add_argument('--judge-url', help='Optional Ollama judge endpoint; without this the separate LLM judge is disabled')
    p.add_argument('--judge-model', default='qwen2.5:7b')
    p.add_argument('--storage-class', default='')
    p.add_argument('--registry-config', type=Path, help='Dedicated Docker auth config.json for Kubernetes image pulls')
    args = p.parse_args()
    try:
        if args.command == 'prepare':
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
            (check if args.command == 'check' else install)(home, cfg)
            print('Configuration checked (no workloads started).' if args.command == 'check' else 'Services ready. Run runtime acceptance before opening access.')
    except (ValueError, RuntimeError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
