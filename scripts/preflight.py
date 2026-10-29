#!/usr/bin/env python3
"""Read-only host preflight for a deployment and its external LiteLLM endpoint.

It does not start a container or Pod and cannot establish what those workloads
will see. A real, small completion is sent to the supplied endpoint. Its response
and all credentials are deliberately omitted from the report.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
from urllib import error, parse, request

sys.dont_write_bytecode = True

MAX_RESPONSE = 65536
MAX_KEY = 8192


class CheckFailure(Exception):
    """An allowlisted diagnostic code, never untrusted error text."""


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_url(value, allow_http=False):
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise CheckFailure('URL_INVALID')
    try:
        url = parse.urlsplit(value)
        port = url.port
    except ValueError:
        raise CheckFailure('URL_INVALID') from None
    if (url.scheme not in ('https', 'http') or not url.hostname or url.username is not None
            or url.password is not None or url.query or url.fragment or port == 0):
        raise CheckFailure('URL_INVALID')
    if url.scheme == 'http' and not allow_http:
        raise CheckFailure('HTTP_NOT_ALLOWED')
    return url


def same_origin(left, right):
    def effective_port(url):
        return url.port or (443 if url.scheme == 'https' else 80)
    return (left.scheme, left.hostname, effective_port(left)) == (
        right.scheme, right.hostname, effective_port(right))


def read_key(path):
    """Reject links, non-files, oversized files and group/world-readable keys."""
    try:
        if Path(path).is_symlink():
            raise CheckFailure('KEY_FILE_INVALID')
        # O_NOFOLLOW protects the final path component where supported.
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise CheckFailure('KEY_FILE_INVALID')
            if os.name == 'posix' and (info.st_mode & 0o077):
                raise CheckFailure('KEY_FILE_PERMISSIONS')
            data = source.read(MAX_KEY + 1)
        if len(data) > MAX_KEY:
            raise CheckFailure('KEY_FILE_INVALID')
        key = data.decode('utf-8').rstrip('\r\n')
        # http.client encodes headers as latin-1. Constrain credentials to
        # printable ASCII so encoding failures never expose their contents.
        if any(not 32 <= ord(c) <= 126 for c in key):
            raise CheckFailure('KEY_FILE_INVALID')
        return key
    except CheckFailure:
        raise
    except (OSError, UnicodeError):
        raise CheckFailure('KEY_FILE_UNREADABLE') from None


def resource_snapshot(path):
    try:
        cpu = len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else os.cpu_count()
    except OSError:
        cpu = os.cpu_count()
    memory = None
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemAvailable:'):
                memory = int(line.split()[1]) * 1024
                break
    except (OSError, ValueError, IndexError):
        pass
    try:
        disk = shutil.disk_usage(path).free
    except OSError:
        disk = None
    return {'cpu_visible': cpu, 'memory_available_bytes': memory, 'disk_free_bytes': disk,
            'scope': 'operator_host_only', 'reservation_or_sizing_guarantee': False}


def run_command(args, timeout=15):
    """Never propagate command output, which may contain sensitive material."""
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout, check=False,
                                text=True, encoding='utf-8', errors='replace')
        return result.returncode, result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, ''


def runtime_checks(backend, context):
    checks = []
    def add(name, status, code):
        checks.append({'name': name, 'status': status, 'code': code})
    if backend == 'compose':
        if not shutil.which('docker'):
            add('docker', 'fail', 'DOCKER_NOT_FOUND')
            return checks
        rc, output = run_command(['docker', 'compose', 'version', '--short'])
        version = re.match(r'^v?(\d+)\.(\d+)(?:\.|$)', output.strip()) if rc == 0 else None
        if not version:
            add('compose_cli', 'fail', 'COMPOSE_VERSION_UNAVAILABLE')
        elif (int(version.group(1)), int(version.group(2))) < (2, 30):
            add('compose_cli', 'fail', 'COMPOSE_VERSION_UNSUPPORTED')
        else:
            add('compose_cli', 'pass', 'COMPOSE_VERSION_SUPPORTED')
        if os.environ.get('DOCKER_HOST'):
            add('docker_context', 'fail', 'DOCKER_HOST_UNSUPPORTED')
            return checks
        rc, output = run_command(['docker', 'context', 'inspect', 'default'])
        try:
            host = json.loads(output)[0]['Endpoints']['docker']['Host'] if rc == 0 else ''
        except (ValueError, KeyError, IndexError, TypeError):
            host = ''
        if not host.startswith('unix://'):
            add('docker_context', 'fail', 'LOCAL_DEFAULT_UNIX_CONTEXT_REQUIRED')
            return checks
        add('docker_context', 'pass', 'LOCAL_DEFAULT_UNIX_CONTEXT')
        rc, _ = run_command(['docker', '--context', 'default', 'info', '--format', '{{.ServerVersion}}'])
        add('docker_daemon', 'pass' if rc == 0 else 'fail', 'DOCKER_REACHABLE' if rc == 0 else 'DOCKER_UNAVAILABLE')
    else:
        for name in ('kubectl', 'helm'):
            present = bool(shutil.which(name))
            add(name, 'pass' if present else 'fail', name.upper() + ('_AVAILABLE' if present else '_NOT_FOUND'))
        if not context or context.startswith('-') or any(ord(c) < 32 or ord(c) == 127 for c in context):
            add('kubernetes_context', 'fail', 'EXPLICIT_CONTEXT_REQUIRED')
        elif shutil.which('kubectl'):
            rc, output = run_command(['kubectl', 'config', 'get-contexts', '-o', 'name'])
            if rc != 0 or context not in output.splitlines():
                add('kubernetes_context', 'fail', 'CONTEXT_NOT_FOUND')
            else:
                add('kubernetes_context', 'pass', 'CONTEXT_FOUND')
                rc, _ = run_command(['kubectl', '--context', context, 'get', '--raw=/version'])
                add('kubernetes_api', 'pass' if rc == 0 else 'fail', 'API_REACHABLE' if rc == 0 else 'API_UNAVAILABLE')
        add('kubernetes_permissions_and_nodes', 'warning', 'NOT_CHECKED')
    return checks


def opener(ca_file, use_env_proxy):
    try:
        tls = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    except (OSError, ssl.SSLError, ValueError):
        raise CheckFailure('CA_FILE_INVALID') from None
    proxy = request.ProxyHandler() if use_env_proxy else request.ProxyHandler({})
    return request.build_opener(proxy, NoRedirect(), request.HTTPSHandler(context=tls))


def json_call(client, url, key, timeout, payload=None):
    headers = {'Accept': 'application/json'}
    if key:
        headers['Authorization'] = 'Bearer ' + key
    data = None
    if payload is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(payload).encode('utf-8')
    req = request.Request(url, data=data, headers=headers)
    started = time.monotonic()
    try:
        with client.open(req, timeout=timeout) as response:
            if response.status != 200:
                raise CheckFailure('HTTP_UNEXPECTED_STATUS')
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise CheckFailure('RESPONSE_TOO_LARGE')
            try:
                body = json.loads(raw)
            except (ValueError, UnicodeError):
                raise CheckFailure('RESPONSE_INVALID') from None
        return body, round(time.monotonic() - started, 3)
    except error.HTTPError as exc:
        # Do not read/print the error body or the redirect location.
        exc.close()
        if 300 <= exc.code < 400:
            raise CheckFailure('REDIRECT_BLOCKED') from None
        if exc.code in (400, 401, 403, 404, 408, 409, 422, 429, 500, 502, 503, 504):
            raise CheckFailure('HTTP_' + str(exc.code)) from None
        raise CheckFailure('HTTP_OTHER') from None
    except ssl.SSLError:
        raise CheckFailure('TLS_FAILED') from None
    except error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLError):
            raise CheckFailure('TLS_FAILED') from None
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            raise CheckFailure('NETWORK_TIMEOUT') from None
        raise CheckFailure('NETWORK_FAILED') from None
    except (TimeoutError, socket.timeout):
        raise CheckFailure('NETWORK_TIMEOUT') from None
    except (OSError, ValueError):
        raise CheckFailure('NETWORK_FAILED') from None


def probe_llm(base, health, model, key, timeout, ca_file=None, use_env_proxy=False):
    client = opener(ca_file, use_env_proxy)
    checks = []
    try:
        health_body, elapsed = json_call(client, health, key, timeout)
        if isinstance(health_body, dict) and health_body.get('healthy_count') == 0:
            checks.append({'name': 'litellm_health', 'status': 'fail', 'code': 'NO_HEALTHY_BACKENDS', 'elapsed_seconds': elapsed})
        else:
            # A 200 or a nonempty aggregate is not proof that the chosen alias
            # is healthy or fresh. The actual completion below checks that alias.
            checks.append({'name': 'litellm_health', 'status': 'warning', 'code': 'HTTP_200_HEALTH_SEMANTICS_UNVERIFIED', 'elapsed_seconds': elapsed})
    except CheckFailure as exc:
        checks.append({'name': 'litellm_health', 'status': 'fail', 'code': str(exc)})
    try:
        body, elapsed = json_call(client, base.rstrip('/') + '/chat/completions', key, timeout,
                                  {'model': model, 'messages': [{'role': 'user', 'content': 'Reply with OK.'}],
                                   'max_tokens': 4, 'temperature': 0})
        choices = body.get('choices') if isinstance(body, dict) else None
        message = choices[0].get('message') if isinstance(choices, list) and choices and isinstance(choices[0], dict) else None
        if not isinstance(message, dict) or not isinstance(message.get('content'), str) or not message['content'].strip():
            raise CheckFailure('COMPLETION_INVALID')
        checks.append({'name': 'litellm_completion', 'status': 'pass', 'code': 'COMPLETION_RECEIVED', 'elapsed_seconds': elapsed})
    except CheckFailure as exc:
        checks.append({'name': 'litellm_completion', 'status': 'fail', 'code': str(exc)})
    return checks


def preflight(args):
    url = check_url(args.llm_url, args.allow_http_llm)
    if not args.llm_model or any(ord(c) < 32 or ord(c) == 127 for c in args.llm_model):
        raise CheckFailure('MODEL_INVALID')
    health = args.health_url or parse.urlunsplit((url.scheme, url.netloc, '/health', '', ''))
    parsed_health = check_url(health, args.allow_http_llm)
    if not same_origin(url, parsed_health):
        raise CheckFailure('HEALTH_ORIGIN_MISMATCH')
    if not 1 <= args.timeout <= 120:
        raise CheckFailure('TIMEOUT_INVALID')
    key = read_key(args.llm_key_file)
    checks = runtime_checks(args.backend, args.context)
    if url.scheme == 'http':
        checks.append({'name': 'transport', 'status': 'warning', 'code': 'HTTP_TRANSPORT_UNENCRYPTED'})
    if args.use_env_proxy:
        # A configured proxy may resolve the destination itself.
        checks.append({'name': 'host_dns', 'status': 'warning', 'code': 'DNS_NOT_CHECKED_FOR_PROXY'})
    else:
        try:
            socket.getaddrinfo(url.hostname, url.port or (443 if url.scheme == 'https' else 80), type=socket.SOCK_STREAM)
            checks.append({'name': 'host_dns', 'status': 'pass', 'code': 'DNS_RESOLVED'})
        except (OSError, UnicodeError):
            checks.append({'name': 'host_dns', 'status': 'fail', 'code': 'DNS_FAILED'})
    checks.extend(probe_llm(args.llm_url, health, args.llm_model, key, args.timeout, args.ca_file, args.use_env_proxy))
    return {'scope': 'operator_host_only',
            'container_or_pod_network_and_trust': 'not_checked',
            'registry_access': 'not_checked', 'cluster_storage_cni_and_rbac': 'not_checked',
            'health_url_selection': 'caller_specified' if args.health_url else 'root_health_assumption',
            'proxy_policy': 'environment' if args.use_env_proxy else 'disabled',
            'models_and_credentials_not_printed': True, 'real_completion_attempted': True,
            'resources': resource_snapshot(args.workdir), 'checks': checks,
            'result': 'fail' if any(c['status'] == 'fail' for c in checks) else 'pass_with_unchecked_items'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=('compose', 'kubernetes'), required=True)
    parser.add_argument('--context', help='Explicit Kubernetes context; never changes the current context')
    parser.add_argument('--llm-url', required=True, help='OpenAI-compatible base URL without credentials')
    parser.add_argument('--llm-model', required=True, help='LiteLLM model alias')
    parser.add_argument('--llm-key-file', required=True, type=Path, help='Private key file, may be empty')
    parser.add_argument('--health-url', help='Same-origin health URL, defaults to /health on the base origin')
    parser.add_argument('--ca-file', type=Path, help='CA bundle for this host-only check; does not configure Uter')
    parser.add_argument('--allow-http-llm', action='store_true', help='Permit HTTP only on a trusted test network')
    parser.add_argument('--use-env-proxy', action='store_true', help='Explicitly use proxy environment variables')
    parser.add_argument('--workdir', type=Path, default=Path.cwd(), help='Host path whose available disk space is reported')
    parser.add_argument('--timeout', type=int, default=30, help='Per-request timeout in seconds, 1..120')
    args = parser.parse_args(argv)
    try:
        result = preflight(args)
    except CheckFailure as exc:
        result = {'scope': 'operator_host_only', 'container_or_pod_network_and_trust': 'not_checked',
                  'result': 'fail', 'checks': [{'name': 'configuration', 'status': 'fail', 'code': str(exc)}]}
    print(json.dumps(result, indent=2))
    return 1 if result['result'] == 'fail' else 0


if __name__ == '__main__':
    sys.exit(main())
