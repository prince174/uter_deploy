#!/usr/bin/env python3
"""Diagnose a pending FIRST installation; never resume or modify workloads.

The installer did not persist a unique ownership marker or cluster identity.
Names and labels alone cannot establish ownership, including when no objects exist.
Runtime inspection is read-only, explicit and does not read Secret resources.
"""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True

NAME = re.compile(r'[a-z][a-z0-9-]{0,38}[a-z0-9]\Z')
IMAGE = re.compile(r'[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}\Z')
MAX_JSON = 65536
MAX_OUTPUT = 1024 * 1024
MAX_LINES = 10000


class DiagnosticError(Exception):
    """Fixed diagnostic category; never include subprocess output or secrets."""


def read_json_file(path):
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise DiagnosticError('LOCAL_FILE_INVALID')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise DiagnosticError('LOCAL_FILE_INVALID')
            raw = source.read(MAX_JSON + 1)
        if len(raw) > MAX_JSON:
            raise DiagnosticError('LOCAL_FILE_TOO_LARGE')
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise DiagnosticError('LOCAL_FILE_INVALID')
        return value
    except DiagnosticError:
        raise
    except (OSError, ValueError, UnicodeError):
        raise DiagnosticError('LOCAL_FILE_UNREADABLE_OR_INVALID') from None


def inspect_local(home, expected_backend, expected_name, expected_context):
    try:
        path = Path(home)
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise DiagnosticError('HOME_INVALID')
        path = path.resolve(strict=True)
    except DiagnosticError:
        raise
    except OSError:
        raise DiagnosticError('HOME_INVALID') from None
    config = read_json_file(path / 'install.json')
    state = read_json_file(path / 'install-state.json')
    if state != {'status': 'pending'}:
        raise DiagnosticError('NOT_FIRST_INSTALL_PENDING')
    backend, name, context = config.get('backend'), config.get('name'), config.get('context')
    if backend not in ('compose', 'kubernetes') or not isinstance(name, str) or not NAME.fullmatch(name):
        raise DiagnosticError('INSTALL_CONFIGURATION_INVALID')
    if (not isinstance(context, str) or not context or context.startswith('-')
            or any(ord(c) < 32 or ord(c) == 127 for c in context)):
        raise DiagnosticError('INSTALL_CONFIGURATION_INVALID')
    if backend == 'compose' and context != 'default':
        raise DiagnosticError('INSTALL_CONFIGURATION_INVALID')
    if (backend, name, context) != (expected_backend, expected_name, expected_context):
        raise DiagnosticError('EXPECTED_IDENTITY_MISMATCH')
    images = config.get('images')
    if (not isinstance(images, dict) or set(images) != {'guardrail', 'agent', 'redis'}
            or any(not isinstance(v, str) or not IMAGE.fullmatch(v) for v in images.values())):
        raise DiagnosticError('INSTALL_CONFIGURATION_INVALID')
    # No runtime env files, credentials, Secret manifests or Helm release state
    # are read. Even matching metadata cannot identify the creator.
    return {'backend': backend, 'name': name, 'context': context,
            'managed_state_exists': (path / 'state.json').exists()}


def run_readonly(command, timeout=15, env=None):
    """Read bounded output without logging stderr or allowing a hung child to persist."""
    if os.name != 'posix':
        raise DiagnosticError('POSIX_RUNTIME_INSPECTION_REQUIRED')
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   bufsize=0, start_new_session=True, env=env)
    except OSError:
        raise DiagnosticError('RUNTIME_QUERY_UNAVAILABLE') from None
    data = bytearray()
    selector = selectors.DefaultSelector()

    def terminate():
        try:
            # The command is placed in a new session; no other workload is in
            # this group. Kill descendants too if they retain the pipe.
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
    try:
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        exited_at = None
        while True:
            now = time.monotonic()
            if now >= deadline:
                raise DiagnosticError('RUNTIME_QUERY_UNAVAILABLE')
            if process.poll() is not None:
                if exited_at is None:
                    exited_at = now
                elif now - exited_at >= 1:
                    # A descendant kept stdout open after its parent exited.
                    raise DiagnosticError('RUNTIME_QUERY_UNAVAILABLE')
            events = selector.select(min(0.1, deadline - now))
            if not events:
                continue
            try:
                chunk = os.read(process.stdout.fileno(), min(65536, MAX_OUTPUT + 1 - len(data)))
            except BlockingIOError:
                continue
            except OSError:
                raise DiagnosticError('RUNTIME_QUERY_UNAVAILABLE') from None
            if not chunk:
                try:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    raise DiagnosticError('RUNTIME_QUERY_UNAVAILABLE') from None
                if process.returncode != 0:
                    raise DiagnosticError('RUNTIME_QUERY_FAILED')
                return data.decode('utf-8', errors='replace')
            data.extend(chunk)
            if len(data) > MAX_OUTPUT:
                raise DiagnosticError('RUNTIME_RESULT_TOO_LARGE')
    except BaseException as exc:
        terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        if isinstance(exc, (OSError, ValueError)):
            raise DiagnosticError('RUNTIME_QUERY_UNAVAILABLE') from None
        raise
    finally:
        selector.close()
        process.stdout.close()


def count_lines(output):
    lines = output.splitlines()
    if len(lines) > MAX_LINES or any(not line or len(line) > 512 for line in lines):
        raise DiagnosticError('RUNTIME_RESULT_INVALID')
    return len(lines)


def inspect_compose(name):
    if os.environ.get('DOCKER_HOST'):
        raise DiagnosticError('DOCKER_HOST_UNSUPPORTED')
    output = run_readonly(['docker', 'context', 'inspect', 'default'])
    try:
        host = json.loads(output)[0]['Endpoints']['docker']['Host']
    except (ValueError, TypeError, KeyError, IndexError):
        raise DiagnosticError('DOCKER_CONTEXT_INVALID') from None
    if not isinstance(host, str) or not host.startswith('unix://'):
        raise DiagnosticError('LOCAL_DEFAULT_UNIX_CONTEXT_REQUIRED')
    counts = {}
    label = 'label=com.docker.compose.project=' + name
    for kind in ('container', 'volume', 'network'):
        command = ['docker', '--context', 'default', kind, 'ls']
        if kind == 'container':
            command.append('--all')
        command += ['--quiet', '--filter', label]
        counts[kind + '_label_matches'] = count_lines(run_readonly(command))
    return counts


def inspect_kubernetes(name, context):
    # Confirm the selected kubeconfig context exists before consulting the API.
    names = run_readonly(['kubectl', 'config', 'get-contexts', '-o', 'name']).splitlines()
    if len(names) > MAX_LINES or context not in names:
        raise DiagnosticError('KUBERNETES_CONTEXT_NOT_FOUND')
    kube = ['kubectl', '--context', context]
    output = run_readonly(kube + ['get', 'namespace', name, '--ignore-not-found', '-o', 'name'])
    namespace = output.splitlines()
    if len(namespace) > 1 or (namespace and namespace[0] != 'namespace/' + name):
        raise DiagnosticError('RUNTIME_RESULT_INVALID')
    if not namespace:
        return {'namespace_present': False, 'partial_label_matches': 0,
                'inventory_is_not_exhaustive': True}
    # These kinds contain no Kubernetes Secrets. The install-created Secret and
    # ConfigMap manifests are intentionally not queried by this diagnostic.
    output = run_readonly(kube + ['-n', name, 'get', 'deployments,services,persistentvolumeclaims,networkpolicies',
                                  '-l', 'app.kubernetes.io/instance=' + name, '-o', 'name'])
    return {'namespace_present': True, 'partial_label_matches': count_lines(output),
            'inventory_is_not_exhaustive': True}


def diagnose(home, expected_backend, expected_name, expected_context, inspect_runtime=False):
    info = inspect_local(home, expected_backend, expected_name, expected_context)
    result = {'state': 'first_install_pending', 'local_identity_matches_expected': True,
              'backend': info['backend'], 'managed_state_exists': info['managed_state_exists'],
              'runtime_inspection': 'not_requested', 'ownership': 'unproven',
              'cluster_or_daemon_identity': 'unproven', 'labels_are_ownership_proof': False,
              'resume': 'not_available', 'result': 'inconclusive',
              'reason': 'INSTALLER_HAS_NO_PERSISTED_OWNERSHIP_IDENTITY'}
    if inspect_runtime:
        result['runtime_inspection'] = 'read_only_partial_snapshot'
        result['observations'] = (inspect_compose(info['name']) if info['backend'] == 'compose'
                                  else inspect_kubernetes(info['name'], info['context']))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--expected-backend', choices=('compose', 'kubernetes'), required=True)
    parser.add_argument('--expected-name', required=True)
    parser.add_argument('--expected-context', required=True)
    parser.add_argument('--inspect-runtime', action='store_true',
                        help='Explicitly query project labels or namespace metadata; no changes')
    args = parser.parse_args(argv)
    try:
        result = diagnose(args.home, args.expected_backend, args.expected_name,
                          args.expected_context, args.inspect_runtime)
    except DiagnosticError as exc:
        result = {'result': 'error', 'code': str(exc), 'resume': 'not_available'}
        print(json.dumps(result, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 2  # inconclusive; never signal that automatic resume is safe


if __name__ == '__main__':
    sys.exit(main())
