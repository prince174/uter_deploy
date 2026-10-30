"""Experimental bounded loopback exec transport; not an update command.

The caller must authenticate the running workload and keep its identity stable.
This module does not perform inventory, mutation authorization or fencing.
"""
import json
import os
import re
import selectors
import signal
import subprocess
import time

from scripts import kubernetes_sealed_config, kubernetes_trusted_kubectl


class TransportError(ValueError):
    pass


# Fixed program: credentials are read inside the selected workload and never
# supplied in argv, the host environment, stdout or a shell command.
_CLIENT = '''import json,os,sys
from pathlib import Path
import httpx
with Path(os.environ["UTER_MAINTENANCE_KEY_FILE"]).open("rb") as source:
    raw=source.read(4097)
if len(raw)>4096:raise ValueError()
key=raw.decode("utf-8").strip()
if len(key)<32:raise ValueError()
with httpx.Client(trust_env=False,timeout=5) as client:
    with client.stream(sys.argv[1],"http://127.0.0.1:"+sys.argv[2]+"/internal/maintenance",headers={"X-Uter-Maintenance-Key":key,"Accept-Encoding":"identity"}) as response:
        if response.headers.get("content-encoding", "identity").lower() not in ("", "identity"):raise ValueError()
        body=bytearray()
        for chunk in response.iter_raw(chunk_size=4096):
            body.extend(chunk)
            if len(body)>16384:raise ValueError()
        print(json.dumps({"status":response.status_code,"body":bytes(body).decode("utf-8")}))
'''


def _run(command, *, fds=(), timeout=8):
    if os.name != 'posix':
        raise TransportError('MAINTENANCE_TRANSPORT_UNAVAILABLE')
    process = None
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=dict(kubernetes_trusted_kubectl.ENV),
                                   pass_fds=fds, start_new_session=True, bufsize=0)
        selector = selectors.DefaultSelector()
        output = bytearray()
        deadline = time.monotonic() + timeout
        try:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                ready = selector.select(min(remaining, .2))
                if not ready:
                    continue
                chunk = os.read(process.stdout.fileno(), 32769-len(output))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > 32768:
                    raise ValueError
            while not os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                if time.monotonic() >= deadline:
                    raise TimeoutError
                time.sleep(.02)
            # Reap only after signalling the group: the unreaped leader pins
            # its PID, so it cannot be reused for an unrelated process group.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.wait(timeout=max(.001, deadline-time.monotonic())) != 0:
                raise ValueError
            return bytes(output)
        finally:
            selector.close()
    finally:
        if process is not None:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            if process.stdout is not None:
                process.stdout.close()


def _response(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    if (not isinstance(value, dict) or set(value) != {'status', 'body'}
            or type(value['status']) is not int or not 100 <= value['status'] <= 599
            or not isinstance(value['body'], str) or len(value['body'].encode()) > 16384):
        raise ValueError
    return value['status'], value['body'].encode()


def request(*, service, method, identity_guard, container_id=None, session=None, pod=None):
    """Request one exact container; only HTTP loopback is implemented.

    The guard must authenticate the current container/Pod UID and complete
    inventory before and after every call. Kubernetes requires a previously
    bound session with pinned binary and sealed kubeconfig descriptors.
    """
    try:
        if service not in ('agent', 'guardrail') or method not in ('GET', 'POST'):
            raise ValueError
        port = '8001' if service == 'agent' else '8000'
        if identity_guard() is not True:
            raise ValueError
        if session is None:
            if pod is not None or not isinstance(container_id, str) or not re.fullmatch(r'[0-9a-f]{64}', container_id):
                raise ValueError
            command = ['/usr/bin/docker', '--context', 'default', 'exec', container_id]
            fds = ()
        else:
            if (container_id is not None or session._executor is None or session._record['schema'] != 2
                    or not isinstance(pod, str) or not re.fullmatch(re.escape(session.site)+r'-'+service+r'-[a-z0-9-]{1,64}', pod)):
                raise ValueError
            session._scope()
            api = session._inner.api
            binary, config = api.binary_fd, session._inner.config_fd
            kubernetes_trusted_kubectl.verify(binary, session._record['kubectl_sha256'])
            kubernetes_sealed_config.verify_sealed(config, session.config_sha256)
            command = ['/proc/self/fd/'+str(binary), '--kubeconfig=/proc/self/fd/'+str(config),
                       '--context='+api.context, '--namespace='+session.site, '--request-timeout=7s',
                       'exec', 'pod/'+pod, '-c', service, '--']
            fds = (binary, config)
        result = _run(command+['python', '-c', _CLIENT, method, port], fds=fds)
        if session is not None:
            session._scope()
        if identity_guard() is not True:
            raise ValueError
        return _response(result)
    except TimeoutError:
        raise
    except Exception:
        # The caller must treat POST failure as unknown, never as success.
        raise TransportError('MAINTENANCE_TRANSPORT_UNVERIFIED') from None
