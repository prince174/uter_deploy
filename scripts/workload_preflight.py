#!/usr/bin/env python3
"""Probe LiteLLM from a disposable, locally available signed Guardrail image.

The probe uses Python urllib in a new Docker bridge, not the compiled application.
Its network, DNS and trust may differ from the eventual Compose workload. Journals
contain only resource identities, never the LiteLLM key or request/response data.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from urllib import parse

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import uterctl
from scripts import install, preflight

LABEL = 'uter.workload-preflight.id'
ID = re.compile(r'[0-9a-f]{32}\Z')
DAEMON_ID = re.compile(r'[A-Za-z0-9._:-]{1,128}\Z')
FINGERPRINT = re.compile(r'[0-9a-fA-F]{64}\Z')
MAX_REPORT = 8192
MAX_DOCKER_OUTPUT = 1024 * 1024
MAX_BUNDLE_FILES = 1024
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
ALLOWED_RESULT_CODES = frozenset({
    'COMPLETION_RECEIVED', 'INPUT_TOO_LARGE', 'HTTP_UNEXPECTED_STATUS', 'ENCODING_UNSUPPORTED',
    'RESPONSE_TOO_LARGE', 'RESPONSE_INVALID', 'REDIRECT_BLOCKED', 'HTTP_OTHER',
    'NETWORK_OR_TLS_FAILED', 'NO_HEALTHY_BACKENDS', 'COMPLETION_INVALID', 'TOTAL_TIMEOUT',
    'PROBE_FAILED', *('HTTP_'+str(code) for code in (400,401,403,404,408,409,422,429,500,502,503,504)),
})

# This static program receives the complete payload exclusively through stdin.
# It never writes request data, response bodies, headers or credentials to stdout.
CHILD_CODE = r'''import json,signal,ssl,sys
from urllib import error,request
MAX_INPUT=1058000
MAX_RESPONSE=65536
def stop(_signum,_frame):
    raise TimeoutError()
signal.signal(signal.SIGALRM,stop)
signal.alarm(int(sys.argv[1]))
def fail(code):
    print(json.dumps({'result':'fail','code':code}),flush=True)
    sys.exit(1)
class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        return None
try:
    raw=sys.stdin.buffer.read(MAX_INPUT+1)
    if len(raw)>MAX_INPUT:fail('INPUT_TOO_LARGE')
    payload=json.loads(raw)
    signal.alarm(payload['total_timeout'])
    context=ssl.create_default_context(cadata=payload['ca_bundle'] or None)
    client=request.build_opener(request.ProxyHandler({}),NoRedirect(),request.HTTPSHandler(context=context))
    headers={'Accept':'application/json','Accept-Encoding':'identity'}
    if payload['key']:headers['Authorization']='Bearer '+payload['key']
    def call(url,body=None):
        h=dict(headers)
        data=None
        if body is not None:
            h['Content-Type']='application/json'
            data=json.dumps(body).encode()
        req=request.Request(url,data=data,headers=h)
        try:
            with client.open(req,timeout=payload['timeout']) as response:
                if response.status!=200:fail('HTTP_UNEXPECTED_STATUS')
                if response.headers.get('Content-Encoding','identity').lower()!='identity':
                    fail('ENCODING_UNSUPPORTED')
                raw=response.read(MAX_RESPONSE+1)
                if len(raw)>MAX_RESPONSE:fail('RESPONSE_TOO_LARGE')
                try:return json.loads(raw)
                except (ValueError,UnicodeError):fail('RESPONSE_INVALID')
        except error.HTTPError as exc:
            code=exc.code;exc.close()
            if 300<=code<400:fail('REDIRECT_BLOCKED')
            if code in (400,401,403,404,408,409,422,429,500,502,503,504):fail('HTTP_'+str(code))
            fail('HTTP_OTHER')
        except (error.URLError,ssl.SSLError,TimeoutError,OSError):fail('NETWORK_OR_TLS_FAILED')
    health=call(payload['health'])
    if isinstance(health,dict) and health.get('healthy_count')==0:fail('NO_HEALTHY_BACKENDS')
    reply=call(payload['base'].rstrip('/')+'/chat/completions',{
        'model':payload['model'],'messages':[{'role':'user','content':'Reply with OK.'}],
        'max_tokens':4,'temperature':0})
    choices=reply.get('choices') if isinstance(reply,dict) else None
    message=choices[0].get('message') if isinstance(choices,list) and choices and isinstance(choices[0],dict) else None
    if not isinstance(message,dict) or not isinstance(message.get('content'),str) or not message['content'].strip():
        fail('COMPLETION_INVALID')
    print(json.dumps({'result':'pass','code':'COMPLETION_RECEIVED'}),flush=True)
except TimeoutError:fail('TOTAL_TIMEOUT')
except Exception:fail('PROBE_FAILED')
'''


class ProbeError(Exception):
    """Only fixed diagnostic codes may be surfaced to the operator."""


def regular_bytes(path, limit, *, private=False):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or
                    (private and (info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1))):
                raise ProbeError('FILE_INVALID')
            data = source.read(limit+1)
        if len(data) > limit:
            raise ProbeError('FILE_TOO_LARGE')
        return data
    except ProbeError:
        raise
    except OSError:
        raise ProbeError('FILE_UNREADABLE') from None


def read_trusted_file(path, limit, *, secret, error):
    """Read bounded trusted bytes by dirfd without following links or blocking on FIFOs."""
    path = Path(path)
    if '..' in path.parts:
        raise ProbeError(error)
    path = path.absolute()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    directory = None
    try:
        directory = os.open('/', directory_flags)
        root = os.fstat(directory)
        if root.st_uid != 0 or root.st_mode & 0o022:
            raise ProbeError(error)
        for part in path.parts[1:-1]:
            next_directory = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = next_directory
            info = os.fstat(directory)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
                    (info.st_mode & 0o022 and not sticky_root)):
                raise ProbeError(error)
        fd = os.open(path.name, file_flags, dir_fd=directory)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
                    info.st_nlink != 1 or (stat.S_IMODE(info.st_mode) != 0o600 if secret else info.st_mode & 0o022)):
                raise ProbeError(error)
            data = source.read(limit + 1)
        if len(data) > limit:
            raise ProbeError(error)
        return data
    except OSError:
        raise ProbeError(error) from None
    finally:
        if directory is not None:
            os.close(directory)


def read_trusted_key(path):
    data = read_trusted_file(path, preflight.MAX_KEY, secret=True, error='KEY_FILE_INVALID')
    try:
        key = data.decode('utf-8').rstrip('\r\n')
        if any(not 32 <= ord(c) <= 126 for c in key):
            raise ProbeError('KEY_FILE_INVALID')
        return key
    except UnicodeError:
        raise ProbeError('KEY_FILE_INVALID') from None


def read_trusted_ca(path):
    data = read_trusted_file(path, install.CA_LIMIT, secret=False, error='CA_FILE_INVALID')
    try:
        if not data or install.PEM_CERT.sub(b'', data).strip() or not install.x509.load_pem_x509_certificates(data):
            raise ValueError
        return data.decode('ascii')
    except (ValueError, UnicodeError):
        raise ProbeError('CA_FILE_INVALID') from None


def secure_directory(path):
    path = Path(path)
    if '..' in path.parts:
        raise ProbeError('PRIVATE_STATE_DIRECTORY_REQUIRED')
    path = path.absolute()
    try:
        for current in [*reversed(path.parents), path]:
            info = current.lstat()
            reparse = bool(getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0))
            if stat.S_ISLNK(info.st_mode) or reparse or not stat.S_ISDIR(info.st_mode):
                raise ValueError
            if current == path:
                if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    raise ValueError
            else:
                sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not sticky_root):
                    raise ValueError
        return path
    except (OSError, ValueError):
        raise ProbeError('PRIVATE_STATE_DIRECTORY_REQUIRED') from None


def snapshot_bundle(source, destination):
    """Copy bounded regular files through directory FDs before signature verification."""
    source = Path(source)
    if '..' in source.parts:
        raise ProbeError('SIGNED_BUNDLE_INVALID')
    source = source.absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    parent = None
    count, total = 0, 0
    try:
        parent = os.open('/', flags)
        for part in source.parts[1:]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        def copy_directory(src, dst, depth):
            nonlocal count, total
            if depth > 32:
                raise ProbeError('SIGNED_BUNDLE_INVALID')
            for name in os.listdir(src):
                count += 1
                if count > MAX_BUNDLE_FILES:
                    raise ProbeError('SIGNED_BUNDLE_INVALID')
                info = os.stat(name, dir_fd=src, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    fd = os.open(name, flags, dir_fd=src)
                    try:
                        (dst/name).mkdir(mode=0o700)
                        copy_directory(fd, dst/name, depth+1)
                    finally:
                        os.close(fd)
                elif stat.S_ISREG(info.st_mode):
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=src)
                    with os.fdopen(fd, 'rb') as incoming:
                        actual = os.fstat(incoming.fileno())
                        if not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1:
                            raise ProbeError('SIGNED_BUNDLE_INVALID')
                        with open(dst/name, 'xb') as output:
                            while chunk := incoming.read(min(65536, MAX_BUNDLE_BYTES-total+1)):
                                total += len(chunk)
                                if total > MAX_BUNDLE_BYTES:
                                    raise ProbeError('SIGNED_BUNDLE_INVALID')
                                output.write(chunk)
                else:
                    raise ProbeError('SIGNED_BUNDLE_INVALID')
        copy_directory(parent, Path(destination), 0)
    except OSError:
        raise ProbeError('SIGNED_BUNDLE_INVALID') from None
    finally:
        if parent is not None:
            os.close(parent)


def create_operation(root):
    root = secure_directory(root)
    opid = secrets.token_hex(16)
    directory = root/opid
    directory.mkdir(mode=0o700)
    config = directory/'docker-config'
    try:
        config.mkdir(mode=0o700)
        fd = os.open(config/'config.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='ascii') as out:
            out.write('{}\n')
    except BaseException:
        if config.is_dir() and not config.is_symlink():
            (config/'config.json').unlink(missing_ok=True)
            config.rmdir()
        directory.rmdir()
        raise
    return opid, directory


def validate_docker_config(config):
    # Never let a recovery directory supply Docker settings or helpers.
    secure_directory(config)
    try:
        if {p.name for p in config.iterdir()} != {'config.json'}:
            raise ProbeError('DOCKER_CONFIG_UNEXPECTED_CONTENT')
        if regular_bytes(config/'config.json', 16, private=True) != b'{}\n':
            raise ProbeError('DOCKER_CONFIG_INVALID')
    except OSError:
        raise ProbeError('DOCKER_CONFIG_INVALID') from None


def write_journal(directory, record):
    """Atomically publish a small, secret-free identity journal."""
    path = Path(directory)/'journal.json'
    temp = Path(directory)/('journal-'+secrets.token_hex(8)+'.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='ascii') as out:
            json.dump(record, out, sort_keys=True)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
        parent = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temp.unlink(missing_ok=True)


def read_journal(directory):
    directory = secure_directory(directory)
    data = regular_bytes(directory/'journal.json', 4096, private=True)
    try:
        record = json.loads(data)
        opid = record['operation_id']
        if (not isinstance(opid, str) or not ID.fullmatch(opid) or directory.name != opid or
                record.get('schema') != 1 or record.get('network') != 'uter-wp-'+opid or
                record.get('container') != 'uter-wp-'+opid or
                not isinstance(record.get('daemon_id'), str) or not DAEMON_ID.fullmatch(record['daemon_id'])):
            raise ValueError
        return directory, record
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise ProbeError('JOURNAL_INVALID') from None


def docker_environment(config):
    """Never forward caller credentials or proxy settings to the Docker CLI."""
    return {'PATH': '/usr/bin', 'HOME': str(config), 'LANG': 'C'}


def trusted_docker():
    found = shutil.which('docker')
    if not found:
        raise ProbeError('DOCKER_BINARY_UNTRUSTED')
    binary = Path(os.path.normpath(os.path.abspath(found)))
    try:
        # Resolve links one component at a time, validating every link and
        # every directory used along the way, then execute the resolved path.
        for _ in range(41):
            parts = binary.parts
            path = Path('/')
            for index, part in enumerate(parts):
                if index:
                    path /= part
                info = path.lstat()
                reparse = bool(getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0))
                if reparse or info.st_uid not in (0, os.geteuid()):
                    raise ValueError
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(path)
                    candidate = Path(target) if os.path.isabs(target) else path.parent/target
                    binary = Path(os.path.normpath(str(candidate.joinpath(*parts[index+1:]))))
                    break
                if index == len(parts)-1:
                    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_nlink != 1:
                        raise ValueError
                    return str(binary)
                if (not stat.S_ISDIR(info.st_mode) or
                        (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
                    raise ValueError
        raise ValueError
    except (OSError, ValueError):
        raise ProbeError('DOCKER_BINARY_UNTRUSTED') from None


def bounded_process(args, env, timeout, *, payload=None, limit, start_code, timeout_code, overflow_code):
    """Pump subprocess output without unbounded capture or secret-bearing files."""
    try:
        proc = subprocess.Popen(args, env=env, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        raise ProbeError(start_code) from None
    output = bytearray()
    deadline = time.monotonic()+timeout
    try:
        os.set_blocking(proc.stdout.fileno(), False)
        if payload is not None:
            os.set_blocking(proc.stdin.fileno(), False)
        with selectors.DefaultSelector() as selector:
            if payload is not None:
                selector.register(proc.stdin, selectors.EVENT_WRITE, 'stdin')
            selector.register(proc.stdout, selectors.EVENT_READ, 'stdout')
            offset = 0
            while selector.get_map():
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise ProbeError(timeout_code)
                for event, _ in selector.select(min(remaining, 1)):
                    if event.data == 'stdin':
                        try:
                            written = os.write(proc.stdin.fileno(), payload[offset:offset+16384])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            written = 0
                        offset += written
                        if not written or offset == len(payload):
                            selector.unregister(proc.stdin);proc.stdin.close()
                    else:
                        try:
                            chunk = os.read(proc.stdout.fileno(), min(4096, limit+1-len(output)))
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(proc.stdout);proc.stdout.close()
                        else:
                            output.extend(chunk)
                            if len(output) > limit:
                                raise ProbeError(overflow_code)
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise ProbeError(timeout_code)
        rc = proc.wait(timeout=remaining)
        return rc, bytes(output)
    except subprocess.TimeoutExpired:
        raise ProbeError(timeout_code) from None
    finally:
        if proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                raise ProbeError('DOCKER_CLI_TERMINATION_FAILED') from None
        for pipe in (proc.stdin, proc.stdout):
            if pipe and not pipe.closed:
                pipe.close()


def run_docker(config, args, *, timeout=20, allow_failure=False):
    env = docker_environment(config)
    argv = [trusted_docker(), '--config', str(config), '--context', 'default', *args]
    rc, output = bounded_process(argv, env, timeout, limit=MAX_DOCKER_OUTPUT,
                                 start_code='DOCKER_UNAVAILABLE_OR_TIMEOUT',
                                 timeout_code='DOCKER_UNAVAILABLE_OR_TIMEOUT',
                                 overflow_code='DOCKER_OUTPUT_TOO_LARGE')
    result = subprocess.CompletedProcess(argv, rc, output, b'')
    if result.returncode and not allow_failure:
        raise ProbeError('DOCKER_COMMAND_FAILED')
    return result


def daemon_identity(config):
    if os.environ.get('DOCKER_HOST'):
        raise ProbeError('REMOTE_DOCKER_UNSUPPORTED')
    raw = run_docker(config, ['context', 'inspect', 'default']).stdout
    try:
        host = json.loads(raw)[0]['Endpoints']['docker']['Host']
        if not host.startswith('unix://'):
            raise ValueError
        daemon = run_docker(config, ['info', '--format', '{{.ID}}']).stdout.decode('ascii').strip()
        if not DAEMON_ID.fullmatch(daemon):
            raise ValueError
        return daemon
    except (ValueError, KeyError, IndexError, TypeError, UnicodeError):
        raise ProbeError('LOCAL_DOCKER_IDENTITY_UNAVAILABLE') from None


def verify_local_image(config, ref, config_id):
    raw = run_docker(config, ['image', 'inspect', ref]).stdout
    try:
        items = json.loads(raw)
        if not isinstance(items, list) or len(items) != 1:
            raise ValueError
        image = items[0]
        digest = ref.rsplit('@', 1)[-1]
        refs = image.get('RepoDigests') or []
        descriptor = image.get('Descriptor') or {}
        descriptor_match = image.get('Id') == digest and descriptor.get('digest') == digest
        if (not isinstance(refs, list) or
                (ref not in refs and not descriptor_match) or
                (not descriptor_match and (not config_id or image.get('Id') != config_id)) or
                image.get('Os') != 'linux' or image.get('Architecture') != 'amd64'):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise ProbeError('SIGNED_IMAGE_NOT_AVAILABLE_LOCALLY') from None


def signed_image(bundle, publisher_key, fingerprint, state_dir):
    if not FINGERPRINT.fullmatch(fingerprint):
        raise ProbeError('FINGERPRINT_INVALID')
    key = regular_bytes(publisher_key, 32768)
    if hashlib.sha256(key).hexdigest() != fingerprint.lower():
        raise ProbeError('FINGERPRINT_MISMATCH')
    # A private descriptor pins the key bytes between the fingerprint and signature checks.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='uter-preflight-key-', dir=secure_directory(state_dir)) as temp:
        trusted = Path(temp)/'publisher.pem'
        fd = os.open(trusted, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(key)
        try:
            snapshot = Path(temp)/'bundle'
            snapshot.mkdir(mode=0o700)
            snapshot_bundle(bundle, snapshot)
            manifest = uterctl.verify(snapshot, trusted)
            ref = manifest['images']['guardrail']
            if not isinstance(ref, str) or not install.IMAGE.fullmatch(ref):
                raise ValueError
            ids = manifest.get('image_config_ids')
            config_id = ids['guardrail'] if ids is not None else None
            if config_id is not None and not re.fullmatch(r'sha256:[0-9a-f]{64}', config_id):
                raise ValueError
            return ref, config_id
        except Exception:
            raise ProbeError('SIGNED_BUNDLE_INVALID') from None


def result_scope():
    return {'scope': 'disposable_guardrail_image_docker_bridge',
            'actual_uter_application': 'not_checked', 'actual_compose_network': 'not_checked',
            'kubernetes_pod_cni_and_policy': 'not_checked',
            'client': 'python_urllib_in_signed_guardrail_image', 'proxy': 'disabled',
            'health_semantics': 'http_200_does_not_prove_per_model_freshness'}


def run_container(config, record, network_id, ref, payload, timeout, child_timeout):
    """Bound stdout in memory and send the secret payload only through stdin."""
    env = docker_environment(config)
    args = [trusted_docker(), '--config', str(config), '--context', 'default', 'run', '--rm', '-i',
            '--name', record['container'], '--label', LABEL+'='+record['operation_id'],
            '--network', network_id, '--pull', 'never', '--user', '10001:10001',
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--pids-limit', '64', '--memory', '384m', '--cpus', '1', '--entrypoint', 'python',
            ref, '-I', '-c', CHILD_CODE, str(child_timeout)]
    rc, output = bounded_process(args, env, timeout, payload=payload, limit=MAX_REPORT,
                                 start_code='DOCKER_START_FAILED', timeout_code='WORKLOAD_TIMEOUT',
                                 overflow_code='WORKLOAD_OUTPUT_TOO_LARGE')
    try:
        result = json.loads(output)
        if (not isinstance(result, dict) or set(result) != {'result', 'code'} or
                result['result'] not in ('pass', 'fail') or result['code'] not in ALLOWED_RESULT_CODES):
            raise ValueError
        if rc == 0 and result == {'result': 'pass', 'code': 'COMPLETION_RECEIVED'}:
            return result
        if rc != 0 and result['result'] == 'fail' and result['code'] != 'COMPLETION_RECEIVED':
            return result
    except (ValueError, TypeError, KeyError):
        pass
    raise ProbeError('WORKLOAD_RESPONSE_INVALID')


def inspect_owned(config, record, kind):
    opid = record['operation_id']
    flags = ['-a', '-q'] if kind == 'container' else ['-q']
    raw = run_docker(config, [kind, 'ls', *flags, '--filter', 'label='+LABEL+'='+opid]).stdout
    ids = raw.decode('ascii').split()
    if len(ids) > 1 or any(not re.fullmatch(r'[0-9a-f]{12,64}', item) for item in ids):
        raise ProbeError('RESOURCE_IDENTITY_AMBIGUOUS')
    for item in ids:
        raw = run_docker(config, [kind, 'inspect', item]).stdout
        try:
            info = json.loads(raw)[0]
            labels = (info.get('Config') or {}).get('Labels') if kind == 'container' else info.get('Labels')
            name = info['Name'].lstrip('/')
            if (labels or {}).get(LABEL) != opid or name != record[kind]:
                raise ValueError
            if kind == 'network' and info.get('Containers'):
                raise ProbeError('NETWORK_HAS_UNRELATED_ATTACHMENTS')
        except ProbeError:
            raise
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise ProbeError('RESOURCE_IDENTITY_MISMATCH') from None
    return ids


def _cleanup_operation(directory, *, remove_journal=True):
    directory, record = read_journal(directory)
    config = directory/'docker-config'
    validate_docker_config(config)
    if {p.name for p in directory.iterdir()} != {'journal.json', 'docker-config'}:
        raise ProbeError('JOURNAL_UNEXPECTED_CONTENT')
    if daemon_identity(config) != record['daemon_id']:
        raise ProbeError('DOCKER_DAEMON_CHANGED')
    for kind in ('container', 'network'):
        for item in inspect_owned(config, record, kind):
            args = [kind, 'rm']
            if kind == 'container':
                args.append('-f')
            run_docker(config, args+[item], timeout=30)
    if not remove_journal:
        return
    # Do not recursively remove anything unexpected from a user-provided directory.
    validate_docker_config(config)
    if {p.name for p in directory.iterdir()} != {'journal.json', 'docker-config'}:
        raise ProbeError('JOURNAL_UNEXPECTED_CONTENT')
    (config/'config.json').unlink();config.rmdir()
    (directory/'journal.json').unlink();directory.rmdir()


def cleanup_operation(directory, *, remove_journal=True):
    # A repeated Ctrl-C/SIGTERM must not interrupt removal halfway through.
    if os.name != 'posix' or not hasattr(signal, 'pthread_sigmask'):
        raise ProbeError('LINUX_REQUIRED')
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        return _cleanup_operation(directory, remove_journal=remove_journal)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def prepare_payload(args):
    try:
        url = preflight.check_url(args.llm_url, args.allow_http_llm)
        if '\\' in args.llm_url or any(ord(c) <= 32 or ord(c) >= 127 for c in args.llm_url):
            raise ProbeError('URL_INVALID')
        if not args.llm_model or len(args.llm_model) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in args.llm_model):
            raise ProbeError('MODEL_INVALID')
        health = args.health_url or parse.urlunsplit((url.scheme, url.netloc, '/health', '', ''))
        parsed = preflight.check_url(health, args.allow_http_llm)
        if not preflight.same_origin(url, parsed) or '\\' in health or any(ord(c) <= 32 or ord(c) >= 127 for c in health):
            raise ProbeError('HEALTH_ORIGIN_INVALID')
        if not 1 <= args.timeout <= 120:
            raise ProbeError('TIMEOUT_INVALID')
        ca = read_trusted_ca(args.llm_ca_bundle) if args.llm_ca_bundle else ''
        if ca and url.scheme != 'https':
            raise ProbeError('CA_REQUIRES_HTTPS')
        key = read_trusted_key(args.llm_key_file)
    except (preflight.CheckFailure, ValueError, OSError):
        raise ProbeError('INPUT_INVALID') from None
    return json.dumps({'base': args.llm_url, 'health': health, 'model': args.llm_model, 'key': key,
                       'ca_bundle': ca, 'timeout': args.timeout,
                       'total_timeout': args.timeout*2+10}, ensure_ascii=True).encode()


def probe(args):
    if os.name != 'posix':
        raise ProbeError('LINUX_REQUIRED')
    payload = prepare_payload(args)
    ref, config_id = signed_image(args.bundle, args.publisher_key, args.fingerprint, args.state_dir)
    opid, directory = create_operation(args.state_dir)
    config = directory/'docker-config'
    record = None
    attempted = False
    uncertain = False
    try:
        validate_docker_config(config)
        daemon = daemon_identity(config)
        verify_local_image(config, ref, config_id)
        record = {'schema': 1, 'operation_id': opid, 'network': 'uter-wp-'+opid,
                  'container': 'uter-wp-'+opid, 'daemon_id': daemon}
        write_journal(directory, record)
        print('Recovery journal:', directory, file=sys.stderr, flush=True)
        # Once a create is sent, a killed client may not know whether dockerd
        # completed it. Keep the journal on interruptions/timeouts even if no
        # resources are immediately visible.
        attempted = True
        result = run_docker(config, ['network', 'create', '--driver', 'bridge', '--label',
                                    LABEL+'='+opid, record['network']], timeout=30)
        network_id = result.stdout.decode('ascii').strip()
        if not re.fullmatch(r'[0-9a-f]{12,64}', network_id):
            raise ProbeError('NETWORK_CREATE_RESPONSE_INVALID')
        networks = inspect_owned(config, record, 'network')
        if len(networks) != 1 or not network_id.startswith(networks[0]) and not networks[0].startswith(network_id):
            raise ProbeError('NETWORK_IDENTITY_MISMATCH')
        report = run_container(config, record, network_id, ref, payload,
                               timeout=args.timeout*2+45, child_timeout=args.timeout*2+10)
        return {**result_scope(), **report, 'ca_bundle': 'provided' if args.llm_ca_bundle else 'image_default',
                'health_url': 'operator_supplied' if args.health_url else 'root_health_assumption',
                'http_transport': 'unencrypted' if args.llm_url.startswith('http://') else 'tls_verified'}
    except BaseException:
        uncertain = attempted
        raise
    finally:
        if record is None or not attempted:
            # No Docker resource has been created yet. Only remove known local files.
            (config/'config.json').unlink(missing_ok=True)
            config.rmdir();(directory/'journal.json').unlink(missing_ok=True);directory.rmdir()
        else:
            # On interrupted/failed creates preserve the identity journal even when
            # cleanup currently sees nothing: a daemon operation may still complete.
            cleanup_operation(directory, remove_journal=not uncertain)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('probe')
    for name in ('bundle', 'publisher-key', 'llm-key-file', 'state-dir'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--fingerprint', required=True)
    p.add_argument('--llm-url', required=True)
    p.add_argument('--llm-model', required=True)
    p.add_argument('--llm-ca-bundle', type=Path)
    p.add_argument('--health-url')
    p.add_argument('--allow-http-llm', action='store_true')
    p.add_argument('--timeout', type=int, default=30)
    c = commands.add_parser('cleanup')
    c.add_argument('--operation-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'cleanup':
            cleanup_operation(args.operation_dir)
            result = {'result': 'pass', 'cleanup': 'complete'}
        else:
            result = probe(args)
        print(json.dumps(result, indent=2))
        return 0 if result['result'] == 'pass' else 1
    except (Exception, KeyboardInterrupt) as exc:
        code = str(exc) if isinstance(exc, ProbeError) else 'INTERRUPTED' if isinstance(exc, KeyboardInterrupt) else 'INTERNAL_ERROR'
        print(json.dumps({'result': 'fail', 'code': code,
                          'cleanup': 'check_recovery_journal'}))
        return 1


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda _signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt()))
    sys.exit(main())
