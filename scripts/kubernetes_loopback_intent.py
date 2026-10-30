"""Durable intent and conservative recovery classification for a Redis rollout.

This primitive alone is not a fence, rollback, or permission to update. The
caller holds the installation lock and is responsible for authenticating the
cluster, signed installation and storage, stopping every writer and preventing
other controllers from acting. The journal and intent are point-in-time
evidence only. No paths here release a finalizer or resume writers.
"""
import copy
import hashlib
import json
import os
import re
import stat

from scripts import kubernetes_fence_finalizer as finalizer
from scripts import kubernetes_redis_identity as identity
from scripts import redis_fence_journal as journal

NAME = 'redis-loopback-intent.json'
ATTEMPT_NAME = 'redis-loopback-attempt.json'
MAX_BYTES = 4096
FIELDS = frozenset(('schema', 'operation', 'context', 'namespace', 'deployment',
                    'uid', 'original_rv', 'original_hash', 'loopback_hash'))
LOOPBACK = identity.COMMAND + ' --bind 127.0.0.1'


class LoopbackIntentError(ValueError):
    pass


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode()).hexdigest()


def _validate(value):
    try:
        if (not isinstance(value, dict) or set(value) != FIELDS or value['schema'] != 1
                or type(value['schema']) is not int
                or not re.fullmatch(r'[0-9a-f]{32}', value['operation'])
                or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.:@/-]{0,252}', value['context'])
                or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', value['namespace'])
                or value['deployment'] != value['namespace'] + '-redis'
                or not identity.UUID.fullmatch(value['uid'])
                or not re.fullmatch(r'[0-9]{1,32}', value['original_rv'])
                or not re.fullmatch(r'[0-9a-f]{64}', value['original_hash'])
                or not re.fullmatch(r'[0-9a-f]{64}', value['loopback_hash'])
                or value['original_hash'] == value['loopback_hash']):
            raise ValueError
        return value
    except (KeyError, TypeError, ValueError):
        raise LoopbackIntentError('KUBE_LOOPBACK_INTENT_INVALID') from None


def _read(directory):
    fd = journal._directory(directory)
    try:
        try:
            handle = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(handle, 'rb') as source:
                info = os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > MAX_BYTES):
                    raise LoopbackIntentError('KUBE_LOOPBACK_INTENT_UNSAFE')
                data = source.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise LoopbackIntentError('KUBE_LOOPBACK_INTENT_UNSAFE')
            return _validate(json.loads(data))
        except LoopbackIntentError:
            raise
        except (OSError, ValueError, TypeError, UnicodeError):
            raise LoopbackIntentError('KUBE_LOOPBACK_INTENT_UNREADABLE') from None
    finally:
        os.close(fd)


def _persist(directory, record):
    """Write once, fsync file and containing directory before any API patch."""
    encoded = (json.dumps(_validate(record), sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = journal._directory(directory)
    try:
        try:
            handle = os.open(NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(handle, 'wb') as target:
                os.fchmod(target.fileno(), 0o600)
                target.write(encoded)
                target.flush()
                os.fsync(target.fileno())
            os.fsync(fd)
        except OSError:
            # A failed write/fsync may have created the file. Preserve it.
            raise LoopbackIntentError('KUBE_LOOPBACK_INTENT_WRITE_UNCERTAIN') from None
    finally:
        os.close(fd)


def _mark_attempt(directory, record):
    """Never replay a request whose API result may still be in flight."""
    raw = (json.dumps({'operation': record['operation'], 'intent_sha256': _hash(record)},
                      sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = journal._directory(directory)
    try:
        try:
            handle = os.open(ATTEMPT_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=fd)
            with os.fdopen(handle, 'wb') as target:
                os.fchmod(target.fileno(), 0o600)
                target.write(raw)
                target.flush()
                os.fsync(target.fileno())
            os.fsync(fd)
        except OSError:
            # Exists or creation uncertain: retain evidence and never submit.
            raise LoopbackIntentError('KUBE_LOOPBACK_ATTEMPT_UNCERTAIN') from None
    finally:
        os.close(fd)


def _reject_existing_attempt(directory):
    """An attempt marker of any type blocks a second request."""
    fd = journal._directory(directory)
    try:
        try:
            os.stat(ATTEMPT_NAME, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise LoopbackIntentError('KUBE_LOOPBACK_ATTEMPT_UNCERTAIN')
    finally:
        os.close(fd)


def _deployment(record, deployment):
    try:
        if not isinstance(deployment, dict) or deployment.get('kind') != 'Deployment':
            raise ValueError
        meta = deployment['metadata']
        if (meta.get('name') != record['deployment'] or meta.get('namespace') != record['namespace']
                or meta.get('uid') != record['uid'] or meta.get('deletionTimestamp')
                or not isinstance(meta.get('resourceVersion'), str)
                or not re.fullmatch(r'[0-9]{1,32}', meta['resourceVersion'])):
            raise ValueError
        spec = deployment['spec']
        containers = spec['template']['spec']['containers']
        if (not isinstance(containers, list) or len(containers) != 1
                or containers[0].get('name') != 'redis'):
            raise ValueError
        return meta, spec, containers[0]
    except (KeyError, TypeError, ValueError):
        raise LoopbackIntentError('KUBE_LOOPBACK_DEPLOYMENT_CHANGED') from None


def _bound(directory, pod_plan, operation, api):
    try:
        finalizer._check_journal(directory, pod_plan, operation, 'isolating')
        if api.context != pod_plan['context'] or api.namespace != pod_plan['namespace']:
            raise ValueError
    except Exception:
        raise LoopbackIntentError('KUBE_LOOPBACK_CONTEXT_CHANGED') from None


def prepare(directory, pod_plan, operation, api):
    """Persist exact before/after spec hashes; never patch a resource here."""
    _bound(directory, pod_plan, operation, api)
    try:
        finalizer._verify_live(pod_plan, api.get(pod_plan['pod']), [finalizer._token(operation)])
        name = pod_plan['namespace'] + '-redis'
        deployment = api.get_deployment(name)
        meta = deployment['metadata']
        record = {'schema': 1, 'operation': operation, 'context': pod_plan['context'],
                  'namespace': pod_plan['namespace'], 'deployment': name, 'uid': meta['uid'],
                  'original_rv': meta['resourceVersion'], 'original_hash': '0' * 64,
                  'loopback_hash': '1' * 64}
        _, spec, container = _deployment(record, deployment)
        if container.get('args') != [identity.COMMAND]:
            raise ValueError
        target = copy.deepcopy(spec)
        target['template']['spec']['containers'][0]['args'] = [LOOPBACK]
        record['original_hash'] = _hash(spec)
        record['loopback_hash'] = _hash(target)
        _persist(directory, record)
        return _validate(record)
    except LoopbackIntentError:
        raise
    except Exception:
        raise LoopbackIntentError('KUBE_LOOPBACK_PREPARE_UNCERTAIN') from None


def classify(directory, pod_plan, operation, api):
    """Classify an ambiguous patch without mutating objects or authorizing update.

    A match is only evidence about the observed Deployment spec. It says nothing
    about rollout, old Pods, external writers, storage durability or ownership.
    """
    _bound(directory, pod_plan, operation, api)
    record = _read(directory)
    if (record['operation'] != operation or record['context'] != api.context
            or record['namespace'] != api.namespace):
        raise LoopbackIntentError('KUBE_LOOPBACK_INTENT_MISMATCH')
    try:
        meta, spec, _ = _deployment(record, api.get_deployment(record['deployment']))
        observed = _hash(spec)
        if observed == record['original_hash'] and meta['resourceVersion'] == record['original_rv']:
            state = 'original_observed'
        elif observed == record['loopback_hash']:
            state = 'loopback_spec_observed'
        else:
            raise ValueError
        return {'state': state, 'redis_isolated': False, 'safe_to_update': False}
    except Exception:
        raise LoopbackIntentError('KUBE_LOOPBACK_RESULT_UNCERTAIN') from None


def request(directory, pod_plan, operation, api):
    """Make exactly one UID/RV-guarded patch after a durable intent exists."""
    _bound(directory, pod_plan, operation, api)
    record = _read(directory)
    if (record['operation'] != operation or record['context'] != api.context
            or record['namespace'] != api.namespace):
        raise LoopbackIntentError('KUBE_LOOPBACK_INTENT_MISMATCH')
    try:
        _reject_existing_attempt(directory)
        finalizer._verify_live(pod_plan, api.get(pod_plan['pod']), [finalizer._token(operation)])
        if classify(directory, pod_plan, operation, api)['state'] != 'original_observed':
            raise ValueError
        # The durable one-shot marker precedes the request. A timeout cannot be
        # assumed to cancel processing by the API server, so retry is forbidden.
        _mark_attempt(directory, record)
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': record['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': record['original_rv']},
                 {'op': 'test', 'path': '/spec/template/spec/containers/0/args', 'value': [identity.COMMAND]},
                 {'op': 'replace', 'path': '/spec/template/spec/containers/0/args', 'value': [LOOPBACK]}]
        api.patch_deployment(record['deployment'], patch)
        if classify(directory, pod_plan, operation, api)['state'] != 'loopback_spec_observed':
            raise ValueError
    except Exception:
        raise LoopbackIntentError('KUBE_LOOPBACK_REQUEST_UNCERTAIN') from None
    return {'state': 'loopback_spec_observed', 'redis_isolated': False, 'safe_to_update': False}
