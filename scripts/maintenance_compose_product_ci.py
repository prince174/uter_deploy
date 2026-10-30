"""Exercise maintenance on exact compiled images in a disposable CI project.

This probe does not establish a production lock, ingress fence, Redis writer
isolation, backup, upgrade or recovery. Never run on a shared Docker daemon.
"""
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

from scripts import maintenance_evidence, maintenance_protocol, maintenance_transport, redis_fence_journal


class ProbeError(ValueError):
    pass


def _docker(*args):
    result = subprocess.run(['/usr/bin/docker', '--context', 'default', *map(str, args)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=True, timeout=30)
    if len(result.stdout) > 8192:
        raise ProbeError('MAINTENANCE_CI_INSPECT_UNVERIFIED')
    return result.stdout.decode('utf-8').strip()


def exercise(home):
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('RUNNER_OS') != 'Linux' or os.environ.get('UTER_CI_MAINTENANCE') != 'true'):
        raise ProbeError('MAINTENANCE_CI_ENVIRONMENT_UNVERIFIED')
    home = Path(home).resolve(strict=True)
    if home.name != 'integration' or home.parent.name != 'work':
        raise ProbeError('MAINTENANCE_CI_PATH_UNVERIFIED')
    project = 'uter-compiled-ci'
    def inspect():
        result = {}
        for service in ('agent', 'guardrail', 'redis'):
            ident = _docker('ps', '--no-trunc', '--filter', 'label=com.docker.compose.project='+project,
                            '--filter', 'label=com.docker.compose.service='+service, '--format', '{{.ID}}')
            if not re.fullmatch(r'[0-9a-f]{64}', ident):
                raise ProbeError('MAINTENANCE_CI_IDENTITY_UNVERIFIED')
            fmt = ('{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},'
                   '"started":{{json .State.StartedAt}},"restarts":{{json .RestartCount}},'
                   '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                   '"service":{{json (index .Config.Labels "com.docker.compose.service")}}}')
            detail = json.loads(_docker('inspect', '--format', fmt, ident))
            if (detail.get('id') != ident or detail.get('running') is not True or detail.get('project') != project
                    or detail.get('service') != service or not isinstance(detail.get('started'), str)
                    or type(detail.get('restarts')) is not int):
                raise ProbeError('MAINTENANCE_CI_IDENTITY_UNVERIFIED')
            if service in ('agent', 'guardrail'):
                expected = _docker('image', 'inspect', '--format', '{{.Id}}', 'uter-'+service+'-protected')
                if detail.get('image') != expected:
                    raise ProbeError('MAINTENANCE_CI_IMAGE_UNVERIFIED')
            result[service] = detail
        return result
    pinned = inspect()
    identities = {'agent': (pinned['agent']['id'],), 'guardrail': (pinned['guardrail']['id'],)}
    def stable():
        return inspect() == pinned
    def inventory():
        if not stable():
            raise ProbeError('MAINTENANCE_CI_IDENTITY_CHANGED')
        return dict(identities)
    proof = home/'maintenance-ci-proof'; proof.mkdir(mode=0o700)
    operation = secrets.token_hex(16)
    plan = secrets.token_hex(32)
    redis_fence_journal.create(proof, backend='compose', site=project, resource=pinned['redis']['id'],
                               plan_sha256=plan, operation=operation)
    # CI fixture only: no production lock or external-writer fence is asserted.
    recorder = maintenance_evidence.Recorder(proof, secrets.token_bytes(32), operation=operation,
                                             backend='compose', plan_sha256=plan, lock_guard=lambda: True)
    def request(service, instance, method, timeout):
        return maintenance_transport.request(service=service, method=method, container_id=instance, identity_guard=stable)
    result = maintenance_protocol.collect(identities, observe_inventory=inventory, request=request,
                                          record_intent=recorder.intent, record_receipt=recorder.receipt)
    if set(result) != {pinned['agent']['id'], pinned['guardrail']['id']} or not stable():
        raise ProbeError('MAINTENANCE_CI_RECEIPTS_UNVERIFIED')
    # Simulate a lost process after both receipts. This runs only in the
    # disposable CI project and does not establish continuous fencing.
    _docker('stop', '--time', '5', pinned['agent']['id'])
    invalidated = False
    try:
        inventory()
    except Exception:
        invalidated = True
    if not invalidated:
        raise ProbeError('MAINTENANCE_CI_STOP_NOT_DETECTED')
    (home.parent/'integration-evidence'/'maintenance.txt').write_text(
        'Agent and Guardrail maintenance receipts verified on exact compiled containers.\n'
        'Stopping the receipted Agent invalidated the inventory.\n'
        'Redis fence, backup, update and recovery were not tested by this probe.\n', encoding='utf-8')
    print('MAINTENANCE_COMPOSE_PRODUCT_RECEIPTS_PASS: no Redis fence, backup or update asserted', flush=True)
