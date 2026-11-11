"""Publish only image-bound SQLite VEX candidates on a disposable CI runner.

Raw Trivy High findings remain in the evidence. This is a narrowly authorised
candidate publication, not a signed deployment release or a strict raw gate pass.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import sqlite_vex_gate

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ('agent', 'guardrail')


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def verify_evidence(root, service, actual_id):
    security = Path(root) / 'security'
    image_id = (security / (service + '-image-id.txt')).read_text().strip()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id) or image_id != actual_id:
        raise ValueError('PUBLISH_IMAGE_IDENTITY_UNVERIFIED')
    raw = read_json(security / (service + '.json'))
    measurement = read_json(security / (service + '-sqlite.json'))
    _, result = sqlite_vex_gate.assess_evidence(raw, image_id, measurement)
    if read_json(security / (service + '-vex-summary.json')) != result:
        raise ValueError('PUBLISH_VEX_UNVERIFIED')
    audit = read_json(security / (service + '-source-audit.json'))
    if not isinstance(audit, dict) or audit.get('schema') != 2 or audit.get('violations') != []:
        raise ValueError('PUBLISH_SOURCE_AUDIT_UNVERIFIED')
    return result


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('GITHUB_REPOSITORY') != 'prince174/uter_deploy'
            or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or os.environ.get('GITHUB_REF') != 'refs/heads/main'
            or os.environ.get('RAW_GATE_OUTCOME') != 'failure'
            or not re.fullmatch(r'[1-9][0-9]{0,19}', os.environ.get('GITHUB_RUN_ID', ''))
            or not re.fullmatch(r'[1-9][0-9]{0,5}', os.environ.get('GITHUB_RUN_ATTEMPT', ''))):
        raise ValueError('PUBLISH_CONTEXT_UNVERIFIED')
    token = os.environ.get('REGISTRY_TOKEN', '')
    if not token or '\n' in token:
        raise ValueError('PUBLISH_CREDENTIAL_UNAVAILABLE')
    work = ROOT / 'work'
    acceptance = read_json(work / 'integration-evidence/acceptance.json')
    for key in ('auth', 'normal_chat', 'input_block', 'output_pii_block', 'openai_api', 'agent_auth', 'audit_chain', 'real_toxicity_model'):
        if acceptance.get(key) != 'pass':
            raise ValueError('PUBLISH_INTEGRATION_UNVERIFIED')
    if (work / 'integration-evidence/restart.txt').read_text().strip() != 'Guardrail restart + repeated acceptance + audit continuity passed':
        raise ValueError('PUBLISH_RESTART_UNVERIFIED')
    def docker(*args):
        return subprocess.check_output(['docker', *args], text=True, timeout=180).strip()
    verified = {}
    for service in SERVICES:
        image_id = docker('image', 'inspect', 'uter-' + service + '-protected', '--format', '{{.Id}}')
        verified[service] = verify_evidence(work, service, image_id)
    result = {'schema': 1, 'status': 'partial', 'run_id': os.environ['GITHUB_RUN_ID'],
              'strict_unfiltered_gate': 'failed', 'sqlite_vex_gate': 'passed', 'images': {}}
    path = work / 'security/publication.json'
    def write_result():
        tmp = path.with_suffix('.tmp')
        tmp.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        os.replace(tmp, path)
    write_result()
    with tempfile.TemporaryDirectory(prefix='uter-registry-') as config:
        subprocess.run(['docker', '--config', config, 'login', 'ghcr.io', '--username', 'prince174', '--password-stdin'],
                       input=token.encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=60)
        for service in SERVICES:
            expected = verified[service]['image_id']
            if docker('image', 'inspect', 'uter-' + service + '-protected', '--format', '{{.Id}}') != expected:
                raise ValueError('PUBLISH_IMAGE_IDENTITY_CHANGED')
            tag = 'ghcr.io/prince174/uter-' + service + ':sqlite-vex-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
            subprocess.run(['docker', 'tag', 'uter-' + service + '-protected', tag], check=True, timeout=60)
            result['images'][service] = {'tag': tag, 'image_id': expected, 'state': 'push_started'}
            write_result()
            subprocess.run(['docker', '--config', config, 'push', tag], check=True, timeout=900)
            refs = json.loads(docker('image', 'inspect', tag, '--format', '{{json .RepoDigests}}'))
            prefix = 'ghcr.io/prince174/uter-' + service + '@sha256:'
            matches = [x for x in refs if isinstance(x, str) and re.fullmatch(re.escape(prefix) + r'[0-9a-f]{64}', x)]
            if len(matches) != 1:
                raise ValueError('PUBLISH_DIGEST_UNVERIFIED')
            ref = matches[0]
            # Record immediately so a subsequent failure cannot hide a partial publication.
            result['images'][service] = {'tag': tag, 'reference': ref, 'image_id': expected, 'anonymous_pull_verified': False}
            write_result()
            with tempfile.TemporaryDirectory(prefix='uter-anonymous-') as anonymous:
                subprocess.run(['docker', '--config', anonymous, 'pull', ref], check=True, timeout=900,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if docker('image', 'inspect', ref, '--format', '{{.Id}}') != expected:
                    raise ValueError('PUBLISH_PULLED_IMAGE_MISMATCH')
            vex, checked = sqlite_vex_gate.build_vex(
                read_json(work / ('security/' + service + '.json')), expected,
                read_json(work / ('security/' + service + '-sqlite.json')), ref)
            if checked != verified[service]:
                raise ValueError('PUBLISH_VEX_UNVERIFIED')
            (work / ('security/' + service + '-vex.json')).write_text(json.dumps(vex, indent=2) + '\n', encoding='utf-8')
            result['images'][service]['anonymous_pull_verified'] = True
            write_result()
    result['status'] = 'complete'
    write_result()
    print('SQLite VEX candidate images published; unfiltered Trivy findings remain in the evidence.')


if __name__ == '__main__':
    main()
