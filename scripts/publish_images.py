"""Publish exact audited archives to GHCR on an ephemeral GitHub runner."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request
import urllib.error
import urllib.parse
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import source_provenance

REDIS = 'redis:7.4-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf'


def run(args):
    return subprocess.check_output(args, text=True).strip()


def anonymous_denied(name):
    url = 'https://ghcr.io/token?' + urllib.parse.urlencode({'service': 'ghcr.io', 'scope': f'repository:{name}:pull'})
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            body = json.load(response)
        # A token with pull scope means an anonymous caller can access the package.
        if body.get('token') or body.get('access_token'):
            raise RuntimeError('Anonymous pull token granted; refusing publication to a non-private package')
        raise RuntimeError('Unexpected anonymous registry response')
    except urllib.error.HTTPError as error:
        if error.code not in (401, 403, 404):
            raise


def verify_visibility(name, reference, visibility):
    if visibility == 'private':
        anonymous_denied(name)
    elif visibility == 'public':
        with tempfile.TemporaryDirectory() as config:
            subprocess.run(['docker', '--config', config, 'pull', reference], check=True)
    else:
        raise ValueError('Expected private or public package visibility')


def snapshot_identity(images_root):
    """Fail before registry writes if source snapshot metadata is partial or differs."""
    states = []
    for service in ('guardrail', 'agent', 'redis'):
        evidence = Path(images_root) / ('protected-' + service) / 'evidence'
        path = evidence / 'source-state.json'
        if path.exists():
            baseline = (evidence / 'source-sha.txt').read_text().strip()
            states.append(source_provenance.validate(json.loads(path.read_text()), baseline))
    if states and (len(states) != 3 or any(item != states[0] for item in states)):
        raise ValueError('Source snapshot identity differs between images')
    return states[0] if states else None


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('GitHub-hosted CI only')
    owner = os.environ['GITHUB_REPOSITORY_OWNER'].lower()
    visibility = os.environ.get('PACKAGE_VISIBILITY', 'private')
    if visibility not in ('private', 'public'):
        raise ValueError('Expected private or public package visibility')
    build = os.environ['BUILD_RUN_ID']
    assert re.fullmatch(r'\d+', build)
    identity = json.loads(run(['gh', 'api', f'repos/{os.environ["GITHUB_REPOSITORY"]}/actions/runs/{build}']))
    assert identity['path'] in ('.github/workflows/harden-image-artifacts.yml', '.github/workflows/remediate-images.yml', '.github/workflows/remediate-new-build.yml') and identity['conclusion'] == 'success'
    remediated = identity['path'] in ('.github/workflows/remediate-images.yml', '.github/workflows/remediate-new-build.yml')
    snapshot_identity('work/images')
    images, metadata = {}, {}
    snapshot_states = []
    output = Path('work/published')
    output.mkdir(parents=True)
    for service in ('guardrail', 'agent', 'redis'):
        package = f'{owner}/uter-{service}'
        if visibility == 'private': anonymous_denied(package)
        if service != 'redis' or remediated:
            folder = Path(f'work/images/protected-{service}')
            if remediated:
                gate = json.loads((folder / 'evidence/security-summary.json').read_text())
                assert gate['critical_high'] == 0 and gate['secrets'] == 0
            archive = folder / 'image.tar.gz'
            expected = (folder / 'evidence/archive.sha256').read_text().split()[0]
            with archive.open('rb') as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            assert actual == expected
            subprocess.run(['python', 'scripts/scan_image_archive.py', str(archive)], check=True)
            subprocess.run(['docker', 'load', '-i', str(archive)], check=True)
            local = f'uter-{service}-protected'
            image_id = run(['docker', 'image', 'inspect', local, '--format', '{{.Id}}'])
            assert image_id == (folder / 'evidence/image-id.txt').read_text().strip()
            sha = (folder / 'evidence/source-sha.txt').read_text().strip()
            assert re.fullmatch('[0-9a-f]{40}', sha)
            metadata[service] = dict(source_commit=sha, archive_sha256=actual, image_id=image_id)
            snapshot_file = folder / 'evidence/source-state.json'
            if snapshot_file.exists():
                state = source_provenance.validate(json.loads(snapshot_file.read_text()), sha)
                metadata[service]['source_state'] = state
                snapshot_states.append(state)
            if remediated:
                metadata[service]['security'] = gate
                if service == 'redis':
                    metadata[service]['application_commit'] = metadata[service].pop('source_commit')
                    metadata[service]['upstream'] = (folder / 'evidence/parent-image.txt').read_text().strip()
        else:
            local = REDIS
            subprocess.run(['docker', 'pull', '--platform', 'linux/amd64', local], check=True)
            metadata[service] = dict(upstream=REDIS)
        tag = f'ghcr.io/{package}:build-{build}'
        subprocess.run(['docker', 'tag', local, tag], check=True)
        subprocess.run(['docker', 'push', tag], check=True)
        refs = json.loads(run(['docker', 'image', 'inspect', tag, '--format', '{{json .RepoDigests}}']))
        images[service] = next(ref for ref in refs if ref.startswith(f'ghcr.io/{package}@sha256:'))
        # Verify the requested visibility using an isolated client configuration.
        subprocess.run(['docker', 'pull', images[service]], check=True)
        verify_visibility(package, images[service], visibility)
    assert metadata['agent']['source_commit'] == metadata['guardrail']['source_commit']
    if snapshot_states:
        if len(snapshot_states) != 3 or any(state != snapshot_states[0] for state in snapshot_states):
            raise ValueError('Source snapshot identity differs between images')
    (output / 'images.json').write_text(json.dumps(images, indent=2) + '\n')
    (output / 'publication.json').write_text(json.dumps(dict(build_run_id=build, images=metadata,
        registry='ghcr.io', anonymous_pull='allowed' if visibility == 'public' else 'denied', workflow_run_id=os.environ['GITHUB_RUN_ID']), indent=2) + '\n')
    source = Path('work/images/protected-guardrail/evidence')
    if remediated:
        for service in images:
            shutil.copyfile(Path(f'work/images/protected-{service}/evidence/security-summary.json'), output / f'{service}-security-summary.json')
    shutil.copyfile(source / 'policies/default.toml', output / 'policy.toml')
    shutil.copyfile(source / 'profiles/model_profiles.toml', output / 'model_profiles.toml')
    with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as report:
        report.write(f'{visibility.capitalize()} registry publication verified.\n\n```json\n' + json.dumps(images, indent=2) + '\n```\n')


if __name__ == '__main__':
    main()
