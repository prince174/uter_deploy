"""Mirror verified GHCR images into explicitly private Docker Hub repositories."""
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request
import urllib.error
import urllib.parse


def api(path, token=None, data=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request('https://hub.docker.com' + path,
        data=json.dumps(data).encode() if data is not None else None, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        try:
            payload = json.load(error)
            detail = str(payload.get('message', payload.get('detail', 'Request rejected')))
            detail = re.sub(r'[A-Za-z0-9_.-]{40,}', '[REDACTED]', detail)
            error.safe_detail = detail[:400]
        except (ValueError, AttributeError):
            error.safe_detail = 'Request rejected'
        raise


def private_repository(namespace, name, token):
    path = f'/v2/namespaces/{namespace}/repositories/{name}'
    try:
        repository = api(path, token)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        api(f'/v2/namespaces/{namespace}/repositories', token,
            {'name': name, 'namespace': namespace, 'is_private': True, 'registry': 'docker.io'})
        repository = api(path, token)
    if repository.get('is_private') is not True:
        raise RuntimeError('Repository is not private; refusing to publish')


def anonymous_denied(repository, digest):
    query = urllib.parse.urlencode({'service': 'registry.docker.io', 'scope': f'repository:{repository}:pull'})
    with urllib.request.urlopen('https://auth.docker.io/token?' + query, timeout=30) as response:
        token = json.load(response)['token']
    request = urllib.request.Request(f'https://registry-1.docker.io/v2/{repository}/manifests/{digest}',
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}, method='HEAD')
    try:
        with urllib.request.urlopen(request, timeout=30):
            raise RuntimeError('Anonymous manifest access succeeded; repository is not private')
    except urllib.error.HTTPError as error:
        if error.code not in (401, 403, 404):
            raise


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('GitHub-hosted CI only')
    namespace = os.environ['DOCKERHUB_NAMESPACE']
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{1,63}', namespace):
        raise ValueError('Invalid Docker Hub namespace')
    username, password = os.environ['DOCKERHUB_USERNAME'], os.environ['DOCKERHUB_TOKEN']
    if not username or not password:
        raise ValueError('DOCKERHUB_USERNAME and DOCKERHUB_TOKEN GitHub secrets are required')
    token = api('/v2/auth/token', data={'identifier': username, 'secret': password})['access_token']
    run_id = os.environ['SOURCE_RUN_ID']
    assert re.fullmatch('[0-9]+', run_id)
    source_run = json.loads(subprocess.check_output(['gh', 'api', f'repos/{os.environ["GITHUB_REPOSITORY"]}/actions/runs/{run_id}']))
    assert source_run['path'] == '.github/workflows/publish-images.yml' and source_run['conclusion'] == 'success'
    folder = Path('work/published')
    source = json.loads((folder / 'images.json').read_text())
    assert set(source) == {'guardrail', 'agent', 'redis'}
    for service in source:
        assert re.fullmatch(r'ghcr.io/[a-z0-9_-]+/uter-' + service + r'@sha256:[a-f0-9]{64}', source[service])
        private_repository(namespace, 'uter-' + service, token)
    subprocess.run(['docker', 'login', '-u', username, '--password-stdin'], input=password.encode(), check=True, capture_output=True)
    result, identities = {}, {}
    def inspect(ref, fmt):
        return subprocess.check_output(['docker', 'image', 'inspect', ref, '--format', fmt], text=True).strip()
    for service, original in source.items():
        subprocess.run(['docker', 'pull', original], check=True)
        original_id = inspect(original, '{{.Id}}')
        repository = f'{namespace}/uter-{service}'
        tag = f'docker.io/{repository}:publication-{run_id}'
        subprocess.run(['docker', 'tag', original, tag], check=True)
        subprocess.run(['docker', 'push', tag], check=True)
        refs = json.loads(inspect(tag, '{{json .RepoDigests}}'))
        ref = next(x for x in refs if x.split('@')[0] in (repository, 'docker.io/' + repository))
        result[service] = 'docker.io/' + repository + '@' + ref.split('@')[1]
        subprocess.run(['docker', 'pull', result[service]], check=True)
        assert inspect(result[service], '{{.Id}}') == original_id
        private_repository(namespace, 'uter-' + service, token)
        anonymous_denied(repository, ref.split('@')[1])
        identities[service] = original_id
    (folder / 'images-ghcr.json').write_text(json.dumps(source, indent=2) + '\n')
    (folder / 'images.json').write_text(json.dumps(result, indent=2) + '\n')
    (folder / 'mirror.json').write_text(json.dumps(dict(source_run_id=run_id, registry='docker.io',
        private=True, anonymous_pull='denied', identical_image_ids=identities), indent=2) + '\n')


if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as error:
        raise SystemExit(f'Docker Hub API HTTP {error.code}: {getattr(error, "safe_detail", "Request rejected")}')
