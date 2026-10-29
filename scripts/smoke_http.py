"""Check a running HTTP endpoint with interactive credentials; never prints tokens."""
import argparse
import contextlib
import getpass
import json
import socket
import sys
import urllib.request
import urllib.parse
import urllib.error


class SmokeFailure(ValueError):
    """Fixed, non-sensitive failure reason for failed acceptance checks."""

    def __init__(self, category, message):
        super().__init__(message)
        self.category = category


def check(base, username, password, *, diagnostic=None):
    @contextlib.contextmanager
    def stage(name):
        try:
            yield
        except Exception as error:
            # Emit only fixed categories, never exception text, response bodies,
            # URLs, tokens or other values supplied by a service.
            if isinstance(error, urllib.error.HTTPError):
                category = 'HTTP_' + (str(error.code) if error.code in
                    (400, 401, 403, 404, 408, 409, 422, 429, 500, 502, 503, 504) else 'OTHER')
            elif isinstance(error, (socket.timeout, TimeoutError)) or (
                    isinstance(error, urllib.error.URLError) and isinstance(error.reason, (socket.timeout, TimeoutError))):
                category = 'TIMEOUT'
            elif isinstance(error, urllib.error.URLError):
                category = 'NETWORK_FAILED'
            elif isinstance(error, SmokeFailure):
                category = error.category
            elif isinstance(error, (json.JSONDecodeError, KeyError, TypeError, AttributeError)):
                category = 'INVALID_RESPONSE'
            else:
                category = 'FAILED'
            if diagnostic is not None:
                diagnostic(name, category)
            raise

    def request(path, data=None, token=None, form=False):
        headers = {}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if data is not None:
            data = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        with urllib.request.urlopen(urllib.request.Request(base.rstrip('/') + path, data=data, headers=headers), timeout=60) as response:
            return json.load(response)
    with stage('READY'):
        request('/ready')
    with stage('AUTH'):
        auth = request('/auth/token', {'username': username, 'password': password}, form=True)
        token = auth['access_token']
    with stage('HEALTH'):
        health = request('/health', token=token)
        if not health['upstream_available'] or not health['agent_runtime_available'] or not health['toxicity_guard']['available']:
            raise SmokeFailure('NOT_READY', 'Required dependencies are not ready')
    with stage('CHAT'):
        answer = request('/chat', {'message': 'Explain safe software deployment.', 'user_id': 'installation-smoke'}, token=token)
        if answer.get('blocked') is not False:
            raise SmokeFailure('BLOCKED_OR_INVALID', 'Normal request was blocked; inspect runtime policy and LLM response')
    return {'ready': 'pass', 'login': 'pass', 'upstream': 'pass', 'agent': 'pass', 'toxicity': 'pass', 'chat': 'pass'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:18000')
    parser.add_argument('--username', default='admin')
    args = parser.parse_args()
    if not sys.stdin.isatty():
        parser.error('Interactive terminal required for hidden password entry')
    try:
        print(json.dumps(check(args.url, args.username, getpass.getpass('Password: ')), indent=2))
    except urllib.error.HTTPError as error:
        raise SystemExit(f'HTTP {error.code}; response omitted to protect confidential data')
    except (ValueError, urllib.error.URLError) as error:
        raise SystemExit(str(error))
