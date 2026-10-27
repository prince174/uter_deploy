"""Check a running HTTP endpoint with interactive credentials; never prints tokens."""
import argparse
import getpass
import json
import sys
import urllib.request
import urllib.parse
import urllib.error


def check(base, username, password):
    def request(path, data=None, token=None, form=False):
        headers = {}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if data is not None:
            data = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        with urllib.request.urlopen(urllib.request.Request(base.rstrip('/') + path, data=data, headers=headers), timeout=60) as response:
            return json.load(response)
    request('/ready')
    auth = request('/auth/token', {'username': username, 'password': password}, form=True)
    health = request('/health', token=auth['access_token'])
    if not health['upstream_available'] or not health['agent_runtime_available'] or not health['toxicity_guard']['available']:
        raise ValueError('Required dependencies are not ready')
    answer = request('/chat', {'message': 'Explain safe software deployment.', 'user_id': 'installation-smoke'}, token=auth['access_token'])
    if answer.get('blocked') is not False:
        raise ValueError('Normal request was blocked; inspect runtime policy and LLM response')
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
