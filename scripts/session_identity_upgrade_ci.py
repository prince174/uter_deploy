"""Read-only identity-compatibility probes for disposable release-upgrade CI.

Execute real user JWT chat calls, inspect only synthetic Redis session metadata,
and never print JWTs, runtime secrets, requests, responses, or session records.
No automatic migration or merging of old user-provided aliases is attempted.
"""
import json
import re
import subprocess
import urllib.error
import urllib.request


class SessionCheckFailure(Exception):
    """A fixed, non-sensitive category."""


SUBJECTS = ('ci-identity-alice', 'ci-identity-bob', 'ci-identity-canonical')
CHAT_ALIAS = 'ci-identity-shared-chat'
OPENAI_ALIAS = 'ci-identity-shared-openai'
MARKERS = ('ci-alpha-turn', 'ci-beta-turn', 'ci-canonical-turn')
KEYS = (
    'sess:ci-identity-alice:ci-identity-shared-chat',
    'sess:ci-identity-bob:ci-identity-shared-chat',
    'sess:ci-identity-shared-openai',
    'sess:ci-identity-canonical',
    'sess:ci-identity-alice',
    'sess:ci-identity-bob',
)
_REDIS_PROBE = '''import hashlib,json,redis
from redis_config import load_redis_connection_settings
r=redis.Redis(**load_redis_connection_settings().client_kwargs())
keys=KEYS
out={}
for key in keys:
 values=r.lrange(key,0,-1)
 digest=hashlib.sha256(b'\\x00'.join(values)).hexdigest()
 own=sum(1 for x in values if OWN.encode() in x)
 other=sum(1 for x in values if OTHER.encode() in x)
 out[key]={'length':len(values),'digest':digest,'ttl':r.ttl(key),'own':own,'other':other}
print(json.dumps(out))
'''
_TOKENS = '''import json
from auth import create_access_token
print(json.dumps({name:create_access_token(name,'user') for name in SUBJECTS}))
'''


def container_command(cmd, env, program):
    try:
        result = subprocess.run([str(x) for x in cmd], input=program.encode(), env=env,
                                capture_output=True, timeout=60, check=True)
        if len(result.stdout) > 65536:
            raise ValueError
        return json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SessionCheckFailure('SESSION_CONTAINER_PROBE_FAILED') from None


def tokens(cmd, env):
    value = container_command(cmd, env, 'SUBJECTS='+repr(SUBJECTS)+'\n'+_TOKENS)
    if not isinstance(value, dict) or set(value) != set(SUBJECTS) or not all(
            isinstance(item, str) and re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', item)
            for item in value.values()):
        raise SessionCheckFailure('SESSION_TOKEN_FAILED')
    return value


def snapshot(cmd, env):
    result = container_command(cmd, env, 'KEYS='+repr(KEYS)+'\nOWN='+repr(MARKERS[0])+'\nOTHER='+repr(MARKERS[1])+'\n'+_REDIS_PROBE)
    if not isinstance(result, dict) or set(result) != set(KEYS):
        raise SessionCheckFailure('SESSION_SNAPSHOT_INVALID')
    for data in result.values():
        if (not isinstance(data, dict) or set(data) != {'length','digest','ttl','own','other'}
                or not all(type(data[name]) is int for name in ('length','ttl','own','other'))
                or data['length'] < 0 or data['own'] < 0 or data['other'] < 0
                or not isinstance(data['digest'], str) or not re.fullmatch('[0-9a-f]{64}',data['digest'])):
            raise SessionCheckFailure('SESSION_SNAPSHOT_INVALID')
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def post(path, token, payload, ingress=None):
    headers = {'Authorization':'Bearer '+token, 'Content-Type':'application/json'}
    if ingress is not None:
        headers['X-Uter-Ingress-Secret'] = ingress
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        req = urllib.request.Request('http://127.0.0.1:18000'+path,
                                     data=json.dumps(payload).encode(), headers=headers)
        with opener.open(req, timeout=120) as response:
            raw = response.read(1024*1024+1)
        if len(raw) > 1024*1024 or not isinstance(json.loads(raw),dict):
            raise ValueError
    except urllib.error.HTTPError as error:
        error.close()
        raise SessionCheckFailure('SESSION_CHAT_FAILED') from None
    except (OSError, ValueError, urllib.error.URLError):
        raise SessionCheckFailure('SESSION_CHAT_FAILED') from None


def send_turns(cmd, env, ingress):
    creds = tokens(cmd, env)
    # Same untrusted alias for two different authenticated principals.
    for index in (0,1):
        post('/chat', creds[SUBJECTS[index]],
             {'message':'Please say hello. '+MARKERS[index], 'user_id':CHAT_ALIAS})
    post('/chat', creds[SUBJECTS[2]],
         {'message':'Please say hello. '+MARKERS[2], 'user_id':SUBJECTS[2]})
    # Legacy OpenAI used request.user directly; verify the shared alias separately.
    for index in (0,1):
        post('/v1/chat/completions', creds[SUBJECTS[index]],
             {'model':'uter-guardrail-chat', 'user':OPENAI_ALIAS,
              'messages':[{'role':'user','content':'Please say hello. '+MARKERS[index]}]}, ingress)


def prepare_baseline(cmd, env, ingress):
    empty = snapshot(cmd, env)
    if any(item['length'] for item in empty.values()):
        raise SessionCheckFailure('SESSION_KEYS_ALREADY_EXIST')
    send_turns(cmd, env, ingress)
    before = snapshot(cmd, env)
    if (before[KEYS[0]]['length'] < 2 or before[KEYS[1]]['length'] < 2
            or before[KEYS[2]]['length'] < 4 or before[KEYS[3]]['length'] < 2
            or before[KEYS[4]]['length'] or before[KEYS[5]]['length']):
        raise SessionCheckFailure('SESSION_OLD_BEHAVIOR_UNEXPECTED')
    return before


def verify_after_update(cmd, env, ingress, before):
    # Ensure old physical values were not damaged before exercising updated routes.
    persisted = snapshot(cmd, env)
    for key in KEYS[:4]:
        if persisted[key]['length'] != before[key]['length'] or persisted[key]['digest'] != before[key]['digest'] or persisted[key]['ttl'] <= 0:
            raise SessionCheckFailure('SESSION_DATA_NOT_PRESERVED')
    send_turns(cmd, env, ingress)
    after = snapshot(cmd, env)
    # Legacy aliases remain untouched; canonical account continues its own history.
    for key in KEYS[:3]:
        if after[key]['length'] != before[key]['length'] or after[key]['digest'] != before[key]['digest']:
            raise SessionCheckFailure('LEGACY_SESSION_CHANGED')
    if after[KEYS[3]]['length'] <= before[KEYS[3]]['length']:
        raise SessionCheckFailure('CANONICAL_SESSION_NOT_CONTINUED')
    alice, bob = after[KEYS[4]], after[KEYS[5]]
    if (alice['length'] < 4 or bob['length'] < 4 or alice['own'] < 2 or alice['other'] != 0
            or bob['other'] < 2 or bob['own'] != 0):
        raise SessionCheckFailure('SESSION_PRINCIPALS_NOT_ISOLATED')
    return {'canonical_history_continues':'pass', 'legacy_alias_data_physically_preserved':'pass',
            'legacy_alias_history_automatically_accessible':'no', 'new_principals_isolated':'pass',
            'legacy_openai_shared_alias_exists':'yes', 'automatic_alias_merge':'not performed'}


def verify_restored(cmd, env, expected):
    restored = snapshot(cmd, env)
    for key in KEYS:
        if (restored[key]['length'] != expected[key]['length']
                or restored[key]['digest'] != expected[key]['digest']
                or (expected[key]['length'] and restored[key]['ttl'] <= 0)):
            raise SessionCheckFailure('SESSION_RESTORE_NOT_PRESERVED')
