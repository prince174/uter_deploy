"""Experimental Redis ACL exclusion primitive, not a production fence.

The caller must provide one persistent, authenticated admin connection, a
durable write-once intent recorder and independently pinned Redis identity.
This does not prove network/admission isolation, Redis persistence or recovery.
"""
import re

_MINIMAL=frozenset(('+ping','+get','+set'))
_UTER_TEST=_MINIMAL | frozenset('''+del +eval +incr +ttl +expire +lpush +ltrim +lrange
    +multi +exec +discard +smembers +sismember +scard +sadd +srem
    +hgetall +hexists +hlen +hset +hdel +client|setinfo'''.split())

class ACLExperimentError(ValueError):
    pass


def _fields(raw):
    if not isinstance(raw, str) or len(raw) > 262144:
        raise ValueError
    result = {}
    for line in raw.splitlines():
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition(':')
        if not sep or not key or key in result:
            raise ValueError
        result[key] = value
    return result


def _clients(raw, admin_id, admin_user, *, only_admin):
    if not isinstance(raw, str) or len(raw) > 262144:
        raise ValueError
    seen = set()
    for line in raw.splitlines():
        fields = {}
        for token in line.split():
            key, sep, value = token.partition('=')
            if not sep or not key or key in fields:
                raise ValueError
            fields[key] = value
        ident, user = fields.get('id'), fields.get('user')
        if not isinstance(ident, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', ident) or ident in seen:
            raise ValueError
        seen.add(ident)
        if ident == admin_id:
            if user != admin_user:
                raise ValueError
        elif only_admin or user != 'default':
            raise ValueError
    if admin_id not in seen:
        raise ValueError
    return frozenset(seen-{admin_id})


def _default_user(execute, *, disabled, profile):
    info = execute('ACL', 'GETUSER', 'default')
    if not isinstance(info, dict) or not isinstance(info.get('flags'), list):
        raise ValueError
    flags = info['flags']
    if (any(not isinstance(x,str) for x in flags) or len(flags)!=len(set(flags))
            or ('off' in flags) != disabled or ('on' in flags) == disabled or 'nopass' in flags):
        raise ValueError
    passwords = info.get('passwords')
    if (not isinstance(passwords, list) or len(passwords)!=1
            or any(not isinstance(x, str) or not re.fullmatch(r'[0-9a-f]{64}', x) for x in passwords)
            or info.get('selectors') != []):
        raise ValueError
    commands = info.get('commands')
    if not isinstance(commands, str):
        raise ValueError
    tokens = commands.split()
    allowed = {'minimal-ci':_MINIMAL, 'uter-selected-ci':_UTER_TEST}.get(profile)
    if (not tokens or tokens[0] != '-@all' or len(tokens) != len(set(tokens))
            or allowed is None or set(tokens[1:]) != allowed):
        raise ValueError


def _observe(execute, admin_user, expected_run_id, expected_client_id, *, disabled, profile):
    server = _fields(execute('INFO', 'SERVER'))
    replication = _fields(execute('INFO', 'REPLICATION'))
    persistence = _fields(execute('INFO', 'PERSISTENCE'))
    if (server.get('run_id') != expected_run_id or replication.get('role') != 'master'
            or replication.get('connected_slaves') != '0'
            or persistence.get('loading') != '0' or persistence.get('aof_enabled') != '1'
            or persistence.get('aof_rewrite_in_progress') != '0'
            or persistence.get('rdb_bgsave_in_progress') != '0'
            or persistence.get('aof_last_write_status') != 'ok'
            or execute('MODULE', 'LIST') != [] or execute('FUNCTION', 'LIST') != []
            or str(execute('CLIENT', 'ID')) != expected_client_id):
        raise ValueError
    users = execute('ACL', 'USERS')
    if not isinstance(users, list) or sorted(users) != sorted(['default', admin_user]):
        raise ValueError
    _default_user(execute, disabled=disabled, profile=profile)


def _args(execute, admin_user, expected_run_id, expected_client_id):
    if (not callable(execute) or not isinstance(admin_user, str)
            or not re.fullmatch(r'uter-maint-[a-z0-9]{1,24}', admin_user)
            or not isinstance(expected_run_id, str) or not re.fullmatch(r'[0-9a-f]{40}', expected_run_id)
            or not isinstance(expected_client_id, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', expected_client_id)):
        raise ValueError


def inspect_after_failure(execute, *, admin_user, expected_run_id, expected_client_id,
                          recorded_intents, profile='minimal-ci'):
    """Observe a failed fixture operation; do not retry, restore or authorize."""
    try:
        _args(execute, admin_user, expected_run_id, expected_client_id)
        if (not isinstance(recorded_intents, frozenset) or not recorded_intents
                or not recorded_intents <= {'disable-default','kill-default'}
                or 'disable-default' not in recorded_intents):
            raise ValueError
        first=execute('ACL','GETUSER','default')
        flags=first.get('flags') if isinstance(first,dict) else None
        if not isinstance(flags,list) or ('off' in flags) == ('on' in flags): raise ValueError
        disabled='off' in flags
        _observe(execute,admin_user,expected_run_id,expected_client_id,disabled=disabled,profile=profile)
        clients=_clients(execute('CLIENT','LIST'),expected_client_id,admin_user,only_admin=False)
        _observe(execute,admin_user,expected_run_id,expected_client_id,disabled=disabled,profile=profile)
        if _clients(execute('CLIENT','LIST'),expected_client_id,admin_user,only_admin=False) != clients: raise ValueError
        state='default_on_uncertain' if not disabled else ('default_off_clients_present' if clients else 'default_off_only_admin')
        return {'observation':state,'retry_allowed':False,'recovery_automated':False,
                'safe_to_backup':False,'safe_to_update':False}
    except Exception:
        raise ACLExperimentError('REDIS_ACL_EXPERIMENT_INSPECTION_UNVERIFIED') from None


def run(execute, *, admin_user, expected_run_id, expected_client_id, record_intent, profile='minimal-ci'):
    """Disable default, disconnect its existing clients and observe exclusion.

    Every Redis command uses the same admin connection. Repeating this function
    after an uncertain outcome is forbidden unless external recovery has
    independently classified that outcome. The supplied intent recorder must
    durably reject repeated stages; these callbacks are not a production lock.
    """
    try:
        _args(execute, admin_user, expected_run_id, expected_client_id)
        if not callable(record_intent): raise ValueError
        def observe(*, disabled=False):
            _observe(execute, admin_user, expected_run_id, expected_client_id, disabled=disabled, profile=profile)
        def intent(stage):
            if record_intent(stage) is not True:
                raise ValueError
        observe()
        _clients(execute('CLIENT', 'LIST'), expected_client_id, admin_user, only_admin=False)
        intent('disable-default')
        if execute('ACL', 'SETUSER', 'default', 'off') != 'OK':
            raise ValueError
        observe(disabled=True)
        intent('kill-default')
        count = execute('CLIENT', 'KILL', 'USER', 'default', 'SKIPME', 'yes')
        if type(count) is not int or count < 0:
            raise ValueError
        observe(disabled=True)
        _clients(execute('CLIENT', 'LIST'), expected_client_id, admin_user, only_admin=True)
        observe(disabled=True)
        return {'default_disabled':True, 'default_clients_killed':count,
                'observed_only_admin':True, 'safe_to_backup':False, 'safe_to_update':False}
    except Exception:
        raise ACLExperimentError('REDIS_ACL_EXPERIMENT_UNVERIFIED') from None
