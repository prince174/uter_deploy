"""Experimental Redis ACL exclusion primitive, not a production fence.

The caller must provide one persistent, authenticated admin connection, a
durable write-once intent recorder and independently pinned Redis identity.
This does not prove network/admission isolation, Redis persistence or recovery.
"""
import re


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


def _default_user(execute, *, disabled):
    info = execute('ACL', 'GETUSER', 'default')
    if not isinstance(info, dict) or not isinstance(info.get('flags'), list):
        raise ValueError
    flags = info['flags']
    if ('off' in flags) != disabled or ('on' in flags) == disabled or 'nopass' in flags:
        raise ValueError
    passwords = info.get('passwords')
    if (not isinstance(passwords, list) or not passwords
            or any(not isinstance(x, str) or not re.fullmatch(r'[0-9a-f]{64}', x) for x in passwords)
            or info.get('selectors') != []):
        raise ValueError
    commands = info.get('commands')
    if not isinstance(commands, str):
        raise ValueError
    tokens = commands.split()
    # Deliberately narrow synthetic profile, not yet verified against Uter.
    # Categories, subcommands, admin commands and scripts all fail closed.
    if (not tokens or tokens[0] != '-@all' or len(tokens) != len(set(tokens))
            or any(token not in {'+ping', '+get', '+set'} for token in tokens[1:])):
        raise ValueError


def run(execute, *, admin_user, expected_run_id, expected_client_id, record_intent):
    """Disable default, disconnect its existing clients and observe exclusion.

    Every Redis command uses the same admin connection. Repeating this function
    after an uncertain outcome is forbidden unless external recovery has
    independently classified that outcome. The supplied intent recorder must
    durably reject repeated stages; these callbacks are not a production lock.
    """
    try:
        if (not callable(execute) or not callable(record_intent)
                or not isinstance(admin_user, str) or not re.fullmatch(r'uter-maint-[a-z0-9]{1,24}', admin_user)
                or not isinstance(expected_run_id, str) or not re.fullmatch(r'[0-9a-f]{40}', expected_run_id)
                or not isinstance(expected_client_id, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', expected_client_id)):
            raise ValueError
        def observe(*, disabled=False):
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
            _default_user(execute, disabled=disabled)
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
