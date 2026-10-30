"""Narrow Compose Redis fence adapter under development; not wired to updater.

Trusted boundary: installation owner, controller process, Docker daemon and host
administrators. Caller must hold uterctl's O_EXCL operation lock. Errors after
Docker mutations mean an unknown outcome; the authenticated plan and journal
must be retained. This adapter does not establish session ownership or permit
an epoch transition. It is not ready for production until integration/failure
tests on the exact published installation have succeeded.
"""
import json
import os
from pathlib import Path
import re
import stat

import uterctl
from scripts import compose_fence_recovery_plan as plans, compose_redis_diagnostic as diagnostic
from scripts import install, install_recovery


class ComposeFenceAdapterError(ValueError):
    pass


class Adapter:
    def __init__(self, home, bundle, publisher_key, backup_key):
        self.home = Path(home)
        self.bundle = Path(bundle)
        self.publisher_key = Path(publisher_key)
        self.backup_key = backup_key

    def _run(self, *args):
        try:
            return install_recovery.run_readonly(['docker', '--context', 'default', *map(str, args)], timeout=30).strip()
        except Exception:
            raise ComposeFenceAdapterError('COMPOSE_FENCE_DOCKER_UNCERTAIN') from None

    def _json(self, *args):
        try: return json.loads(self._run(*args))
        except ComposeFenceAdapterError: raise
        except (ValueError, TypeError):
            raise ComposeFenceAdapterError('COMPOSE_FENCE_INSPECTION_FAILED') from None

    def _plan(self, record):
        try:
            return plans.read(self.home, self.backup_key, record['plan_sha256'], operation=record['operation'],
                              site=record['site'], resource=record['resource'])
        except Exception:
            raise ComposeFenceAdapterError('COMPOSE_FENCE_PLAN_INVALID') from None

    def _lock(self):
        try:
            fd = os.open(self.home/'operation.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as source:
                info = os.fstat(source.fileno())
                value = source.read(32)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                        or info.st_mode & 0o077 or value != str(os.getpid()).encode()):
                    raise ValueError
        except (OSError, ValueError):
            raise ComposeFenceAdapterError('COMPOSE_FENCE_LOCK_INVALID') from None

    def _signed(self, plan):
        try:
            self._lock()
            signed = uterctl.verify(self.bundle, self.publisher_key)
            installed = self.home/'releases'/signed['version']
            state = uterctl.read(self.home/'state.json')
            cfg = uterctl.read(self.home/'install.json')
            site = uterctl.site_config(self.home)
            if (os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT', 'default') not in ('', 'default')
                    or self._json('context', 'inspect', 'default', '--format', '{{json .Endpoints.docker.Host}}') != 'unix:///var/run/docker.sock'
                    or uterctl.verify(installed, self.publisher_key) != signed
                    or (installed/'checksums.json').read_bytes() != (self.bundle/'checksums.json').read_bytes()
                    or state.get('current') != signed or state.get('pending') is not None
                    or state.get('adopted_installer') is not True or cfg.get('backend') != 'compose'
                    or cfg.get('context') != 'default' or cfg.get('name') != plan['site']
                    or cfg.get('images') != signed['images'] or signed['images']['redis'] != plan['image_ref']
                    or site.get('name') != plan['site'] or site.get('namespace') != plan['site']
                    or site.get('backend') != 'compose' or site.get('context') != 'default'):
                raise ValueError
            identity = self._json('inspect', '--format',
                '{"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}}}',
                plan['container_id'])
            if identity != {'project': plan['site'], 'service': 'redis'}: raise ValueError
            image = self._json('image', 'inspect', '--format', '{{json .Id}}', plan['image_ref'])
            if image != plan['image_config_id']: raise ValueError
            if signed.get('image_config_ids') and signed['image_config_ids'].get('redis') != image:
                digest = plan['image_ref'].rsplit('@', 1)[-1]
                if image != digest or self._json('image', 'inspect', '--format', '{{json .Descriptor.Digest}}', plan['image_ref']) != digest:
                    raise ValueError
            command, env = install.commands(self.home, cfg)
            command[command.index('-f')+1] = str(installed/'compose/compose.yaml')
            for service in ('guardrail', 'agent'):
                raw = install_recovery.run_readonly(command + ['ps', '-aq', service], timeout=30, env=env).strip()
                if not re.fullmatch(r'[0-9a-f]{12,64}', raw): raise ValueError
                state = self._json('inspect', '--format',
                    '{"running":{{json .State.Running}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}}}', raw)
                if state != {'running': False, 'project': plan['site'], 'service': service}: raise ValueError
        except ComposeFenceAdapterError: raise
        except Exception:
            raise ComposeFenceAdapterError('COMPOSE_FENCE_IDENTITY_INVALID') from None

    def _state(self, plan, *, detached, restart):
        state = diagnostic._redis_inspect(plan['container_id'])
        networks = state.get('networks')
        if (state.get('id') != plan['container_id'] or state.get('running') is not True
                or state.get('started') != plan['started_at'] or state.get('restart_count') != plan['restart_count']
                or type(state.get('pid')) is not int or state['pid'] <= 0
                or state.get('image') != plan['image_ref'] or state.get('image_id') != plan['image_config_id']
                or state.get('restart') != restart or state.get('privileged') is not False
                or state.get('network_mode') != plan['network_name']
                or state.get('pid_mode') not in ('', None) or state.get('cap_add') not in (None, [])
                or state.get('ports') or state.get('publish_all') is not False
                or not isinstance(state.get('runtime_ports'), dict)
                or any(x not in (None, []) for x in state['runtime_ports'].values())
                or not isinstance(state.get('mounts'), list) or not isinstance(networks, dict)):
            raise ComposeFenceAdapterError('COMPOSE_FENCE_REDIS_CHANGED')
        data = [m for m in state['mounts'] if isinstance(m, dict) and m.get('Destination') == '/data']
        if len(data) != 1 or data[0].get('Type') != 'volume' or data[0].get('Name') != plan['volume_name'] or data[0].get('RW') is not True:
            raise ComposeFenceAdapterError('COMPOSE_FENCE_VOLUME_CHANGED')
        if detached:
            if networks: raise ComposeFenceAdapterError('COMPOSE_FENCE_NETWORK_CHANGED')
        else:
            if set(networks) != {plan['network_name']}: raise ComposeFenceAdapterError('COMPOSE_FENCE_NETWORK_CHANGED')
            endpoint = networks[plan['network_name']]
            if (endpoint.get('NetworkID') != plan['network_id'] or endpoint.get('IPAddress') != plan['endpoint_ipv4']
                    or endpoint.get('MacAddress', '').lower() != plan['endpoint_mac']
                    or set(endpoint.get('Aliases') or []) != set(plan['endpoint_aliases'])):
                raise ComposeFenceAdapterError('COMPOSE_FENCE_NETWORK_CHANGED')
        return state

    def _network_and_volume(self, plan):
        network = self._json('network', 'inspect', '--format',
            '{"id":{{json .Id}},"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},'
            '"internal":{{json .Internal}},"ipv6":{{json .EnableIPv6}},"options":{{json .Options}},'
            '"ipam":{{json .IPAM}},"project":{{json (index .Labels "com.docker.compose.project")}},'
            '"network":{{json (index .Labels "com.docker.compose.network")}}}', plan['network_id'])
        if (not isinstance(network, dict) or network.get('id') != plan['network_id']
                or network.get('name') != plan['network_name'] or network.get('driver') != 'bridge'
                or network.get('scope') != 'local' or network.get('internal') is not True
                or network.get('ipv6') is not False or network.get('options') not in ({}, None)
                or network.get('project') != plan['site'] or network.get('network') != 'backend'):
            raise ComposeFenceAdapterError('COMPOSE_FENCE_NETWORK_CHANGED')
        ipam = network.get('ipam')
        if (not isinstance(ipam, dict) or ipam.get('Driver') != 'default' or ipam.get('Options') not in ({}, None)
                or not isinstance(ipam.get('Config'), list) or len(ipam['Config']) != 1):
            raise ComposeFenceAdapterError('COMPOSE_FENCE_NETWORK_CHANGED')
        config = ipam['Config'][0]
        if (not isinstance(config, dict) or config.get('Subnet') != plan['network_subnet']
                or config.get('Gateway') != plan['network_gateway']
                or config.get('IPRange') or config.get('AuxiliaryAddresses')):
            raise ComposeFenceAdapterError('COMPOSE_FENCE_NETWORK_CHANGED')
        volume = self._json('volume', 'inspect', '--format',
            '{"name":{{json .Name}},"driver":{{json .Driver}},"options":{{json .Options}},'
            '"project":{{json (index .Labels "com.docker.compose.project")}},'
            '"volume":{{json (index .Labels "com.docker.compose.volume")}}}', plan['volume_name'])
        diagnostic._require_volume(volume, plan['site'], plan['volume_name'])

    def _peers(self, plan):
        # Inspect only network mode and volume names, never Config.Env or mount contents.
        ids = self._run('ps', '--quiet', '--no-trunc').splitlines()
        if len(ids) > 10000 or any(not re.fullmatch(r'[0-9a-f]{64}', item) for item in ids):
            raise ComposeFenceAdapterError('COMPOSE_FENCE_PEERS_UNKNOWN')
        for item in ids:
            if item == plan['container_id']: continue
            val = self._json('inspect', '--format', '{"mode":{{json .HostConfig.NetworkMode}},"mounts":{{json .Mounts}}}', item)
            mode = val.get('mode') if isinstance(val, dict) else None
            mounts = val.get('mounts') if isinstance(val, dict) else None
            if not isinstance(mode, str) or not isinstance(mounts, list): raise ComposeFenceAdapterError('COMPOSE_FENCE_PEERS_UNKNOWN')
            if any(isinstance(m, dict) and m.get('Type') == 'volume' and m.get('Name') == plan['volume_name'] for m in mounts):
                raise ComposeFenceAdapterError('COMPOSE_FENCE_SHARED_VOLUME')
            if mode.startswith('container:'):
                target = self._json('inspect', '--format', '{{json .Id}}', mode[len('container:'):])
                if target == plan['container_id']: raise ComposeFenceAdapterError('COMPOSE_FENCE_SHARED_NAMESPACE')

    def _redis(self, plan, *args):
        # All arguments are fixed by this module. Password stays inside container.
        import shlex
        cmd = 'export REDISCLI_AUTH="$(cat /run/secrets/redis_password)"; exec redis-cli --raw ' + ' '.join(shlex.quote(x) for x in args)
        return self._run('exec', plan['container_id'], 'sh', '-ec', cmd)

    def _redis_config(self, plan):
        if self._redis(plan, 'CONFIG', 'GET', 'unixsocket').strip() != 'unixsocket':
            raise ComposeFenceAdapterError('COMPOSE_FENCE_UNIX_SOCKET_UNSUPPORTED')
        info = self._redis(plan, 'INFO', 'replication')
        lines = {x.strip() for x in info.splitlines()}
        if 'role:master' not in lines or 'connected_slaves:0' not in lines:
            raise ComposeFenceAdapterError('COMPOSE_FENCE_REPLICATION_UNSUPPORTED')
        persistence = {x.strip() for x in self._redis(plan, 'INFO', 'persistence').splitlines()}
        if 'aof_enabled:1' not in persistence or 'aof_last_write_status:ok' not in persistence:
            raise ComposeFenceAdapterError('COMPOSE_FENCE_AOF_UNHEALTHY')

    def _no_other_clients(self, plan):
        result = self._redis(plan, 'CLIENT', 'LIST')
        lines = [line for line in result.splitlines() if line.strip()]
        if len(lines) != 1 or not re.search(r'(?:^| )flags=[^ ]*N[^ ]*(?: |$)', lines[0]):
            raise ComposeFenceAdapterError('COMPOSE_FENCE_CLIENTS_REMAIN')

    def verify_preconditions(self, record):
        plan = self._plan(record)
        self._signed(plan)
        self._state(plan, detached=False, restart='unless-stopped')
        self._network_and_volume(plan)
        self._peers(plan)
        self._redis_config(plan)
        return True

    def disable_restart(self, record):
        plan = self._plan(record); self._lock()
        self._state(plan, detached=False, restart='unless-stopped')
        self._run('update', '--restart=no', plan['container_id'])
        self._state(plan, detached=False, restart='no')

    def disconnect_network(self, record):
        plan = self._plan(record); self._lock()
        self._state(plan, detached=False, restart='no')
        self._run('network', 'disconnect', plan['network_id'], plan['container_id'])
        self._state(plan, detached=True, restart='no')

    def close_external_clients(self, record):
        plan = self._plan(record); self._lock()
        self._state(plan, detached=True, restart='no'); self._peers(plan)
        for kind in ('normal', 'pubsub', 'replica', 'master'):
            response = self._redis(plan, 'CLIENT', 'KILL', 'TYPE', kind, 'SKIPME', 'yes')
            if not re.fullmatch(r'[0-9]+', response):
                raise ComposeFenceAdapterError('COMPOSE_FENCE_CLIENT_KILL_FAILED')
        self._no_other_clients(plan)

    def verify_isolated(self, record):
        plan = self._plan(record); self._signed(plan)
        self._state(plan, detached=True, restart='no'); self._network_and_volume(plan); self._peers(plan)
        self._redis_config(plan); self._no_other_clients(plan)
        self._state(plan, detached=True, restart='no')
        return True

    def verify_old_restoration_safe(self, record):
        # Automatic reconnect is not implemented until the exact dynamic-IP
        # rollback and possible out-of-band writes have been proved in CI.
        return False

    def restore_old_configuration(self, record):
        raise ComposeFenceAdapterError('COMPOSE_FENCE_RESTORE_UNSUPPORTED')

    def verify_old_restored(self, record):
        return False
