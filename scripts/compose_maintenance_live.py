"""Read-only, momentary inspection of an experimental Compose profile.

Root, the kernel, local Docker daemon, administrators and the signed executor
are trusted. This module does not execute inside workloads, send maintenance
requests, establish fencing, count Python workers, back up, restore or update.
"""
import json
import os
from pathlib import Path
import posixpath
import re

from scripts import (backup_snapshot, compose_fence_start, compose_maintenance_profile,
                     compose_maintenance_secret, compose_nsfirewall_adapter,
                     compose_redis_diagnostic as docker, redis_fence_journal, workload_preflight)

_EXPECTED_ENV = {'UTER_MAINTENANCE_ENABLED=true',
                 'UTER_MAINTENANCE_KEY_FILE=/run/uter-maintenance/key', 'WEB_CONCURRENCY=1'}
_KEY_TARGET = '/run/uter-maintenance/key'
_ID = re.compile(r'[0-9a-f]{64}\Z')
_ENV_TEMPLATE = ('{{range .Config.Env}}{{if or (eq (index (split . "=") 0) "UTER_MAINTENANCE_ENABLED") '
                 '(eq (index (split . "=") 0) "UTER_MAINTENANCE_KEY_FILE") '
                 '(eq (index (split . "=") 0) "WEB_CONCURRENCY")}}{{json .}},{{end}}{{end}}"__end__"')
_CONTAINER_FORMAT = ('{"id":{{json .Id}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},'
                     '"started":{{json .State.StartedAt}},"restart_count":{{json .RestartCount}},'
                     '"restart":{{json .HostConfig.RestartPolicy.Name}},"image_ref":{{json .Config.Image}},'
                     '"image_id":{{json .Image}},"user":{{json .Config.User}},'
                     '"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},'
                     '"privileged":{{json .HostConfig.Privileged}},"pid_mode":{{json .HostConfig.PidMode}},'
                     '"readonly_root":{{json .HostConfig.ReadonlyRootfs}},"mounts":{{json .Mounts}},'
                     '"selected_env":['+_ENV_TEMPLATE+']}')
_IMAGE_FORMAT = '{"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}}}'


class LiveProfileError(ValueError):
    pass


def _snapshot(service, expected, home):
    """Select bounded Docker metadata and validate a single writer snapshot."""
    ident = expected.get('id')
    if not isinstance(ident,str) or not _ID.fullmatch(ident):raise ValueError
    state = docker._json(docker._docker('inspect','--format',_CONTAINER_FORMAT,ident))
    if not isinstance(state,dict):raise ValueError
    image = docker._json(docker._docker('image','inspect','--format',_IMAGE_FORMAT,expected['image_id']))
    selected = state.get('selected_env')
    if (not isinstance(selected,list) or len(selected)!=4 or selected[-1]!='__end__'
            or any(not isinstance(x,str) for x in selected[:-1]) or set(selected[:-1])!=_EXPECTED_ENV):
        raise ValueError
    if (state.get('id')!=ident or state.get('running') is not True
            or type(state.get('pid')) is not int or state['pid']<=0
            or state.get('started')!=expected['started'] or state.get('restart_count')!=expected['restart_count']
            or state.get('image_ref')!=expected['image_ref'] or state.get('image_id')!=expected['image_id']
            or state.get('restart')!='unless-stopped' or state.get('user')!='10001:10001'
            or state.get('privileged') is not False or state.get('pid_mode') not in ('',None)
            or state.get('readonly_root') is not True or not isinstance(image,dict)
            or state.get('entrypoint')!=image.get('entrypoint') or state.get('cmd')!=image.get('cmd')):
        raise ValueError
    mounts=state.get('mounts')
    if not isinstance(mounts,list) or len(mounts)>128:raise ValueError
    found=[]
    for mount in mounts:
        if not isinstance(mount,dict):raise ValueError
        destination=mount.get('Destination')
        if (not isinstance(destination,str) or not destination.startswith('/') or destination.startswith('//')
                or posixpath.normpath(destination)!=destination or destination=='/'):
            raise ValueError
        if destination==_KEY_TARGET:
            found.append(mount)
        elif (_KEY_TARGET.startswith(destination+'/') or destination.startswith(_KEY_TARGET+'/')):
            raise ValueError
    if (len(found)!=1 or found[0].get('Type')!='bind' or found[0].get('RW') is not False
            or found[0].get('Source')!=str(home/'runtime'/'maintenance-key')):
        raise ValueError
    # The snapshot is internal: never return command, mounts, env or image refs.
    return state, image


def check(home, bundle, publisher, backup_key):
    """Check a prepared signed profile and exact live container snapshots only."""
    adapter=None
    try:
        home=Path(home)
        if not home.is_absolute():raise ValueError
        backup_snapshot._require_fenced_operation_lock(home)
        if redis_fence_journal.blocks_mutation(home):raise ValueError
        config_path=home/'install.json'
        config_raw=workload_preflight.read_trusted_file(config_path,65536,secret=False,error='CONFIG_UNVERIFIED')
        cfg=json.loads(config_raw)
        compose_maintenance_profile.verify(bundle,publisher,home,cfg)
        key=compose_maintenance_secret.read_key(home/'runtime')
        adapter=compose_nsfirewall_adapter.Adapter(home,bundle,publisher,backup_key)
        plan,writers,bundle_hash=compose_fence_start._observe(home,bundle,publisher,backup_key,adapter)
        first={service:_snapshot(service,writers[service],home) for service in ('agent','guardrail')}
        second={service:_snapshot(service,writers[service],home) for service in ('agent','guardrail')}
        new_plan,new_writers,new_hash=compose_fence_start._observe(home,bundle,publisher,backup_key,adapter)
        new_plan=dict(new_plan,operation=plan['operation'])
        if (first!=second or new_plan!=plan or new_writers!=writers or new_hash!=bundle_hash
                or redis_fence_journal.blocks_mutation(home)
                or compose_maintenance_secret.read_key(home/'runtime')!=key
                or workload_preflight.read_trusted_file(config_path,65536,secret=False,error='CONFIG_UNVERIFIED')!=config_raw):
            raise ValueError
        compose_maintenance_profile.verify(bundle,publisher,home,cfg)
        backup_snapshot._require_fenced_operation_lock(home)
        return {'backend':'compose','writers_observed':2,'profile_snapshots_match':True,
                'application_endpoint_checked':False,'single_worker_verified':False,
                'key_mount_identity_verified':False,
                'ingress_fenced':False,'restart_fenced':False,'redis_isolated':False,
                'safe_to_backup':False,'safe_to_update':False}
    except Exception:
        raise LiveProfileError('COMPOSE_MAINTENANCE_LIVE_UNVERIFIED') from None
    finally:
        if adapter is not None:
            try:adapter.close()
            except Exception:raise LiveProfileError('COMPOSE_MAINTENANCE_LIVE_UNVERIFIED') from None
