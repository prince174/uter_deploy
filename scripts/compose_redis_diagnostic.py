"""Read-only Compose Redis diagnostic; not a fence and not an upgrade authorisation.

Inspects only an explicitly selected installation and signed release. Host/Docker
administrators, container runtimes, filesystem and operating system are trusted.
The result is a momentary diagnostic, not evidence that writers are stopped or
that a later operation is safe. Never automatically called by the update gate.
"""
import argparse
from collections import Counter
import json
import os
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import adopt_installation, install, install_recovery


class ComposeDiagnosticError(ValueError):
    """Fixed code, never runtime data or credentials."""


_ID = re.compile(r'[0-9a-f]{64}\Z')
_PROJECT = re.compile(r'[a-z][a-z0-9-]{0,40}\Z')


def _read(command, env=None):
    try:
        return install_recovery.run_readonly([str(x) for x in command], timeout=30, env=env)
    except Exception:
        raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_QUERY_FAILED') from None


def _json(command, env=None):
    try:
        return json.loads(_read(command, env))
    except ComposeDiagnosticError:
        raise
    except (ValueError, TypeError):
        raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_RESPONSE_INVALID') from None


def _docker(*args):
    return ['docker','--context','default',*args]


def _redis_inspect(container):
    # Never inspect full Config or process environment: they may contain secrets.
    fmt = ('{"id":{{json .Id}},"running":{{json .State.Running}},'
           '"pid":{{json .State.Pid}},"started":{{json .State.StartedAt}},'
           '"restart_count":{{json .RestartCount}},"image":{{json .Config.Image}},'
           '"image_id":{{json .Image}},"restart":{{json .HostConfig.RestartPolicy.Name}},'
           '"network_mode":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}},'
           '"publish_all":{{json .HostConfig.PublishAllPorts}},"runtime_ports":{{json .NetworkSettings.Ports}},'
           '"privileged":{{json .HostConfig.Privileged}},"pid_mode":{{json .HostConfig.PidMode}},'
           '"cap_add":{{json .HostConfig.CapAdd}},"mounts":{{json .Mounts}},'
           '"networks":{{json .NetworkSettings.Networks}}}')
    return _json(_docker('inspect','--format',fmt,container))


def _changed_state_class(before,after):
    """Classify a changed inspection without exposing any observed value.

    This is diagnostic only. It must not make two different inspections equal
    or authorize a mutation, including when a list has merely changed order.
    """
    if not isinstance(before,dict) or not isinstance(after,dict) or set(before)!=set(after):return 'OTHER'
    groups=(('PROCESS',('id','running','pid','started','restart_count','restart')),
            ('IMAGE',('image','image_id')),('SECURITY',('privileged','pid_mode','cap_add')),
            ('NETWORK_MODE',('network_mode',)),
            ('PORTS',('ports','publish_all','runtime_ports')))
    for name,fields in groups:
        if any(before.get(key)!=after.get(key) for key in fields):return name
    a,b=before.get('mounts'),after.get('mounts')
    if a!=b:
        try:
            if (isinstance(a,list) and isinstance(b,list)
                    and Counter(json.dumps(item,sort_keys=True,separators=(',',':')) for item in a)
                    ==Counter(json.dumps(item,sort_keys=True,separators=(',',':')) for item in b)):
                return 'MOUNTS_ORDER'
        except (TypeError,ValueError):pass
        return 'MOUNTS_CONTENT'
    left,right=before.get('networks'),after.get('networks')
    if left!=right:
        if not isinstance(left,dict) or not isinstance(right,dict) or set(left)!=set(right):return 'NETWORK_SET'
        for network in left:
            a,b=left[network],right[network]
            if not isinstance(a,dict) or not isinstance(b,dict) or set(a)!=set(b):return 'NETWORK_FIELDS'
            for key,label in (('NetworkID','NETWORK_ID'),('EndpointID','ENDPOINT_ID'),
                              ('IPAddress','ENDPOINT_ADDRESS'),('IPPrefixLen','ENDPOINT_ADDRESS'),
                              ('Gateway','ENDPOINT_GATEWAY'),('MacAddress','ENDPOINT_MAC'),
                              ('IPAMConfig','ENDPOINT_IPAM'),('DriverOpts','ENDPOINT_OPTIONS'),
                              ('IPv6Gateway','ENDPOINT_IPV6'),('GlobalIPv6Address','ENDPOINT_IPV6'),
                              ('GlobalIPv6PrefixLen','ENDPOINT_IPV6')):
                if a.get(key)!=b.get(key):return label
            for key,label in (('Aliases','ALIASES'),('DNSNames','DNSNAMES')):
                x,y=a.get(key),b.get(key)
                if x!=y:
                    try:
                        if isinstance(x,list) and isinstance(y,list) and Counter(x)==Counter(y):return label+'_ORDER'
                    except TypeError:pass
                    return label+'_CONTENT'
            if a!=b:return 'NETWORK_OTHER'
        return 'NETWORK_OTHER'
    return 'OTHER'


def _require_redis(state, project, expected_id, image):
    if not isinstance(state,dict): raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_REDIS_INVALID')
    netname=project+'_backend'; volname=project+'_redis-data'
    networks=state.get('networks'); mounts=state.get('mounts'); runtime_ports=state.get('runtime_ports')
    if (state.get('id')!=expected_id or not _ID.fullmatch(expected_id)
            or state.get('running') is not True or type(state.get('pid')) is not int or state['pid']<=0
            or not isinstance(state.get('started'),str) or not state['started'] or len(state['started'])>64
            or type(state.get('restart_count')) is not int or state['restart_count']<0
            or state.get('image')!=image or not isinstance(state.get('image_id'),str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',state['image_id'])
            or state.get('restart')!='unless-stopped' or state.get('network_mode')!=netname
            or state.get('ports') or state.get('publish_all') is not False
            or not isinstance(runtime_ports,dict) or any(value not in (None,[]) for value in runtime_ports.values())
            or state.get('privileged') is not False
            or state.get('pid_mode') not in ('',None) or state.get('cap_add') not in ([],None)
            or not isinstance(networks,dict) or set(networks)!={netname}
            or not isinstance(networks[netname],dict)
            or not isinstance(networks[netname].get('NetworkID'),str)
            or not _ID.fullmatch(networks[netname]['NetworkID'])
            or not isinstance(mounts,list)):
        raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_REDIS_INVALID')
    data=[m for m in mounts if isinstance(m,dict) and m.get('Destination')=='/data']
    if len(data)!=1 or data[0].get('Type')!='volume' or data[0].get('Name')!=volname or data[0].get('RW') is not True:
        raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_DATA_VOLUME_INVALID')
    return networks[netname]['NetworkID'],volname


def _require_network(data,project,netid):
    if (not isinstance(data,dict) or data.get('id')!=netid or data.get('driver')!='bridge'
            or data.get('internal') is not True or data.get('project')!=project or data.get('network')!='backend'
            or data.get('scope')!='local'):
        raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_NETWORK_INVALID')


def _require_volume(data,project,name):
    if (not isinstance(data,dict) or data.get('name')!=name or data.get('driver')!='local'
            or data.get('project')!=project or data.get('volume')!='redis-data'
            or data.get('options') not in ({},None)):
        raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_VOLUME_INVALID')


def inspect_installation(home, bundle, publisher_key):
    """Inspect a signed current Compose installation; never mutate it.

    Even success does not fence, disconnect clients, cover restart/crash, validate
    external writers, authorise backup/migration, or validate data provenance.
    Do not call against the developer's active stack.
    """
    try:
        home=Path(home).resolve(strict=True)
        signed=uterctl.verify(Path(bundle),Path(publisher_key))
        state=uterctl.read(home/'state.json')
        cfg=uterctl.read(home/'install.json')
        site=uterctl.site_config(home)
        name=cfg.get('name')
        if (not isinstance(state,dict) or state.get('current')!=signed or state.get('pending') is not None
                or state.get('adopted_installer') is not True or cfg.get('backend')!='compose'
                or cfg.get('context')!='default' or site.get('backend')!='compose'
                or site.get('context')!='default' or site.get('name')!=name or site.get('namespace')!=name
                or not isinstance(name,str) or not _PROJECT.fullmatch(name) or cfg.get('images')!=signed['images']
                or os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT','default') not in ('','default')):
            raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_IDENTITY_INVALID')
        if _json(_docker('context','inspect','default','--format','{{json .Endpoints.docker.Host}}'))!='unix:///var/run/docker.sock':
            raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_DAEMON_INVALID')
        installed=home/'releases'/signed['version']
        if (uterctl.verify(installed,Path(publisher_key))!=signed or
                (installed/'checksums.json').read_bytes()!=(Path(bundle)/'checksums.json').read_bytes()):
            raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_INSTALLED_BUNDLE_MISMATCH')
        adopt_installation.verify_live(home,cfg,signed)
        command,env=install.commands(home,cfg)
        command[command.index('-f')+1]=str(home/'releases'/signed['version']/'compose/compose.yaml')
        short=_read(command+['ps','-q','redis'],env).strip()
        if not re.fullmatch(r'[0-9a-f]{12,64}',short): raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_REDIS_INVALID')
        full=_json(_docker('inspect','--format','{{json .Id}}',short))
        if not isinstance(full,str) or not _ID.fullmatch(full): raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_REDIS_INVALID')
        first=_redis_inspect(full)
        net,volume=_require_redis(first,name,full,signed['images']['redis'])
        local_image=_json(_docker('image','inspect','--format','{{json .Id}}',signed['images']['redis']))
        if first.get('image_id')!=local_image:
            raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_IMAGE_CHANGED')
        if signed.get('image_config_ids') and local_image!=signed['image_config_ids']['redis']:
            # Some Docker stores represent the manifest digest as ID; check the
            # descriptor explicitly before accepting that representation.
            digest=signed['images']['redis'].rsplit('@',1)[-1]
            if local_image!=digest or _json(_docker('image','inspect','--format','{{json .Descriptor.Digest}}',signed['images']['redis']))!=digest:
                raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_IMAGE_CHANGED')
        network=_json(_docker('network','inspect','--format',
            '{"id":{{json .Id}},"driver":{{json .Driver}},"internal":{{json .Internal}},"scope":{{json .Scope}},'
            '"project":{{json (index .Labels "com.docker.compose.project")}},"network":{{json (index .Labels "com.docker.compose.network")}}}',net))
        _require_network(network,name,net)
        vol=_json(_docker('volume','inspect','--format',
            '{"name":{{json .Name}},"driver":{{json .Driver}},"options":{{json .Options}},'
            '"project":{{json (index .Labels "com.docker.compose.project")}},"volume":{{json (index .Labels "com.docker.compose.volume")}}}',volume))
        _require_volume(vol,name,volume)
        # Reinspection catches some races; it does not stop further changes.
        second=_redis_inspect(full)
        if first!=second: raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_STATE_CHANGED_'+_changed_state_class(first,second))
        return {'result':'supported_shape_observed','backend':'compose','isolation_established':False,
                'writers_stopped':False,'safe_to_upgrade':False}
    except ComposeDiagnosticError:
        raise
    except Exception:
        raise ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_FAILED') from None


def main():
    parser=argparse.ArgumentParser(description='Read-only Compose Redis shape diagnostic; does not establish isolation')
    parser.add_argument('--home',type=Path,required=True)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--publisher-key',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(inspect_installation(args.home,args.bundle,args.publisher_key),sort_keys=True))


if __name__=='__main__':
    try: main()
    except ComposeDiagnosticError as error:
        print(json.dumps({'result':'error','code':str(error)},sort_keys=True),file=sys.stderr)
        sys.exit(1)
