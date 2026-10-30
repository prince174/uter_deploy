"""Probe init mount inode replacement on a disposable hosted Docker runner.

Synthetic fixture only. Does not exercise Uter, workers, maintenance, fences,
backup or updates. Never run this script on an existing/shared Docker daemon.
"""
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts import compose_mount_inode_probe as probe, install_recovery

IMAGE='ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc'
LABEL='uter.inode.fixture'


def run(*args,env):
    result=install_recovery.run_readonly(['/usr/bin/docker','--context','default',*args],timeout=120,env=env)
    if len(result)>65536:raise ValueError('INODE_FIXTURE_OUTPUT_INVALID')
    return result.strip()


def main():
    if (sys.platform!='linux' or os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true'
            or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('RUNNER_OS')!='Linux'
            or os.environ.get('UTER_CI_INODE')!='true' or os.environ.get('DOCKER_HOST')):
        raise ValueError('INODE_FIXTURE_ENVIRONMENT_UNVERIFIED')
    nonce=secrets.token_hex(16);name='uter-inode-fixture-'+nonce
    ident=None;attempted=False;passed=False
    with tempfile.TemporaryDirectory(prefix='uter-inode-fixture-') as directory:
        private=Path(directory);private.chmod(0o700)
        env={'PATH':'/usr/bin:/bin','HOME':str(private),'DOCKER_CONFIG':str(private),'LANG':'C'}
        runtime=private/'runtime';runtime.mkdir(mode=0o700)
        key=runtime/'maintenance-key';key.write_bytes(secrets.token_hex(32).encode('ascii'))
        os.chown(key,10001,10001);key.chmod(0o400)
        try:
            endpoint=run('context','inspect','default','--format','{{json .Endpoints.docker.Host}}',env=env)
            if json.loads(endpoint)!='unix:///var/run/docker.sock':raise ValueError
            if run('ps','-aq','--no-trunc','--filter','name=^/'+name+'$',env=env):raise ValueError
            run('pull',IMAGE,env=env);attempted=True
            ident=run('run','-d','--name',name,'--network','none','--read-only','--cap-drop','ALL',
                      '--security-opt','no-new-privileges','--user','10001:10001',
                      '--label',LABEL+'='+nonce,'--mount','type=bind,source='+str(key)+',target=/run/uter-maintenance/key,readonly',
                      '--entrypoint','sleep',IMAGE,'300',env=env)
            if not re.fullmatch(r'[0-9a-f]{64}',ident):ident=None;raise ValueError
            def snapshot():
                fmt=('{"id":{{json .Id}},"pid":{{json .State.Pid}},"running":{{json .State.Running}},'
                     '"started":{{json .State.StartedAt}},"restarts":{{json .RestartCount}},'
                     '"name":{{json .Name}},"label":{{json (index .Config.Labels "'+LABEL+'")}}}')
                value=json.loads(run('inspect','--format',fmt,ident,env=env))
                if (value.get('id')!=ident or value.get('name')!='/'+name or value.get('label')!=nonce
                        or value.get('running') is not True or type(value.get('pid')) is not int or value['pid']<=1
                        or type(value.get('restarts')) is not int or not isinstance(value.get('started'),str)):
                    raise ValueError
                return value
            before=snapshot()
            if probe.observe(before['pid'],runtime)['init_key_inode_match'] is not True or snapshot()!=before:raise ValueError
            replacement=runtime/'replacement';replacement.write_bytes(secrets.token_hex(32).encode('ascii'))
            os.chown(replacement,10001,10001);replacement.chmod(0o400);os.replace(replacement,key)
            try:probe.observe(before['pid'],runtime)
            except probe.ProbeError:pass
            else:raise ValueError
            if snapshot()!=before:raise ValueError
            passed=True
        finally:
            if attempted:
                if ident is None:
                    matches=run('ps','-aq','--no-trunc','--filter','name=^/'+name+'$',env=env).splitlines()
                    if len(matches)!=1 or not re.fullmatch(r'[0-9a-f]{64}',matches[0]):
                        raise ValueError('INODE_FIXTURE_CLEANUP_UNCERTAIN') from None
                    ident=matches[0]
                if (run('inspect','--format','{{index .Config.Labels "'+LABEL+'"}}',ident,env=env)!=nonce
                        or run('inspect','--format','{{.Name}}',ident,env=env)!='/'+name):
                    raise ValueError('INODE_FIXTURE_CLEANUP_UNCERTAIN')
                run('rm','-f','-v',ident,env=env)
                if run('ps','-aq','--no-trunc','--filter','id='+ident,env=env):
                    raise ValueError('INODE_FIXTURE_CLEANUP_UNCERTAIN')
    if not passed:raise ValueError('INODE_FIXTURE_FAILED')
    print('COMPOSE_INIT_MOUNT_INODE_CI_PASS: synthetic init only; no Uter, worker or fence tested')


if __name__=='__main__':
    try:main()
    except Exception:
        print('COMPOSE_INIT_MOUNT_INODE_CI_UNVERIFIED',file=sys.stderr);sys.exit(1)
