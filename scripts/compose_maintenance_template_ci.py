"""Test the exact Docker inspect template on a disposable hosted runner.

The fixture is synthetic; it does not test the running Uter product, a mount,
fencing, maintenance or update. Never run this script on a shared daemon.
"""
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import compose_maintenance_live as live, install_recovery

IMAGE='ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc'


def run(*args, env):
    result=install_recovery.run_readonly(['/usr/bin/docker','--context','default',*args],timeout=120,env=env)
    if len(result)>65536:raise ValueError('TEMPLATE_FIXTURE_OUTPUT_INVALID')
    return result.strip()


def main():
    if (sys.platform!='linux' or os.environ.get('GITHUB_ACTIONS')!='true'
            or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('RUNNER_OS')!='Linux'
            or os.environ.get('UTER_CI_TEMPLATE')!='true' or os.environ.get('DOCKER_HOST')):
        raise ValueError('TEMPLATE_FIXTURE_ENVIRONMENT_UNVERIFIED')
    nonce=secrets.token_hex(16);name='uter-template-fixture-'+nonce
    marker='uter.template.fixture';ident=None;attempted=False;passed=False
    with tempfile.TemporaryDirectory(prefix='uter-template-fixture-') as private:
        os.chmod(private,0o700)
        env={'PATH':'/usr/bin:/bin','HOME':private,'DOCKER_CONFIG':private,'LANG':'C'}
        try:
            endpoint=run('context','inspect','default','--format','{{json .Endpoints.docker.Host}}',env=env)
            if json.loads(endpoint)!='unix:///var/run/docker.sock':raise ValueError
            if run('ps','-aq','--no-trunc','--filter','name=^/'+name+'$',env=env):raise ValueError
            run('pull',IMAGE,env=env)
            attempted=True
            ident=run('create','--name',name,'--network','none','--label',marker+'='+nonce,
                      '--env','SYNTHETIC_PRIVATE=template-secret-canary',
                      '--env','UTER_MAINTENANCE_ENABLED=true',
                      '--env','UTER_MAINTENANCE_KEY_FILE=/run/uter-maintenance/key',
                      '--env','WEB_CONCURRENCY=1',IMAGE,env=env)
            if not re.fullmatch(r'[0-9a-f]{64}',ident):
                ident=None
                raise ValueError
            raw=run('inspect','--format',live._CONTAINER_FORMAT,ident,env=env)
            if 'template-secret-canary' in raw or 'SYNTHETIC_PRIVATE' in raw:raise ValueError
            value=json.loads(raw);selected=value.get('selected_env')
            if (not isinstance(selected,list) or len(selected)!=4 or selected[-1]!='__end__'
                    or set(selected[:-1])!=live._EXPECTED_ENV or value.get('id')!=ident):raise ValueError
            passed=True
        finally:
            if attempted:
                if ident is None:
                    matches=run('ps','-aq','--no-trunc','--filter','name=^/'+name+'$',env=env).splitlines()
                    if len(matches)!=1 or not re.fullmatch(r'[0-9a-f]{64}',matches[0]):
                        raise ValueError('TEMPLATE_FIXTURE_CLEANUP_UNCERTAIN') from None
                    ident=matches[0]
                if (run('inspect','--format','{{index .Config.Labels "'+marker+'"}}',ident,env=env)!=nonce
                        or run('inspect','--format','{{.Name}}',ident,env=env)!='/'+name):
                    raise ValueError('TEMPLATE_FIXTURE_CLEANUP_UNCERTAIN')
                run('rm','-f','-v',ident,env=env)
                if run('ps','-aq','--no-trunc','--filter','id='+ident,env=env):
                    raise ValueError('TEMPLATE_FIXTURE_CLEANUP_UNCERTAIN')
    if not passed:raise ValueError('TEMPLATE_FIXTURE_FAILED')
    print('COMPOSE_TEMPLATE_CI_PASS: synthetic Docker inspect only; no Uter, fence or update checked')


if __name__=='__main__':
    try:main()
    except Exception:
        print('COMPOSE_TEMPLATE_CI_UNVERIFIED',file=sys.stderr)
        sys.exit(1)
