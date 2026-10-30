"""Disposable CI-only probe of one quiescent signed writer shutdown.

No ingress barrier is established. Results cannot authorize an update or prove
that arbitrary in-flight requests, audit writes or Redis writes were drained.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request

from scripts import compose_fence_start, compose_redis_diagnostic, install


class ProbeFailure(ValueError):pass


def runner_guard(home):
    root=Path(__file__).resolve().parents[1]
    if (os.name!='posix' or os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true'
            or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('RUNNER_OS')!='Linux'
            or os.environ.get('UTER_CI_STRICT_RUNNER')!='true' or os.environ.get('BACKEND')!='compose'
            or os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT','default')!='default'
            or not Path(home).resolve(strict=True).is_relative_to(root/'work')):
        raise ProbeFailure('DISPOSABLE_RUNNER_REQUIRED')


AUDIT_PROGRAM='''import hashlib,json,os,sys
from pathlib import Path
from audit_logger import verify_audit_set
key_path=os.environ.get('AUDIT_LOG_HMAC_KEY_FILE')
key=Path(key_path).read_text().strip() if key_path else os.environ['AUDIT_LOG_HMAC_KEY']
p=Path('/var/lib/uter/audit/audit.jsonl')
verify_audit_set(p,hmac_key=key)
data=p.read_bytes()
size=int(sys.argv[1]);expected=sys.argv[2]
if size<0 or len(data)<size:raise ValueError
prefix=hashlib.sha256(data[:size]).hexdigest()
print(json.dumps({'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                  'prefix_matches':prefix==expected}))
'''


def audit_snapshot(cmd,env,size=0,expected=None):
    expected=expected or hashlib.sha256(b'').hexdigest()
    command=cmd+['exec','-T','guardrail','python','-',str(size),expected]
    result=subprocess.run(command,input=AUDIT_PROGRAM.encode(),env=env,stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL,timeout=120)
    if result.returncode or len(result.stdout)>4096:raise ProbeFailure('AUDIT_UNVERIFIED')
    value=json.loads(result.stdout)
    if (set(value)!={'size','sha256','prefix_matches'} or type(value['size']) is not int or value['size']<0
            or not isinstance(value['sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',value['sha256'])
            or value['prefix_matches'] is not True):raise ProbeFailure('AUDIT_UNVERIFIED')
    return value


def probe(home,bundle,publisher,manifest,redis,redis_command,run):
    runner_guard(home)
    compose_redis_diagnostic.inspect_installation(home,bundle,publisher)
    import uterctl
    cfg=uterctl.read(home/'install.json');cmd,env=install.commands(home,cfg)
    cmd[cmd.index('-f')+1]=str(home/'releases'/manifest['version']/'compose/compose.yaml')
    writers=compose_fence_start._writers(cmd,env,cfg['name'],manifest)
    baseline=audit_snapshot(cmd,env)
    run([sys.executable,home/'runtime/uter_managed_smoke.py'],timeout=300)
    after_request=audit_snapshot(cmd,env,baseline['size'],baseline['sha256'])
    if after_request['size']<=baseline['size']:raise ProbeFailure('AUDIT_REQUEST_NOT_OBSERVED')
    if redis_command(redis,'CONFIG','GET','appendonly')!=b'appendonly\nyes':raise ProbeFailure('AOF_UNVERIFIED')
    aof=redis_command(redis,'INFO','persistence')
    lines=set(aof.splitlines())
    if b'aof_enabled:1' not in lines or b'aof_last_write_status:ok' not in lines:raise ProbeFailure('AOF_UNVERIFIED')
    # No request is intentionally sent during stop; this is not a drain proof.
    identifier=writers['guardrail']['id']
    run(['docker','--context','default','stop','--time','25',identifier],timeout=60)
    fmt='{"running":{{json .State.Running}},"exit":{{json .State.ExitCode}},"oom":{{json .State.OOMKilled}}}'
    state=json.loads(run(['docker','--context','default','inspect','--format',fmt,identifier]))
    if state.get('running') is not False or state.get('oom') is not False or type(state.get('exit')) is not int:
        raise ProbeFailure('STOP_UNVERIFIED')
    exit_class='TERM_LIKE' if state['exit']==143 else 'ZERO' if state['exit']==0 else 'OTHER'
    if redis_command(redis,'GET','uter:ci:synthetic-update')!=b'retained':raise ProbeFailure('REDIS_CHANGED')
    # Restart is only for audit comparison on this isolated CI fixture.
    run(['docker','--context','default','start',identifier],timeout=60)
    for attempt in range(90):
        try:
            with urllib.request.urlopen('http://127.0.0.1:18000/ready',timeout=2) as response:
                if response.status==200:break
        except OSError:pass
        time.sleep(2)
    else:raise ProbeFailure('RESTART_UNVERIFIED')
    audit_snapshot(cmd,env,after_request['size'],after_request['sha256'])
    run([sys.executable,home/'runtime/uter_managed_smoke.py'],timeout=300)
    if redis_command(redis,'GET','uter:ci:synthetic-update')!=b'retained':raise ProbeFailure('REDIS_CHANGED')
    return {'stop_exit_class':exit_class,'audit_hmac_and_prefix':'pass','redis_aof_observed':'pass',
            'controlled_request_before_and_after':'pass','inflight_drain':'not_verified'}
