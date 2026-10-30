"""Synthetic same-image fenced update on a disposable GitHub-hosted runner only.

This is not a release or proof of application-code migration. Both product
bundles and the executor use ephemeral, distinct CI keys. Never run on a
shared Docker daemon. Errors are deliberately emitted as fixed categories.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import (adopt_managed, backup_crypto, backup_store, compose_nsfirewall_signed_ci,
                     install, redis_fence_journal as journal, release_upgrade_preflight_ci as release,
                     verify_changed_image_upgrade_ci as staging, wizard_ci)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT=Path(__file__).resolve().parents[1]
PHASE='GUARD'
PHASES=frozenset(('GUARD','ASSETS','PAIR','PREPARE','INSTALL','ADOPT','SEED','APPLY','FINISH','VERIFY','CRASH'))


class Failure(ValueError): pass


def run(args, *, env=None, timeout=600):
    try:
        result=subprocess.run([str(x) for x in args],env=env,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,timeout=timeout)
        if result.returncode:raise Failure('COMMAND_FAILED')
        return result.stdout
    except (OSError,subprocess.TimeoutExpired):raise Failure('COMMAND_UNCERTAIN') from None


def sign(bundle,key):
    raw=json.dumps(uterctl.inventory(bundle),sort_keys=True,indent=2).encode()
    (bundle/'checksums.json').write_bytes(raw)
    (bundle/'checksums.sig').write_bytes(base64.b64encode(key.sign(raw)))


def synthetic_pair(source,directory):
    """Re-sign the verified public source; target only changes version/upgrade_from.

    This is a CI-owned synthetic publisher, not the original release publisher.
    The live product's image digests and data epoch are deliberately unchanged.
    """
    key=Ed25519PrivateKey.generate();public=directory/'synthetic-publisher.pem'
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo))
    old=directory/'synthetic-old';target=directory/'synthetic-target'
    shutil.copytree(source,old);shutil.copytree(source,target)
    manifest=json.loads((target/'manifest.json').read_text())
    original=manifest['version'];manifest['version']='0.1.8-ci.1';manifest['upgrade_from']=[original]
    (target/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    sign(old,key);sign(target,key)
    before=uterctl.verify(old,public);after=uterctl.verify(target,public)
    expected=dict(before,version='0.1.8-ci.1',upgrade_from=[before['version']])
    original_inventory=uterctl.inventory(source);old_inventory=uterctl.inventory(old);new_inventory=uterctl.inventory(target)
    if (before!=uterctl.read(source/'manifest.json') or after!=expected
            or old_inventory!=original_inventory
            or {k:v for k,v in new_inventory.items() if k!='manifest.json'}
               !={k:v for k,v in original_inventory.items() if k!='manifest.json'}
            or before['version']==after['version']):raise Failure('SYNTHETIC_PAIR_INVALID')
    return old,target,public,before,after


def redis_identity(identifier):
    # Never request Config.Env or the full inspect document: those can contain secrets.
    fmt=('{"id":{{json .Id}},"pid":{{json .State.Pid}},"started":{{json .State.StartedAt}},'
         '"mounts":{{json .Mounts}},"networks":{{json .NetworkSettings.Networks}}}')
    value=json.loads(run(['docker','--context','default','inspect','--format',fmt,identifier]))
    if not isinstance(value,dict):raise Failure('REDIS_IDENTITY_INVALID')
    mounts=value['mounts']
    if not isinstance(mounts,list):raise Failure('REDIS_IDENTITY_INVALID')
    return {'id':value['id'],'pid':value['pid'],'started':value['started'],
            'mounts':sorted(mounts,key=lambda item:item['Destination']),
            'networks':value['networks']}


def redis_command(identifier,*args):
    # Password stays inside the container and is never placed in a command or log.
    command='export REDISCLI_AUTH="$(cat /run/secrets/redis_password)"; exec redis-cli --raw "$@"'
    return run(['docker','--context','default','exec',identifier,'sh','-ec',command,'ci',*args]).strip()


def exercise(mode):
    global PHASE
    if mode not in ('normal','kill-target','fail-state'):raise Failure('MODE_INVALID')
    PHASE='ASSETS'
    source=ROOT/'work/pair/old/bundle';public=ROOT/'work/pair/old/publisher-public.pem'
    workspace=Path(os.environ['SOURCE_GIT_WORKSPACE'])
    release.verify_assets(ROOT,os.environ['UTER_CI_OLD_TAG'],os.environ['UTER_CI_NEW_TAG'],
                          os.environ['UTER_CI_OLD_VERSION'],os.environ['UTER_CI_NEW_VERSION'],
                          resolve_tag=lambda _,tag:wizard_ci.tag_commit(workspace,tag))
    staging.validate_inputs(os.environ,ROOT)
    original=uterctl.verify(source,public)
    if original['version']!=os.environ['UTER_CI_OLD_VERSION']:raise Failure('RELEASE_INVALID')
    work=ROOT/'work';private=work/'synthetic-fixture';private.mkdir(mode=0o700)
    PHASE='PAIR';old,target,product_key,before,after=synthetic_pair(source,private)
    executor,executor_key=compose_nsfirewall_signed_ci._ci_signed_executor(source,private)
    if executor_key.read_bytes()==product_key.read_bytes():raise Failure('KEYS_INVALID')
    home=private/'installation';backup_parent=private/'backups';backup_parent.mkdir(mode=0o700)
    backup=backup_parent/'snapshot';key=private/'backup.key';key.write_bytes(os.urandom(32));os.chmod(key,0o600)
    llm_key=private/'llm.key';llm_key.write_text('');os.chmod(llm_key,0o600)
    registry=private/'registry';registry.mkdir(mode=0o700)
    os.environ.update({'DOCKER_CONTEXT':'default','DOCKER_CONFIG':str(registry),'GUARDRAIL_PORT':'18000','GUARDRAIL_CPUS':'2'})
    name='uter-fenced-synthetic-ci';installer=old/'scripts/install.py'
    gateway=json.loads(run(['docker','network','inspect','bridge']))[0]['IPAM']['Config'][0]['Gateway']
    fixture=subprocess.Popen([sys.executable,str(ROOT/'tests/fixtures/upstream.py')],
                             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        args=[sys.executable,installer,'prepare','--home',home,'--backend','compose','--name',name,
              '--inputs',work/'input/published-old','--llm-url',f'http://{gateway}:8080',
              '--llm-model','test-model','--llm-key-file',llm_key,'--allow-http-llm','--guardrail-cpus','2']
        PHASE='PREPARE';run(args);run([sys.executable,installer,'check','--home',home])
        PHASE='INSTALL';run([sys.executable,installer,'install','--home',home])
        PHASE='ADOPT';adopt_managed.adopt(home,old,product_key)
        PHASE='SEED'
        cfg=uterctl.read(home/'install.json');cmd,env=install.commands(home,cfg)
        redis=run(cmd+['ps','-q','redis'],env=env).decode().strip()
        if not redis:raise Failure('REDIS_MISSING')
        identity=redis_identity(redis)
        if redis_command(redis,'SET','uter:ci:synthetic-update','retained')!=b'OK':raise Failure('REDIS_SEED_FAILED')
        command=[sys.executable,'-I','-B',executor/'uterctl.py','apply','--fenced-update','--home',home,
                 '--bundle',target,'--key',product_key,'--executor-key',executor_key,
                 '--backup-key',key,'--backup-dir',backup,'--offline']
        PHASE='APPLY'
        if mode in ('normal','fail-state'):
            if mode=='fail-state':
                shim=private/'fault.so'
                run(['cc','-shared','-fPIC','-o',shim,ROOT/'tests/fixtures/ci_fault_before_state_replace.c','-ldl'])
                injected=dict(os.environ,LD_PRELOAD=str(shim),UTER_CI_FAULT_HOME=str(home))
                process=subprocess.Popen([str(x) for x in command],env=injected,
                                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                try:status=process.wait(timeout=1200)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait(timeout=30);raise Failure('FAULT_TIMEOUT') from None
                if status!=88 or journal.read(home)['phase']!='update_finalizing':
                    raise Failure('FAULT_BOUNDARY_NOT_OBSERVED')
                if uterctl.read(home/'state.json').get('current')!=before or not journal.blocks_mutation(home):
                    raise Failure('FAULT_STATE_INVALID')
                # This is test-only after waiting for our own dead child on a
                # fresh hosted runner, not a stale-lock recovery feature.
                compose_nsfirewall_signed_ci._ci_clear_killed_child_lock(home,process.pid)
                finish=[sys.executable,'-I','-B',executor/'uterctl.py','fence-finish-update','--home',home,
                        '--bundle',home/'releases'/after['version'],'--key',product_key,'--executor-key',executor_key,
                        '--backup-key',key,'--backup-dir',backup]
                PHASE='FINISH';run(finish,timeout=600)
            else:run(command,timeout=1200)
            PHASE='VERIFY'
            state=uterctl.read(home/'state.json')
            if state.get('current')!=after or state.get('previous')!=before or journal.blocks_mutation(home):
                raise Failure('FINAL_STATE_INVALID')
            backup_store.verify_set(backup,backup_crypto.read_key(key),home=home,site=uterctl.site_config(home),version=before['version'])
            if redis_identity(redis)!=identity or redis_command(redis,'GET','uter:ci:synthetic-update')!=b'retained':
                raise Failure('REDIS_CHANGED')
            with urllib.request.urlopen('http://127.0.0.1:18000/ready',timeout=30) as response:
                if response.status!=200:raise Failure('HEALTH_FAILED')
        else:
            PHASE='CRASH'
            process=subprocess.Popen([str(x) for x in command],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            deadline=time.monotonic()+1200
            try:
                while time.monotonic()<deadline and process.poll() is None:
                    try:record=journal.read(home)
                    except Exception:record=None
                    if isinstance(record,dict) and record.get('phase')=='target_starting':
                        process.send_signal(signal.SIGKILL);process.wait(timeout=30);break
                    time.sleep(0.005)
                else:raise Failure('CRASH_BOUNDARY_NOT_OBSERVED')
                if process.returncode!=-signal.SIGKILL or journal.read(home)['phase']!='target_starting':
                    raise Failure('CRASH_STATE_INVALID')
                if not journal.blocks_mutation(home) or not (home/journal.UPDATE_START).is_file():
                    raise Failure('CRASH_BARRIER_INVALID')
                backup_store.verify_set(backup,backup_crypto.read_key(key),home=home,site=uterctl.site_config(home),version=before['version'])
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=30)
        print('SYNTHETIC_SAME_IMAGE_'+mode.upper().replace('-','_')+'_PASS',flush=True)
    finally:
        fixture.terminate()
        try:fixture.wait(timeout=5)
        except subprocess.TimeoutExpired:fixture.kill();fixture.wait(timeout=5)


def main():
    # Parent stages a verified Git snapshot and release assets into root-owned
    # 0700 /tmp; no user Docker daemon or old controller may participate.
    if len(sys.argv)==2 and sys.argv[1]=='--staged':
        exercise(os.environ['UTER_CI_SYNTHETIC_MODE']);return
    staging.validate_inputs(os.environ,ROOT)
    with staging.stage_workspace(ROOT,os.environ) as stage:
        python=staging.prepare_private_python(stage)
        keep=('GITHUB_ACTIONS','GITHUB_SHA','RUNNER_ENVIRONMENT','RUNNER_OS','BACKEND','UTER_CI_RELEASE_MODE',
              'UTER_CI_STRICT_RUNNER','UTER_CI_OLD_VERSION','UTER_CI_NEW_VERSION','UTER_CI_OLD_TAG',
              'UTER_CI_NEW_TAG','UTER_CI_SYNTHETIC_MODE','LANG','HOME')
        env={name:os.environ[name] for name in keep if name in os.environ}
        env.update({'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                    'GITHUB_WORKSPACE':str(stage),'SOURCE_GIT_WORKSPACE':str(ROOT),
                    'OLD_SIGNED_BUNDLE_PATH':str(stage/'work/pair/old/bundle'),
                    'NEW_SIGNED_BUNDLE_PATH':str(stage/'work/pair/new/bundle'),
                    'PUBLISHER_KEY_PATH':str(stage/'work/pair/old/publisher-public.pem')})
        child=subprocess.run([str(python),'-I','-B',str(stage/'scripts/compose_fenced_update_e2e_ci.py'),'--staged'],
                             env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=3300)
        if child.returncode:
            match=re.fullmatch(rb'SYNTHETIC_FENCED_UPDATE_CI_([A-Z]+)_FAILED\r?\n',child.stderr)
            phase=match.group(1).decode('ascii') if match and match.group(1).decode('ascii') in PHASES else 'GUARD'
            raise Failure(phase)
    print('Synthetic same-image CI passed; no product-image upgrade or migration was tested.')


if __name__=='__main__':
    try:main()
    except Exception as error:
        phase=str(error) if str(error) in PHASES else PHASE
        print('SYNTHETIC_FENCED_UPDATE_CI_'+phase+'_FAILED',file=sys.stderr);sys.exit(1)
