"""Disposable CI: install.py adoption, encrypted backup, recovery export and update."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import yaml
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.bundle import build as build_bundle
from scripts.smoke_http import check as smoke
import uterctl

ROOT = Path(__file__).resolve().parents[1]
OLLAMA = 'ollama/ollama:0.13.5@sha256:2c9595c555fd70a28363489ac03bd5bf9e7c5bdf2890373c3a830ffd7252ce6d'
MODEL = 'qwen2.5:0.5b-instruct'
MODEL_DIGEST = 'a8b0c51577010a279d933d14c2a8ab4b268079d44c5c8830c0a93900f1827c67'
NODE = 'kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0'
OLD, NEW = 'deploy-2026.10.28', 'deploy-2026.10.28-2'


def call(args, *, input=None, env=None):
    p = subprocess.run([str(a) for a in args], input=input, capture_output=True, env=env)
    if p.returncode:
        lines=p.stderr.decode(errors='replace').splitlines()
        safe=[line for line in lines if line.startswith(('uterctl:', 'adopt:', 'restore export:'))]
        suffix=('; '+safe[-1]) if safe else '; details withheld to avoid leaking runtime secrets'
        raise RuntimeError(f'{args[0]} failed ({p.returncode}){suffix}')
    return p.stdout


def request(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=120) as response:
        return json.load(response)


def audit_and_redis(cmd, env, redis_action):
    program = '''import hashlib,json,os,redis
from pathlib import Path
from audit_logger import verify_audit_set
key_path=os.environ.get('AUDIT_LOG_HMAC_KEY_FILE')
key=Path(key_path).read_text().strip() if key_path else os.environ['AUDIT_LOG_HMAC_KEY']
p=Path('/var/lib/uter/audit/audit.jsonl')
verify_audit_set(p,hmac_key=key)
lines=p.read_bytes().splitlines()
password_path=os.environ.get('REDIS_PASSWORD_FILE')
password=Path(password_path).read_text().strip() if password_path else os.environ['REDIS_PASSWORD']
r=redis.Redis(host=os.environ['REDIS_HOST'],password=password,decode_responses=True)
if ACTION=='write':
 r.set('ci:upgrade:sentinel','uter-upgrade-check')
 r.hset('ci:upgrade:hash',mapping={'state':'pending','version':'1'})
 r.delete('ci:upgrade:list','ci:upgrade:set','ci:upgrade:sorted')
 r.rpush('ci:upgrade:list','first','second')
 r.sadd('ci:upgrade:set','one','two')
 r.zadd('ci:upgrade:sorted',{'one':1,'two':2})
 r.set('ci:upgrade:expiring','alive',ex=900)
assert r.get('ci:upgrade:sentinel')=='uter-upgrade-check'
assert r.hgetall('ci:upgrade:hash')=={'state':'pending','version':'1'}
assert r.lrange('ci:upgrade:list',0,-1)==['first','second']
assert r.smembers('ci:upgrade:set')=={'one','two'}
assert r.zrange('ci:upgrade:sorted',0,-1,withscores=True)==[('one',1.0),('two',2.0)]
assert r.get('ci:upgrade:expiring')=='alive' and 0<r.ttl('ci:upgrade:expiring')<=900
print(json.dumps({'first_sha256':hashlib.sha256(lines[0]).hexdigest(),'lines':len(lines),'redis':'pass'}))
'''.replace('ACTION',repr(redis_action))
    return json.loads(call(cmd, input=program.encode(), env=env))


def verify_active_images(backend, name, home, cfg, kube, images, publication):
    if backend == 'compose':
        env = os.environ.copy()
        env.update({key.upper()+'_IMAGE': value for key, value in cfg['images'].items()})
        env['RUNTIME_DIR'] = str(home/'runtime')
        base = ['docker', 'compose', '--project-name', name, '--env-file', home/'empty.env',
                '-f', home/'compose/compose.yaml']
        for service, reference in images.items():
            container = call(base+['ps','-q',service],env=env).decode().strip()
            assert container, f'No running {service} container'
            live = json.loads(call(['docker','inspect',container]))[0]
            image = json.loads(call(['docker','image','inspect',reference]))[0]
            assert live['State']['Running'] and live['Image'] == image['Id'], f'Wrong running {service} image'
    else:
        pods = json.loads(call(kube+['-n',name,'get','pods','-o','json']))['items']
        for service, reference in images.items():
            deployment = json.loads(call(kube+['-n',name,'get','deployment',name+'-'+service,'-o','json']))
            assert deployment['spec']['template']['spec']['containers'][0]['image'] == reference
            matching = [p for p in pods if p['metadata'].get('labels',{}).get('app.kubernetes.io/name') == service
                        and p['metadata'].get('labels',{}).get('app.kubernetes.io/instance') == name
                        and not p['metadata'].get('deletionTimestamp')]
            expected_ids = {reference.split('@',1)[1], publication['images'][service]['image_id']}
            matches = [c for p in matching if p['spec']['containers'][0]['image'] == reference
                       for c in p.get('status',{}).get('containerStatuses',[]) if c.get('ready')
                       and any(c.get('imageID','').endswith(expected) for expected in expected_ids)]
            observed = [(c.get('image'),c.get('imageID'),c.get('ready')) for p in matching
                        for c in p.get('status',{}).get('containerStatuses',[])]
            assert matches, f'No ready {service} pod with expected digest; observed {observed}'


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.name != 'posix':
        raise SystemExit('Disposable GitHub-hosted runner required')
    backend = os.environ['BACKEND']
    if backend not in ('compose','kubernetes'): raise ValueError('invalid backend')
    work=ROOT/'work'; evidence=work/'adopt-backup-evidence'; evidence.mkdir(parents=True,exist_ok=True)
    home=work/'managed'; registry=work/'registry'; registry.mkdir(mode=0o700)
    token=os.environ['REGISTRY_TOKEN']; user=os.environ['REGISTRY_USER']
    auth=base64.b64encode(f'{user}:{token}'.encode()).decode()
    (registry/'config.json').write_text(json.dumps({'auths':{'ghcr.io':{'auth':auth}}}))
    os.chmod(registry/'config.json',0o600);os.environ['DOCKER_CONFIG']=str(registry)
    os.environ['GUARDRAIL_PORT']='18000';os.environ['GUARDRAIL_CPUS']='2'
    name='uter-upgrade-ci'; cluster='uter-upgrade-ci'; forward=None; proxy=None; created=False; ollama=False
    kube=['kubectl','--context','kind-'+cluster]
    cfg=None
    try:
        # Runner-only network: no local daemon, no external paid model or API token.
        print('Stage: start isolated Ollama',flush=True)
        call(['docker','run','-d','--name','uter-real-llm-ci','--network','host','-e','OLLAMA_HOST=0.0.0.0:11434','-e','OLLAMA_CONTEXT_LENGTH=2048',OLLAMA]);ollama=True
        for attempt in range(60):
            try: request('http://127.0.0.1:11434/api/tags');break
            except (OSError,urllib.error.URLError):
                if attempt==59: raise
                time.sleep(1)
        print('Stage: download and verify model',flush=True)
        call(['docker','exec','uter-real-llm-ci','ollama','pull',MODEL])
        models=request('http://127.0.0.1:11434/api/tags')['models']
        assert any(x['name']==MODEL and x['digest']==MODEL_DIGEST for x in models), 'Model digest mismatch'
        # Verify actual model inference separately, then require a Uter response too.
        direct=request('http://127.0.0.1:11434/v1/chat/completions',{'model':MODEL,'messages':[{'role':'user','content':'Say hello briefly.'}],'stream':False,'max_tokens':16})
        assert direct['choices'][0]['message']['content'].strip()
        proxy=subprocess.Popen([sys.executable,str(ROOT/'scripts/ollama_ci_proxy.py')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for attempt in range(30):
            try: request('http://127.0.0.1:11435/stats');break
            except (OSError,urllib.error.URLError):
                if attempt==29: raise
                time.sleep(1)
        if backend=='kubernetes':
            call(['kind','create','cluster','--name',cluster,'--image',NODE,'--wait','180s']);created=True
            network='kind'
        else: network='bridge'
        if backend=='kubernetes':
            node=json.loads(call(['docker','inspect',cluster+'-control-plane']))[0]
            gateway=node['NetworkSettings']['Networks'][network]['Gateway']
        else:
            configs=json.loads(call(['docker','network','inspect',network]))[0]['IPAM']['Config']
            gateway=next(x['Gateway'] for x in configs if x.get('Gateway') and ':' not in x['Gateway'])
        assert gateway, 'No IPv4 gateway for isolated LLM'
        llm_url=f'http://{gateway}:11435/v1'
        (work/'empty-key').write_text('')
        print('Stage: prepare isolated runtime',flush=True)
        prepare=[sys.executable,ROOT/'scripts/install.py','prepare','--home',home,'--backend',backend,'--name',name,'--inputs',work/'input'/OLD,'--llm-url',llm_url,'--llm-model',MODEL,'--llm-key-file',work/'empty-key','--allow-http-llm','--guardrail-cpus','2']
        if backend=='kubernetes': prepare += ['--context','kind-'+cluster,'--registry-config',registry/'config.json']
        call(prepare)
        cfg=json.loads((home/'install.json').read_text())
        runtime=home/'runtime'
        # Keep CPU inference bounded; these are explicit test settings.
        with (runtime/'guardrail.env').open('a') as f: f.write('UPSTREAM_OPENAI_MAX_TOKENS=64\n')
        if backend=='kubernetes':
            resources=list(yaml.safe_load_all((home/'resources.yaml').read_text()))
            next(x for x in resources if x['kind']=='Secret' and x['metadata']['name']==name+'-guardrail-env')['stringData']['UPSTREAM_OPENAI_MAX_TOKENS']='64'
            (home/'resources.yaml').write_text(yaml.safe_dump_all(resources))
        # Follow the real install.py flow before adopting the resulting installation.
        call([sys.executable,ROOT/'scripts/install.py','check','--home',home])
        call([sys.executable,ROOT/'scripts/install.py','install','--home',home])
        # These are ephemeral CI-only signing keys, not publisher keys or released bundles.
        key=Ed25519PrivateKey.generate(); private=work/'test-key.pem'; public=work/'test-public.pem'
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));os.chmod(private,0o600)
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        bundles=[]
        for version,release,prev in [('0.0.1',OLD,[]),('0.0.2',NEW,['0.0.1'])]:
            folder=work/'input'/release; pub=json.loads((folder/'publication.json').read_text()); images=json.loads((folder/'images.json').read_text())
            manifest={'schema':1,'config_schema':1,'status':'released','version':version,'source_commit':pub['images']['guardrail']['source_commit'],'data_epoch':1,'upgrade_from':prev,'images':images,'image_config_ids':{s:pub['images'][s]['image_id'] for s in images}}
            mpath=work/f'{version}.json';mpath.write_text(json.dumps(manifest)); bundle=work/f'bundle-{version}'
            build_bundle(mpath,bundle,private);bundles.append(bundle)
        credentials=json.loads((home/'credentials.json').read_text())
        # Every smoke opens its own Kubernetes port-forward so pod replacement is safe.
        smoke_file=runtime/'acceptance.py'
        wrapper = """import json,sys,time,subprocess,urllib.error
from pathlib import Path
sys.path.insert(0, SCRIPTS)
from smoke_http import check
p=json.loads(Path(CREDENTIALS).read_text())
f=None
try:
    if KUBE:
        f=subprocess.Popen(KUBE+['-n',NAME,'port-forward','service/'+NAME+'-guardrail','18000:8000'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for i in range(45):
        try:
            result=check('http://127.0.0.1:18000','admin',p['admin']);break
        except (OSError,urllib.error.URLError):
            if i==44: raise
            time.sleep(1)
    print(json.dumps(result))
finally:
    if f: f.terminate();f.wait(timeout=10)
"""
        prefix='SCRIPTS='+repr(str(ROOT/'scripts'))+'\nCREDENTIALS='+repr(str(home/'credentials.json'))+'\nKUBE='+repr(kube if backend=='kubernetes' else [])+'\nNAME='+repr(name)+'\n'
        smoke_file.write_text(prefix+wrapper)
        base=[sys.executable,ROOT/'uterctl.py']; common=['--home',home,'--key',public]
        smoke_argv=work/'smoke-argv.json';smoke_argv.write_text(json.dumps([sys.executable,str(smoke_file)]))
        print('Stage: adopt the install.py installation',flush=True)
        call([sys.executable,ROOT/'scripts/adopt_installation.py','--home',home,'--bundle',bundles[0],
              '--key',public,'--smoke-argv-json',smoke_argv])
        assert json.loads((home/'state.json').read_text())['adopted_installer'] is True
        before=json.loads(call([sys.executable,smoke_file]))
        if backend=='compose':
            cmd=['docker','compose','--project-name',name,'--env-file',str(home/'empty.env'),'-f',str(home/'compose/compose.yaml'),'exec','-T','guardrail','python','-']
            env=os.environ.copy();env.update({n.upper()+'_IMAGE':v for n,v in cfg['images'].items()});env['RUNTIME_DIR']=str(runtime)
        else: cmd=kube+['-n',name,'exec','-i','deployment/'+name+'-guardrail','--','python','-'];env=None
        stats_before=request('http://127.0.0.1:11435/stats')
        assert stats_before['successful_completions'] > 0 and stats_before['completion_tokens'] > 0
        print('Stage: real LLM and persistent state before update',flush=True)
        audit_before=audit_and_redis(cmd,env,'write')
        # A receipt alone must not bypass encrypted backup creation.
        fake=work/'fake-receipt.json';fake.write_text(json.dumps({'version':'0.0.1','backup_id':'fake'}))
        missing=subprocess.run([str(x) for x in base+['apply',*common,'--bundle',bundles[1],'--backup-receipt',fake]],capture_output=True)
        assert missing.returncode and b'receipts alone' in missing.stderr
        from scripts import backup_crypto
        backup_key=work/'backup-key';backup_crypto.create_key(backup_key)
        backup_dir=work/'actual-backup'
        print('Stage: actual encrypted backup and upgrade',flush=True)
        call(base+['apply',*common,'--bundle',bundles[1],'--backup-dir',backup_dir,'--backup-key',backup_key])
        from scripts import backup_store, restore_backup
        backup_manifest=backup_store.verify_set(backup_dir,backup_crypto.read_key(backup_key),home=home,
                                                site=uterctl.site_config(home),version='0.0.1')
        from scripts import recovery_preflight
        with tempfile.TemporaryDirectory(prefix='preflight-',dir=work) as preflight_parent:
            verified=recovery_preflight.preflight(home,backup_dir,backup_key,public,Path(preflight_parent)/'stage')
            assert verified['backup_id']==backup_manifest['id'] and verified['version']=='0.0.1'
        exported=work/'backup-export'
        restore_backup.export(backup_dir,backup_key,exported)
        # Read the actual encrypted audit snapshot after verified export, compare its first record.
        import tarfile
        with tarfile.open(exported/'audit.tar') as tar:
            candidates=[x for x in tar if x.isfile() and x.name.endswith('audit.jsonl')]
            assert len(candidates)==1
            audit_lines=tar.extractfile(candidates[0]).read().splitlines()
        assert hashlib.sha256(audit_lines[0]).hexdigest()==audit_before['first_sha256']
        assert len(audit_lines)>=audit_before['lines']
        # Redis validates the exported RDB format; this uses a disposable helper only.
        redis_image=json.loads((work/'input'/OLD/'images.json').read_text())['redis']
        call(['docker','run','--rm','--network','none','--user','0:0',
              '--mount','type=bind,source='+str(exported/'redis.rdb')+',target=/snapshot.rdb,readonly',
              '--entrypoint','redis-check-rdb',redis_image,'/snapshot.rdb'])
        # Restore the RDB into a separate disposable Redis, never into the active workload.
        restored_name='uter-ci-restored-redis'
        os.chown(exported/'redis.rdb',999,1000);os.chmod(exported/'redis.rdb',0o400)
        try:
            call(['docker','run','-d','--name',restored_name,'--network','none','--user','999:1000',
                  '--mount','type=bind,source='+str(exported/'redis.rdb')+',target=/snapshot.rdb,readonly',
                  '--entrypoint','redis-server',redis_image,'--dir','/','--dbfilename','snapshot.rdb',
                  '--save','','--appendonly','no','--bind','127.0.0.1'])
            for attempt in range(30):
                value=subprocess.run(['docker','exec',restored_name,'redis-cli','--raw','GET','ci:upgrade:sentinel'],capture_output=True)
                if value.returncode==0 and value.stdout.strip()==b'uter-upgrade-check': break
                if attempt==29: raise ValueError('Redis snapshot restore failed')
                time.sleep(1)
            for redis_args, expected in [(['HGET','ci:upgrade:hash','state'],b'pending'),
                                         (['LLEN','ci:upgrade:list'],b'2'),
                                         (['SCARD','ci:upgrade:set'],b'2'),
                                         (['ZCARD','ci:upgrade:sorted'],b'2'),
                                         (['GET','ci:upgrade:expiring'],b'alive')]:
                assert call(['docker','exec',restored_name,'redis-cli','--raw',*redis_args]).strip()==expected
            ttl=int(call(['docker','exec',restored_name,'redis-cli','--raw','TTL','ci:upgrade:expiring']).strip())
            assert 0<ttl<=900, 'Redis snapshot did not retain expiry'
        finally:
            subprocess.run(['docker','rm','-f',restored_name],capture_output=True)
        if backend=='kubernetes':
            from scripts import recovery_pvc_ci
            recovery_pvc_ci.test(kube,name,images['guardrail'],redis_image,exported)
        else:
            from scripts import recovery_compose_ci
            recovery_compose_ci.test(home,backup_dir,backup_key,public,exported,audit_before)
        print('Stage: real LLM and persistent state after update',flush=True)
        after=json.loads(call([sys.executable,smoke_file]))
        stats_after=request('http://127.0.0.1:11435/stats')
        assert stats_after['successful_completions'] > stats_before['successful_completions']
        assert stats_after['completion_tokens'] > stats_before['completion_tokens']
        audit_after=audit_and_redis(cmd,env,'check')
        assert audit_before['first_sha256']==audit_after['first_sha256'] and audit_after['lines']>audit_before['lines']
        state=json.loads((home/'state.json').read_text());assert state['current']['version']=='0.0.2' and state['previous']['version']=='0.0.1' and state['pending'] is None
        assert state['current']['images']==json.loads((work/'input'/NEW/'images.json').read_text())
        publication=json.loads((work/'input'/NEW/'publication.json').read_text())
        verify_active_images(backend,name,home,cfg,kube,state['current']['images'],publication)
        assert any(x['name']==MODEL for x in request('http://127.0.0.1:11434/api/ps')['models'])
        result={'backend':backend,'old_release':OLD,'new_release':NEW,'model':MODEL,'model_digest':MODEL_DIGEST,
                'real_inference':'pass','install_py':'pass','adoption':'pass','receipt_bypass_rejected':'pass',
                'encrypted_backup':'pass','authenticated_recovery_preflight':'pass',
                'backup_export':'pass','redis_rdb_validation':'pass','redis_restore':'pass','backup_audit_matches':'pass',
                'backup_id':backup_manifest['id'],'upgrade':'pass','running_images_match_new_release':'pass',
                'redis_sentinel':'pass','redis_types_and_expiry':'pass',
                'separate_kubernetes_pvc_restore':'pass' if backend=='kubernetes' else 'not applicable',
                'audit_chain_and_persistence':'pass','audit_lines_before':audit_before['lines'],
                'audit_lines_after':audit_after['lines'],'test_signing_key':'ephemeral CI only',
                'full_restore_to_workloads':'separate Compose project passed' if backend=='compose' else 'not tested',
                'data_epoch':'CI assumption, not a production compatibility declaration'}
        (evidence/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    finally:
        if forward: forward.terminate();forward.wait(timeout=10)
        # Preserve diagnostics from this disposable environment without secrets.
        sensitive=[token,auth]
        if home.exists():
            for path in (home/'runtime').glob('*.env'):
                sensitive += [line.split('=',1)[1] for line in path.read_text().splitlines() if '=' in line]
            if (home/'credentials.json').exists():
                sensitive += list(json.loads((home/'credentials.json').read_text()).values())
            for name in ('redis-password','audit-hmac-key'):
                path=home/'runtime'/name
                if path.exists(): sensitive.append(path.read_text().strip())
        def diagnostic(label, command, env=None):
            result=subprocess.run([str(x) for x in command],env=env,capture_output=True)
            text=(result.stdout+result.stderr).decode(errors='replace')
            for secret in sorted(sensitive,key=len,reverse=True):
                if secret: text=text.replace(secret,'[REDACTED]')
            text=re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+','[REDACTED-JWT]',text)
            (evidence/(label+'.txt')).write_text(text)
        if cfg and backend=='compose':
            env=os.environ.copy();env.update({n.upper()+'_IMAGE':v for n,v in cfg['images'].items()});env['RUNTIME_DIR']=str(home/'runtime')
            diagnostic('compose-services',['docker','compose','--project-name',name,'--env-file',home/'empty.env','-f',home/'compose/compose.yaml','ps','-a'],env)
            diagnostic('compose-logs',['docker','compose','--project-name',name,'--env-file',home/'empty.env','-f',home/'compose/compose.yaml','logs','--no-color','--tail','80'],env)
            subprocess.run(['docker','compose','--project-name',name,'--env-file',str(home/'empty.env'),'-f',str(home/'compose/compose.yaml'),'down','--volumes','--remove-orphans'],env=env,capture_output=True)
        if created:
            diagnostic('pods',kube+['-n',name,'get','pods,pvc','-o','wide'])
            diagnostic('events',kube+['-n',name,'get','events','--sort-by=.lastTimestamp'])
            for svc in ('guardrail','agent','redis'):
                diagnostic(svc+'-logs',kube+['-n',name,'logs','deployment/'+name+'-'+svc,'--tail=80'])
            subprocess.run(['kind','delete','cluster','--name',cluster],capture_output=True)
        if proxy:proxy.terminate();proxy.wait(timeout=10)
        if ollama:subprocess.run(['docker','rm','-f','uter-real-llm-ci'],capture_output=True)


if __name__=='__main__': main()
