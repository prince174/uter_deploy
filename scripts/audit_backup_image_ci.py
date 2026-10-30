"""Disposable hosted CI only: exercise strict audit verification in protected image.

Uses synthetic keys, logs, receipt and ephemeral release signature. This is not
a released bundle or authority to restore, back up or update a real workload.
The snapshot workflow authors and artifact run are trusted; metadata matching
alone is not an independent provenance proof of that workflow definition.
"""
import base64
import io
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import uterctl
from scripts import audit_backup_evidence as audit, backup_store, maintenance_evidence, redis_fence_journal as journal
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

IMAGE='uter-guardrail-protected'
PHASE='INITIAL'
FIXTURE=r'''import base64,json,sys,tempfile
from pathlib import Path
from audit_logger import AuditLogger
value=json.load(sys.stdin)
with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
 p=Path(tmp)/'audit.jsonl'
 a=AuditLogger(enabled=True,path=str(p),hmac_key=value['key'],max_bytes=800,backup_count=20)
 for i in range(5):a.log_event('fixture','entry',details={'index':i})
 receipt=a.seal_for_maintenance()
 files={x.name:base64.b64encode(x.read_bytes()).decode() for x in p.parent.glob('audit.jsonl*')}
 print(json.dumps({'files':files,'receipt':receipt}))
'''
CHECK=r'''import base64,inspect,json,sys,tempfile
from pathlib import Path
from audit_logger import verify_audit_set
value=json.load(sys.stdin)
if 'strict' not in inspect.signature(verify_audit_set).parameters:raise ValueError()
with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
 p=Path(tmp)
 for name,raw in value['files'].items():(p/name).write_bytes(base64.b64decode(raw,validate=True))
 r=verify_audit_set(p/'audit.jsonl',hmac_key=value['key'],strict=True)
 names=('last_seq','last_hash','files_verified','verified_entries','segments_verified','hmac_enabled',
        'ignored_trailing_entries','ignored_orphan_entries','ignored_malformed_entries','legacy_entries_skipped')
 print(json.dumps({k:r[k] for k in names}))
'''


def call(script, data, image_id):
    # Run an immutable local image configuration ID, not the mutable load tag.
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):raise ValueError
    import resource
    output_limit=4*1024*1024
    def limit_output():
        resource.setrlimit(resource.RLIMIT_FSIZE,(output_limit,output_limit))
    nonce=secrets.token_hex(16);name='uter-audit-ci-'+nonce
    cmd=['docker','--context','default','run','--rm','-i','--name',name,'--label','uter.audit.ci='+nonce,
         '--network','none','--read-only',
         '--tmpfs','/tmp:size=64m,mode=1777','--cap-drop','ALL','--security-opt','no-new-privileges',
         '--entrypoint','python',image_id,'-c',script]
    try:
        with tempfile.TemporaryFile() as output:
            proc=subprocess.run(cmd,input=json.dumps(data).encode(),stdout=output,stderr=subprocess.DEVNULL,
                                timeout=180,preexec_fn=limit_output)
            output.seek(0); content=output.read(output_limit+1)
            if proc.returncode or len(content)>=output_limit:raise ValueError
            return json.loads(content)
    finally:
        # Remove only a container bearing this random operation label. A
        # timeout remains uncertain even if no container is observed yet.
        found=subprocess.check_output(['docker','--context','default','ps','-aq','--no-trunc',
              '--filter','name=^/'+name+'$'],stderr=subprocess.DEVNULL,timeout=30).decode().splitlines()
        if len(found)>1 or any(not re.fullmatch(r'[0-9a-f]{64}',x) for x in found):raise ValueError
        if found:
            label=subprocess.check_output(['docker','--context','default','inspect','--format',
                  '{{index .Config.Labels "uter.audit.ci"}}',found[0]],stderr=subprocess.DEVNULL,timeout=30).decode().strip()
            if label!=nonce:raise ValueError
            subprocess.run(['docker','--context','default','rm','-f','-v',found[0]],
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=30)


def archive(files):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w') as output:
        for name,content in sorted(files.items()):
            item=tarfile.TarInfo(name);item.size=len(content);output.addfile(item,io.BytesIO(content))
    return stream.getvalue()


def main():
    global PHASE
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'
            or os.environ.get('RUNNER_OS')!='Linux' or os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT')):
        raise ValueError
    endpoint=subprocess.check_output(['docker','--context','default','context','inspect','default','--format',
                                      '{{.Endpoints.docker.Host}}'],stderr=subprocess.DEVNULL,timeout=30).decode().strip()
    if endpoint!='unix:///var/run/docker.sock':raise ValueError
    config=subprocess.check_output(['docker','--context','default','image','inspect','--format','{{.Id}}',IMAGE],
                                   stderr=subprocess.DEVNULL,timeout=30).decode().strip()
    expected=(ROOT/'work/images/protected-guardrail/evidence/image-id.txt').read_text().strip()
    if config!=expected or not re.fullmatch(r'sha256:[0-9a-f]{64}',config):raise ValueError
    PHASE='REAL_ROTATED_FIXTURE'
    hmac_key=secrets.token_hex(32);fixture=call(FIXTURE,{'key':hmac_key},config)
    files={name:base64.b64decode(value,validate=True) for name,value in fixture['files'].items()}
    if len(files)<2 or 'audit.jsonl' not in files:raise ValueError
    with tempfile.TemporaryDirectory(prefix='uter-audit-ci-') as temp:
        root=Path(temp);home=root/'home';home.mkdir(mode=0o700);bundle=root/'bundle';bundle.mkdir()
        site={'backend':'compose','name':'uter-test','namespace':'uter-test','context':'default'}
        # Fixture-only placeholder: this is a local config ID, not a registry
        # manifest digest and the ephemeral signature is not publisher trust.
        images={n:'ci.invalid/'+n+'@'+config for n in ('guardrail','agent','redis')}
        manifest={'schema':1,'config_schema':1,'status':'released','version':'1.0.0','source_commit':'a'*40,
                  'data_epoch':1,'upgrade_from':[],'images':images,
                  'maintenance_protocol':{'version':1,'services':['agent','guardrail']}}
        uterctl.write(bundle/'manifest.json',manifest)
        for name in ('compose/compose.yaml','charts/uter/Chart.yaml'):
            path=bundle/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixture')
        signer=Ed25519PrivateKey.generate();public=root/'publisher.pem'
        public.write_bytes(signer.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        checks=json.dumps(uterctl.inventory(bundle),sort_keys=True).encode()
        (bundle/'checksums.json').write_bytes(checks);(bundle/'checksums.sig').write_bytes(base64.b64encode(signer.sign(checks)))
        key=secrets.token_bytes(32);operation=secrets.token_hex(16);plan=secrets.token_hex(32)
        resource='a'*64;boot=secrets.token_hex(16)
        journal.create(home,backend='compose',site=site['name'],resource=resource,plan_sha256=plan,operation=operation)
        recorder=maintenance_evidence.Recorder(home,key,operation=operation,backend='compose',plan_sha256=plan,lock_guard=lambda:True)
        receipt={'protocol':1,'boot_id':boot,'state':'quiesced','safe_to_stop':True,'active_requests':0,'error':None,
                 'evidence':{'redis_closed':True,'audit':fixture['receipt']}}
        recorder.intent('guardrail','ci-container',boot);recorder.receipt('guardrail','ci-container',boot,receipt)
        def strict(files,key_string,image):
            if image!=images['guardrail']:raise ValueError
            return call(CHECK,{'key':key_string,'files':{n:base64.b64encode(v).decode() for n,v in files.items()}},config)
        def verify_set(folder, data):
            writer=backup_store.BackupWriter(folder,key,home,site,'1.0.0')
            writer.put('runtime',io.BytesIO(archive({'runtime/audit-hmac-key':hmac_key.encode()})))
            writer.put('redis',io.BytesIO(b'REDIS-synthetic'))
            writer.put('audit',io.BytesIO(archive(data)));writer.finish()
            return audit.verify(home=home,backup=folder,key=key,bundle=bundle,publisher=public,recorder=recorder,
                site=site,resource=resource,instance='ci-container',boot=boot,strict_auditor=strict)
        PHASE='STRICT_MATCH'
        value=verify_set(root/'backup',{('audit/'+n):v for n,v in files.items()})
        if value['safe_to_update'] is not False or value['safe_to_backup'] is not False:raise ValueError
        audit.save(value,home=home,key=key,recorder=recorder,site=site['name'],resource=resource)
        PHASE='MISSING_OLDEST'
        names=sorted((n for n in files if n!='audit.jsonl'),key=lambda n:int(n.rsplit('.',1)[1]))
        incomplete=dict(files);del incomplete[names[-1]]
        try:verify_set(root/'missing',{('audit/'+n):v for n,v in incomplete.items()})
        except audit.AuditEvidenceError:pass
        else:raise ValueError
        PHASE='TAMPERED_CONTENT'
        damaged=dict(files);raw=bytearray(damaged['audit.jsonl']);raw[len(raw)//2]^=1;damaged['audit.jsonl']=bytes(raw)
        try:verify_set(root/'tampered',{('audit/'+n):v for n,v in damaged.items()})
        except audit.AuditEvidenceError:pass
        else:raise ValueError
        PHASE='SWAPPED_ROTATION'
        swapped=dict(files);swapped['audit.jsonl'],swapped[names[0]]=swapped[names[0]],swapped['audit.jsonl']
        try:verify_set(root/'swapped',{('audit/'+n):v for n,v in swapped.items()})
        except audit.AuditEvidenceError:pass
        else:raise ValueError
        PHASE='TAMPERED_HMAC'
        damaged=dict(files);entries=damaged['audit.jsonl'].splitlines();entry=json.loads(entries[0])
        signature=entry['audit_hmac'];entry['audit_hmac']=('0' if signature[0]!='0' else '1')+signature[1:]
        entries[0]=json.dumps(entry).encode();damaged['audit.jsonl']=b'\n'.join(entries)+b'\n'
        try:verify_set(root/'hmac',{('audit/'+n):v for n,v in damaged.items()})
        except audit.AuditEvidenceError:pass
        else:raise ValueError
    print('STRICT_AUDIT_ROTATION_MATCH_PASS; synthetic fixtures, no live fence or recovery verified')


if __name__=='__main__':
    try:main()
    except Exception:
        print('AUDIT_BACKUP_IMAGE_CI_'+PHASE+'_FAILED',file=sys.stderr)
        raise SystemExit(1)
