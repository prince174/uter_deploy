"""Test the actual Kubernetes recovery API on a new disposable CI namespace."""
import json
import os
from pathlib import Path
import subprocess
import sys

import uterctl
from scripts.signed_recovery_diagnostics import recovery_category, recovery_phase
from scripts import recover_kubernetes

ROOT=Path(__file__).resolve().parents[1]
NAME='uter-restored-api-ci'
CONTEXT='kind-uter-upgrade-ci'


def test(home,backup,backup_key,publisher_key,expected_audit,recovery_bundle=None):
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.name!='posix' or os.geteuid()!=0:
        raise ValueError('Disposable GitHub-hosted Linux runner required')
    target=ROOT/'work/restored-kubernetes-api';kube=['kubectl','--context',CONTEXT]
    if target.exists():raise ValueError('Recovery test target already exists')
    if subprocess.run(kube+['get','namespace',NAME],capture_output=True).returncode==0:
        raise ValueError('Recovery test namespace already exists')
    try:
        if recovery_bundle is not None:
            command=[sys.executable,Path(recovery_bundle)/'scripts/recover_kubernetes.py','--source-home',home,'--backup',backup,
                     '--backup-key',backup_key,'--publisher-key',publisher_key,'--home',target,
                     '--name',NAME,'--port','18004','--context',CONTEXT]
            run=subprocess.run([str(x) for x in command],capture_output=True)
            if run.returncode:
                category=recovery_category(run.stderr);phase=recovery_phase(target)
                raise ValueError(f'Signed recovery failed; category={category}; phase={phase}')
            result=json.loads(run.stdout)
        else:
            result=recover_kubernetes.restore(home,backup,backup_key,publisher_key,target,NAME,CONTEXT,18004)
        if result['name']!=NAME:raise ValueError('Recovery returned unexpected namespace')
        from scripts.adopt_backup_ci import audit_and_redis
        cmd=kube+['-n',NAME,'exec','-i','deployment/'+NAME+'-guardrail','--','python','-']
        data=audit_and_redis(cmd,None,'read')
        if data['first_sha256']!=expected_audit['first_sha256']:
            raise ValueError('Restored Kubernetes audit chain does not match backup')
        site=uterctl.site_config(target)
        if any(str(home) in arg for arg in site['smoke_command']):
            raise ValueError('Recovery smoke command still refers to original installation')
        print('Production Kubernetes recovery command: full new instance and state preservation PASS',flush=True)
    finally:
        journal=target/'recovery-operation.json'
        if journal.is_file():
            marker=uterctl.read(journal).get('id','')
            p=subprocess.run(kube+['get','namespace',NAME,'-o','json'],capture_output=True)
            if p.returncode==0:
                labels=json.loads(p.stdout).get('metadata',{}).get('labels',{})
                if labels.get('uter.io/recovery-id')!=marker:
                    raise ValueError('Refusing to clean an unrelated namespace')
                subprocess.run(kube+['delete','namespace',NAME,'--wait=true','--timeout=300s'],capture_output=True)
