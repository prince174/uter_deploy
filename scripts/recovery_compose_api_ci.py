"""Test the actual Compose recovery API on uniquely named disposable CI resources."""
import json
import os
from pathlib import Path
import subprocess

import uterctl
from scripts import install, recover_compose

ROOT=Path(__file__).resolve().parents[1]
NAME='uter-restored-api-ci'


def test(home,backup,backup_key,publisher_key,expected_audit):
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.name!='posix' or os.geteuid()!=0:
        raise ValueError('Disposable GitHub-hosted Linux runner required')
    target=ROOT/'work/restored-compose-api'
    if target.exists():raise ValueError('Recovery test target already exists')
    # Only a freshly created project can be deleted in this disposable runner.
    for kind in ('container','network','volume'):
        if recover_compose.run(['docker','--context','default',kind,'ls','-q',
                                '--filter','label=com.docker.compose.project='+NAME]).strip():
            raise ValueError('Recovery test project already exists')
    try:
        result=recover_compose.restore(home,backup,backup_key,publisher_key,target,NAME,18003)
        if result['name']!=NAME:raise ValueError('Recovery returned unexpected project')
        cfg=uterctl.read(target/'install.json');cmd,env=install.commands(target,cfg)
        from scripts.adopt_backup_ci import audit_and_redis
        data=audit_and_redis(cmd+['exec','-T','guardrail','python','-'],env,'read')
        if data['first_sha256']!=expected_audit['first_sha256']:
            raise ValueError('Restored audit chain does not match backup')
        site=uterctl.site_config(target)
        if any(str(home) in arg for arg in site['smoke_command']):
            raise ValueError('Recovery smoke command still refers to original installation')
        print('Production Compose recovery command: full new instance and state preservation PASS',flush=True)
    finally:
        journal=target/'recovery-operation.json'
        if journal.is_file():
            ownership=uterctl.read(journal);marker=ownership.get('id','')
            volumes=[NAME+'_redis-data',NAME+'_audit-data']
            for volume in volumes:
                result=subprocess.run(['docker','--context','default','volume','inspect',volume],capture_output=True)
                if result.returncode==0:
                    labels=json.loads(result.stdout)[0].get('Labels') or {}
                    if labels.get('uter.recovery.id')!=marker:
                        raise ValueError('Refusing to clean an unrelated recovery volume')
            cfg=uterctl.read(target/'install.json');cmd,env=install.commands(target,cfg)
            subprocess.run(cmd+['down','--volumes','--remove-orphans'],env=env,capture_output=True)
