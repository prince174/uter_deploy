"""Disposable CI-only signed executor, real SIGKILL, reauth and backup.

Pins and signing key are synthesized on the same runner. This does not prove
operator trust, production stale-lock recovery, audit HMAC integrity or update.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import uterctl
from scripts import (adopt_backup_ci, backup_snapshot,
                     kubernetes_fence_profile_store as profile_store,
                     kubernetes_pinned_preflight_ci as pin_ci, kubernetes_redis_identity_ci as snapshot,
                     kubernetes_loopback_signed_ci as loopback_ci)

ROOT=Path(__file__).resolve().parents[1]
PHASE='GUARD'
EXECUTOR_REQUIRED=frozenset(('uterctl.py','scripts/kubernetes_executor_ci_child.py',
    'scripts/kubernetes_fence_coordinator.py','scripts/kubernetes_fence_recovery_session.py',
    'scripts/kubernetes_fence_start.py','scripts/kubernetes_backup_coordinator.py',
    'scripts/kubernetes_audit_reader.py','scripts/kubernetes_audit_reader_plan.py',
    'scripts/kubernetes_config_snapshot.py','scripts/kubernetes_runtime_pin.py',
    'scripts/kubernetes_loopback_snapshot.py','scripts/kubernetes_loopback_auth.py',
    'scripts/kubernetes_trusted_kubectl.py','scripts/backup_installation.py',
    'scripts/backup_snapshot.py','scripts/backup_crypto.py','scripts/backup_store.py',
    'scripts/redis_fence_journal.py'))


class CoordinatorCITestError(ValueError):pass


def _validate_executor(executor,public,manifest):
    """Trusted launcher checks signature and root-protected files before exec."""
    if uterctl.verify(executor,public)!=manifest:raise ValueError
    inventory=json.loads((executor/'checksums.json').read_bytes())
    if not EXECUTOR_REQUIRED.issubset(inventory):raise ValueError
    for path in (executor,*executor.rglob('*')):
        info=path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):raise ValueError


def verify(home,product,publisher,manifest):
    global PHASE
    try:
        adopt_backup_ci.runner_guard(os.environ,ROOT)
        if (os.environ.get('UTER_CI_STRICT_RUNNER')!='true' or os.environ.get('BACKEND')!='kubernetes'
                or os.environ.get('UTER_CI_VERIFY_KUBE_LOOPBACK')!='true'):raise ValueError
        for value in (home,product,publisher):
            if not Path(value).resolve(strict=True).is_relative_to(ROOT/'work'):raise ValueError
        loopback_ci.guard(home,product,publisher,manifest)
        PHASE='INPUT'
        raw,api=pin_ci._material(home,product,publisher)
        site=uterctl.site_config(home);names=backup_snapshot.kube_objects(home,site,manifest=manifest)
        if (site.get('name')!=snapshot.SITE or site.get('namespace')!=snapshot.SITE
                or site.get('context')!=snapshot.CONTEXT):raise ValueError
        if len(names)!=len(set(names)):raise ValueError
        binary_path=Path('/usr/bin/uter-ci-kubectl')
        binary_digest=hashlib.sha256(binary_path.read_bytes()).hexdigest()
        uid=lambda kind,name:snapshot._query(['-n',site['namespace'],'get',kind,name])['metadata']['uid']
        obj={item:uid(*item.split('/',1)) for item in names if not item.startswith('pvc/')}
        record={'schema':2,'site':site['name'],'api':api,
                'writer_uids':{service:uid('deployment',site['name']+'-'+service) for service in ('guardrail','agent')},
                'audit_pvc_uid':uid('pvc',site['name']+'-guardrail'),'kubectl_sha256':binary_digest,'object_uids':obj,
                'release_version':manifest['version'],
                'inventory_sha256':hashlib.sha256((Path(product)/'checksums.json').read_bytes()).hexdigest(),
                'publisher_sha256':hashlib.sha256(Path(publisher).read_bytes()).hexdigest()}
        with tempfile.TemporaryDirectory(prefix='kube-coordinator-ci-',dir=ROOT/'work') as folder:
            private=Path(folder);os.chmod(private,0o700)
            if private.stat().st_uid!=0 or private.stat().st_mode&0o077:raise ValueError
            key=private/'backup-key';key.write_bytes(os.urandom(32));key.chmod(0o600)
            config=private/'kubeconfig';config.write_bytes(raw);config.chmod(0o600)
            profile=private/'profile';profile_store.create(profile,key.read_bytes(),record)
            signer=Ed25519PrivateKey.generate();secret=private/'executor-private.pem';public=private/'executor-public.pem'
            secret.write_bytes(signer.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()));secret.chmod(0o600)
            public.write_bytes(signer.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo));public.chmod(0o600)
            executor=private/'executor';PHASE='SIGN_EXECUTOR'
            # The staged CI checkout contains only scripts/tooling. Compose,
            # chart, docs and examples come from the already verified product.
            executor.mkdir(mode=0o700);shutil.copy2(Path(product)/'manifest.json',executor/'manifest.json')
            for name in ('compose','charts','docs','examples'):
                shutil.copytree(Path(product)/name,executor/name)
            (executor/'scripts').mkdir()
            shutil.copy2(ROOT/'uterctl.py',executor/'uterctl.py')
            shutil.copy2(ROOT/'requirements.txt',executor/'requirements.txt')
            for src in sorted((ROOT/'scripts').glob('*.py')):
                shutil.copy2(src,executor/'scripts'/src.name)
            (executor/'empty.env').write_text('# CI executor placeholder.\n')
            inventory=json.dumps(uterctl.inventory(executor),sort_keys=True,indent=2).encode()
            (executor/'checksums.json').write_bytes(inventory)
            (executor/'checksums.sig').write_bytes(base64.b64encode(signer.sign(inventory)))
            _validate_executor(executor,public,manifest)
            destination=private/'backup'
            def command(mode):
                return [sys.executable,'-I','-B',str(executor/'scripts/kubernetes_executor_ci_child.py'),mode,
                        str(home),str(product),str(publisher),str(config),str(profile),str(key),str(public),
                        str(binary_path),str(destination)]
            PHASE='START_CHILD'
            _validate_executor(executor,public,manifest)
            child=subprocess.Popen(command('start'),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:out,err=child.communicate(timeout=900)
            except subprocess.TimeoutExpired:
                child.kill();child.communicate();raise ValueError from None
            if child.returncode!=-9 or out.strip()!=b'CI_ISOLATION_STAGE_DONE':
                stages={b'EXECUTOR_AUTH',b'PROFILE_AUTH',b'KUBECTL_OPEN',b'CONFIG_SEAL',b'PINNED_PREFLIGHT',
                        b'BOUND_PREFLIGHT',b'REDIS_PLAN',b'START'}
                found=re.findall(rb'(?m)^KUBE_COORDINATOR_CI_([A-Z_]+)\r?$',err)
                if found and found[-1] in stages:PHASE='CHILD_'+found[-1].decode('ascii')
                raise ValueError
            # Disposable CI only: exact reaped child PID, exact private lock.
            PHASE='STALE_LOCK_CI_ONLY'
            lock=Path(home)/'operation.lock';info=lock.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
                    or info.st_mode&0o077 or lock.read_bytes()!=str(child.pid).encode()):raise ValueError
            lock.unlink()
            PHASE='RECOVERY_CHILD'
            _validate_executor(executor,public,manifest)
            resumed=subprocess.run(command('resume'),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,timeout=900)
            if resumed.returncode!=0 or resumed.stdout.strip()!=b'CI_BACKUP_RECEIPT_VERIFIED_STRUCTURE_ONLY':
                stages={b'RECOVERY_SESSION',b'NEW_REDIS',b'BACKUP',b'RECEIPT'}
                found=re.findall(rb'(?m)^KUBE_COORDINATOR_CI_([A-Z_]+)\r?$',resumed.stderr)
                if found and found[-1] in stages:PHASE='CHILD_'+found[-1].decode('ascii')
                raise ValueError
        return {'synthetic_signed_executor_backup_receipt_verified':True,
                'production_stale_lock_recovery':False,'audit_integrity':'structure_only','safe_to_update':False}
    except Exception:raise CoordinatorCITestError('KUBE_COORDINATOR_CI_UNVERIFIED') from None
