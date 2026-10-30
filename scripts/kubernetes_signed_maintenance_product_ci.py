"""Fixture-only signed CLI preflight against an already isolated kind cluster.

All pins and signing keys originate on this CI runner. This does not establish
independent trust, fencing, a backup, an update or recovery.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import yaml

from scripts import bundle, kubernetes_fence_profile_store


class FixtureError(ValueError):
    pass


def exercise(*, root, work, home, kubeconfig, kube, site, context, images):
    expected_root=Path(__file__).resolve().parents[1]
    expected_work=expected_root/'work/maintenance-kubernetes'
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('RUNNER_OS') != 'Linux' or os.environ.get('DOCKER_HOST')
            or os.environ.get('DOCKER_CONTEXT', 'default') != 'default'
            or Path(root).resolve() != expected_root or Path(work).resolve() != expected_work
            or Path(home).resolve() != expected_work/'installation'
            or Path(kubeconfig).resolve() != expected_work/'kubeconfig'
            or site != 'uter-maint-ci' or context != 'kind-uter-maint-ci'
            or kube != ['/usr/bin/uter-ci-kubectl','--kubeconfig',str(kubeconfig),'--context',context]):
        raise FixtureError('KUBE_SIGNED_CI_BOUNDARY')
    def query(*args):
        result=subprocess.run([*map(str,kube),*args,'-o','json'],check=True,stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL,timeout=30)
        return json.loads(result.stdout)
    def uid(kind,name, *, namespaced=True):
        args=(['-n',site] if namespaced else [])+['get',kind,name]
        return query(*args)['metadata']['uid']
    private=Path(work)/'signed-cli-private'; private.mkdir(mode=0o700)
    backup_key=private/'backup-key'; backup_key.write_bytes(os.urandom(32)); backup_key.chmod(0o600)
    config=private/'kubeconfig'; config.write_bytes(Path(kubeconfig).read_bytes()); config.chmod(0o600)
    signer=Ed25519PrivateKey.generate()
    secret=private/'signing.pem'; secret.write_bytes(signer.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption())); secret.chmod(0o600)
    public=private/'publisher.pem'; public.write_bytes(signer.public_key().public_bytes(
        serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)); public.chmod(0o600)
    source=json.loads((Path(root)/'candidates/source.json').read_text())['source_commit']
    subprocess.run(['docker','--context','default','pull',images['redis']],check=True,
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=300)
    image_ids={}
    for service in ('agent','guardrail','redis'):
        image=images['redis'] if service == 'redis' else 'uter-'+service+'-protected'
        result=subprocess.run(['docker','--context','default','image','inspect','--format','{{.Id}}',image],
                              check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
        image_ids[service]=result.stdout.decode().strip()
    manifest={'schema':1,'config_schema':1,'tooling_schema':1,'status':'released','version':'0.1.7',
              'source_commit':source,'data_epoch':1,'upgrade_from':['0.1.6'],'images':images,
              'image_config_ids':image_ids,
              'maintenance_protocol':{'version':1,'services':['agent','guardrail']}}
    manifest_file=private/'manifest.json';manifest_file.write_text(json.dumps(manifest))
    executor=private/'executor'; bundle.build(manifest_file,executor,secret,source_root=root)
    # The local CI launcher and isolated Python are part of the test trust
    # boundary. No application output or generated secret is logged.
    chown_attempted=False
    try:
        if executor.resolve(strict=True) != private.resolve(strict=True)/'executor':
            raise FixtureError('KUBE_SIGNED_CI_BOUNDARY')
        chown_attempted=True
        subprocess.run(['sudo','chown','-R','0:0',str(executor)],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        runtime=Path(home)/'runtime';runtime.mkdir(mode=0o700,exist_ok=True)
        with (runtime/'site.json').open('x',encoding='utf-8') as stream:
            json.dump({'backend':'helm','name':site,'namespace':site,'context':context,
                       'smoke_command':['/bin/true']},stream)
        # Fixture-only controller state: no production adoption is being claimed.
        with (Path(home)/'state.json').open('x',encoding='utf-8') as stream:
            json.dump({'current':manifest,'previous':None,'pending':None,'adopted_installer':True},stream)
        raw=yaml.safe_load(config.read_bytes())
        cluster=raw['clusters'][0]['cluster']
        ca=base64.b64decode(cluster['certificate-authority-data'],validate=True)
        api={'schema':1,'context':context,'server_sha256':hashlib.sha256(cluster['server'].encode()).hexdigest(),
             'ca_sha256':hashlib.sha256(ca).hexdigest(),'kube_system_uid':uid('namespace','kube-system',namespaced=False),
             'namespace_uid':uid('namespace',site,namespaced=False),'redis_pvc_uid':uid('pvc',site+'-redis'),
             'redis_deployment_uid':uid('deployment',site+'-redis')}
        resources=list(yaml.safe_load_all((Path(home)/'resources.yaml').read_text()))
        objects={}
        for resource in resources:
            if isinstance(resource,dict) and resource.get('kind') in ('Secret','ConfigMap'):
                kind=resource['kind'].lower();name=resource['metadata']['name']
                objects[kind+'/'+name]=uid(kind,name)
        binary=Path('/usr/bin/uter-ci-kubectl')
        record={'schema':2,'site':site,'api':api,
                'writer_uids':{s:uid('deployment',site+'-'+s) for s in ('agent','guardrail')},
                'audit_pvc_uid':uid('pvc',site+'-guardrail'),
                'kubectl_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'object_uids':objects,
                'release_version':manifest['version'],
                'inventory_sha256':hashlib.sha256((executor/'checksums.json').read_bytes()).hexdigest(),
                'publisher_sha256':hashlib.sha256(public.read_bytes()).hexdigest()}
        profile=private/'profile';kubernetes_fence_profile_store.create(profile,backup_key.read_bytes(),record)
        args=[sys.executable,'-I','-B',str(executor/'uterctl.py'),'maintenance-check-kubernetes',
              '--home',str(home),'--bundle',str(executor),'--key',str(public),'--executor-key',str(public),
              '--backup-key',str(backup_key),'--kubeconfig',str(config),'--operator-profile',str(profile),
              '--kubectl',str(binary)]
        result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
        if result.returncode:
            allowed=('KUBE_PREFLIGHT_INSTALLATION_UNVERIFIED','KUBE_PREFLIGHT_IDENTITY_UNVERIFIED',
                     'KUBE_PIN_PROFILE_INVALID','KUBE_PIN_CONFIG_UNVERIFIED','KUBE_OPERATOR_PROFILE_UNVERIFIED',
                     'KUBE_OPERATOR_SESSION_UNVERIFIED','KUBE_OPERATOR_PROFILE_CHANGED',
                     'KUBE_OPERATOR_OBJECT_UNVERIFIED','KUBE_MAINTENANCE_PREFLIGHT_UNVERIFIED',
                     'KUBE_MAINTENANCE_CHECK_ARGUMENTS_REQUIRED','KUBE_MAINTENANCE_CHECK_PATH_NOT_ABSOLUTE',
                     'KUBE_EXECUTOR_MODULE_UNTRUSTED','FENCE_EXECUTOR_COMPONENT_MISSING')
            diagnostic=next((code for code in allowed if code.encode() in result.stderr),'UNCLASSIFIED')
            print('KUBE_SIGNED_CI_'+diagnostic,file=sys.stderr)
            raise FixtureError('KUBE_SIGNED_CI_CHECK_FAILED')
        value=json.loads(result.stdout)
        if value != {'application_endpoint_checked':False,'backend':'kubernetes','ingress_fenced':False,
                     'redis_isolated':False,'restart_fenced':False,'safe_to_update':False,'writers_observed':2}:
            raise FixtureError('KUBE_SIGNED_CI_RESULT_INVALID')
    finally:
        if chown_attempted:
            if executor.resolve(strict=True) != private.resolve(strict=True)/'executor':
                raise FixtureError('KUBE_SIGNED_CI_CLEANUP_UNCERTAIN')
            subprocess.run(['sudo','chown','-R',str(os.getuid())+':'+str(os.getgid()),str(executor)],check=True,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
