"""Build intentionally artificial writer images for disposable CI only.

These are derived from public image digests but add a wrapper returning zero on
SIGTERM. They are not product images or evidence of graceful application drain.
"""
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

REGISTRY='registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'
REGISTRY_HOST='localhost:5055'
MEDIA=', '.join(('application/vnd.oci.image.index.v1+json','application/vnd.oci.image.manifest.v1+json',
                 'application/vnd.docker.distribution.manifest.list.v2+json',
                 'application/vnd.docker.distribution.manifest.v2+json'))


class SyntheticImageError(ValueError):pass


def _stage(name,action):
    try:return action()
    except Exception:raise SyntheticImageError('PAIR_'+name) from None


def guard(root):
    if (os.name!='posix' or os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true'
            or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('RUNNER_OS')!='Linux'
            or os.environ.get('UTER_CI_STRICT_RUNNER')!='true' or os.environ.get('BACKEND')!='compose'
            or os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT','default')!='default'
            or not Path(root).is_absolute() or not Path(root).resolve(strict=True).is_relative_to(Path('/tmp'))):
        raise SyntheticImageError('SYNTHETIC_IMAGE_CI_ONLY')


def registry_digest(repository,tag):
    if not re.fullmatch(r'uter-ci-(?:guardrail|agent)',repository) or tag not in ('old','target'):
        raise SyntheticImageError('SYNTHETIC_IMAGE_INVALID')
    request=urllib.request.Request('http://127.0.0.1:5055/v2/'+repository+'/manifests/'+tag,
                                   headers={'Accept':MEDIA},method='HEAD')
    with urllib.request.urlopen(request,timeout=20) as response:
        digest=response.headers.get('Docker-Content-Digest','')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',digest):raise SyntheticImageError('SYNTHETIC_IMAGE_INVALID')
    return REGISTRY_HOST+'/'+repository+'@'+digest


def build(root,images,run):
    """Return old/target image and config IDs. Caller owns disposable daemon."""
    guard(root);root=Path(root);script=Path(__file__).with_name('ci_synthetic_writer_wrapper.py')
    if script.is_symlink() or not script.is_file() or set(images)!={'guardrail','agent','redis'}:
        raise SyntheticImageError('SYNTHETIC_IMAGE_INVALID')
    _stage('REGISTRY_START',lambda:run(['docker','--context','default','run','-d','--name','uter-ci-synthetic-registry',
         '--restart','no','--publish','127.0.0.1:5055:5000',REGISTRY],timeout=300))
    for attempt in range(30):
        try:
            with urllib.request.urlopen('http://127.0.0.1:5055/v2/',timeout=2) as response:
                if response.status==200:break
        except OSError:pass
        time.sleep(1)
    else:raise SyntheticImageError('PAIR_REGISTRY_READY')
    result={generation:{} for generation in ('old','target')}
    ids={generation:{} for generation in ('old','target')}
    for service in ('guardrail','agent'):
        reference=images[service]
        if not re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}',reference):raise SyntheticImageError('SYNTHETIC_IMAGE_INVALID')
        _stage('BASE_PULL',lambda:run(['docker','--context','default','pull',reference],timeout=600))
        fmt='{"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}}}'
        config=json.loads(run(['docker','--context','default','image','inspect','--format',fmt,reference]))
        if not isinstance(config,dict) or set(config)!={'entrypoint','cmd'}:raise SyntheticImageError('SYNTHETIC_IMAGE_INVALID')
        command=(config['entrypoint'] or [])+(config['cmd'] or [])
        if not command or any(not isinstance(item,str) or not item or '\x00' in item for item in command):
            raise SyntheticImageError('SYNTHETIC_IMAGE_INVALID')
        directory=root/('build-'+service);directory.mkdir(mode=0o700)
        (directory/'wrapper.py').write_bytes(script.read_bytes())
        for generation in ('old','target'):
            tag=REGISTRY_HOST+'/uter-ci-'+service+':'+generation
            dockerfile=('FROM '+reference+'\nCOPY wrapper.py /uter-ci-wrapper.py\n'
                        'LABEL io.uter.ci.synthetic="true" io.uter.ci.generation="'+generation+'"\n'
                        'ENTRYPOINT ["python", "/uter-ci-wrapper.py"]\nCMD '+json.dumps(command)+'\n')
            (directory/'Dockerfile').write_text(dockerfile)
            _stage('BUILD',lambda:run(['docker','--context','default','build','--pull=false','--tag',tag,str(directory)],timeout=900))
            label_fmt=('{"synthetic":{{json (index .Config.Labels "io.uter.ci.synthetic")}},'
                       '"generation":{{json (index .Config.Labels "io.uter.ci.generation")}}}')
            labels=json.loads(run(['docker','--context','default','image','inspect','--format',label_fmt,tag]))
            if labels!={'synthetic':'true','generation':generation}:raise SyntheticImageError('PAIR_LABELS')
            config_id=json.loads(run(['docker','--context','default','image','inspect','--format','{{json .Id}}',tag]))
            if not isinstance(config_id,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',config_id):raise SyntheticImageError('SYNTHETIC_IMAGE_INVALID')
            _stage('PUSH_LOCAL',lambda:run(['docker','--context','default','push',tag],timeout=600))
            digest=_stage('PUSH_LOCAL',lambda:registry_digest('uter-ci-'+service,generation))
            if not digest.startswith(REGISTRY_HOST+'/uter-ci-'+service+'@sha256:'):
                raise SyntheticImageError('SYNTHETIC_IMAGE_INVALID')
            _stage('PULL_DIGEST',lambda:run(['docker','--context','default','pull',digest],timeout=600))
            result[generation][service]=digest;ids[generation][service]=config_id
    if not re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}',images['redis']):raise SyntheticImageError('SYNTHETIC_IMAGE_INVALID')
    _stage('REDIS_PULL',lambda:run(['docker','--context','default','pull',images['redis']],timeout=600))
    redis_id=json.loads(run(['docker','--context','default','image','inspect','--format','{{json .Id}}',images['redis']]))
    if not isinstance(redis_id,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',redis_id):raise SyntheticImageError('SYNTHETIC_IMAGE_INVALID')
    result['old']['redis']=result['target']['redis']=images['redis']
    ids['old']['redis']=ids['target']['redis']=redis_id
    return result,ids
