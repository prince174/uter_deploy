#!/usr/bin/env python3
"""Adopt an install.py installation without modifying its workloads."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True  # Signed bundles must remain byte-for-byte immutable.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import install as installer, install_recovery


def output(command, env=None):
    try:
        return install_recovery.run_readonly([str(x) for x in command], timeout=30, env=env).encode('utf-8')
    except install_recovery.DiagnosticError:
        raise ValueError('Runtime inspection failed; output withheld because it may contain secrets') from None


def same_tree(left, right):
    return uterctl.inventory(left) == uterctl.inventory(right)


def verify_live(home, cfg, manifest):
    cmd, env = installer.commands(home, cfg)
    expected = manifest['images']
    if cfg['backend'] == 'compose':
        if cfg['context'] != 'default' or os.environ.get('DOCKER_HOST'):
            raise ValueError('Only the local default Docker context is supported')
        host = json.loads(output(['docker', '--context', 'default', 'context', 'inspect', 'default',
                                  '--format', '{{json .Endpoints.docker.Host}}']))
        if not isinstance(host, str) or not host.startswith('unix://'):
            raise ValueError('A local Unix Docker socket is required')
        for service, ref in expected.items():
            ids = output(cmd + ['ps', '-q', service], env).decode().split()
            if len(ids) != 1 or not re.fullmatch(r'[0-9a-f]{12,64}', ids[0]):
                raise ValueError(f'Expected exactly one running {service} container')
            # Never request Config.Env or full inspect data: env contains secrets.
            fmt = ('{"running":{{json .State.Running}},'
                   '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                   '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
                   '"config_image":{{json .Config.Image}},"image":{{json .Image}}}')
            running = json.loads(output(['docker', '--context', 'default', 'inspect', '--format', fmt, ids[0]]))
            image_id = json.loads(output(['docker', '--context', 'default', 'image', 'inspect', '--format', '{{json .Id}}', ref]))
            if (not isinstance(running, dict) or not isinstance(image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id)
                    or running.get('running') is not True or running.get('project') != cfg['name']
                    or running.get('service') != service or running.get('config_image') != ref
                    or running.get('image') != image_id):
                raise ValueError(f'Running {service} does not match the signed image')
            if manifest.get('image_config_ids') and image_id != manifest['image_config_ids'][service]:
                # Docker's containerd image store may expose the manifest digest as Id.
                # Accept that representation only when the descriptor and signed ref agree.
                digest = ref.rsplit('@', 1)[-1]
                if image_id != digest:
                    raise ValueError(f'Image configuration ID mismatch for {service}')
                descriptor = json.loads(output(['docker', '--context', 'default', 'image', 'inspect', '--format',
                                                '{{json .Descriptor.Digest}}', ref]))
                if descriptor != digest:
                    raise ValueError(f'Image configuration ID mismatch for {service}')
    else:
        kube = ['kubectl', '--context', cfg['context'], '-n', cfg['name']]
        for service, ref in expected.items():
            def field(kind, name, expression):
                return output(kube + ['get', kind, name, '-o', 'jsonpath=' + expression]).decode().strip()
            if field('deployment', cfg['name']+'-'+service, '{.spec.template.spec.containers[0].image}') != ref:
                raise ValueError(f'Deployment {service} does not match the signed image')
            selector = 'app.kubernetes.io/instance='+cfg['name']+',app.kubernetes.io/name='+service
            names = output(kube + ['get', 'pods', '-l', selector, '-o',
                                   'jsonpath={range .items[*]}{.metadata.name}{"\\n"}{end}']).decode().splitlines()
            if len(names) > 1000 or any(len(n) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', n) for n in names):
                raise ValueError(f'Invalid {service} pod inventory')
            podset = [n for n in names if not field('pod', n, '{.metadata.deletionTimestamp}')]
            expected_ids = {ref.split('@', 1)[1]}
            if manifest.get('image_config_ids'): expected_ids.add(manifest['image_config_ids'][service])
            if len(podset) != 1:
                raise ValueError(f'Expected one ready {service} pod with signed registry or configuration digest')
            pod = podset[0]
            image = field('pod', pod, '{.spec.containers[0].image}')
            prefix = '{.status.containerStatuses[?(@.name=="' + service + '")]'
            ready = field('pod', pod, prefix + '.ready}')
            image_id = field('pod', pod, prefix + '.imageID}')
            if image != ref or ready != 'true' or not any(image_id.endswith(x) for x in expected_ids):
                raise ValueError(f'Expected one ready {service} pod with signed registry or configuration digest')


def adopt(home, bundle, key, smoke, *, prepare_smoke=None):
    home = Path(home).resolve(strict=True); bundle = Path(bundle).resolve(strict=True)
    manifest = uterctl.verify(bundle, key)
    cfg = uterctl.read(home/'install.json')
    if cfg.get('backend') not in ('compose', 'kubernetes') or cfg.get('images') != manifest['images']:
        raise ValueError('Installer backend or image references do not match signed bundle')
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,38}[a-z0-9]', cfg.get('name', '')):
        raise ValueError('Invalid installation name')
    context = cfg.get('context')
    if not isinstance(context, str) or not context or context.startswith('-'):
        raise ValueError('Explicit installation context required')
    if uterctl.read(home/'install-state.json').get('status') != 'ready':
        raise ValueError('Installation is not in ready state')
    if prepare_smoke is None and (not isinstance(smoke, list) or not smoke or not all(isinstance(x, str) and x for x in smoke)):
        raise ValueError('Smoke command must be a non-empty JSON argv array')
    if prepare_smoke is not None and (smoke is not None or not callable(prepare_smoke)):
        raise ValueError('Invalid managed smoke preparation')
    if not same_tree(home/'compose', bundle/'compose') or not same_tree(home/'charts', bundle/'charts'):
        raise ValueError('Installation deployment assets do not match signed bundle')
    runtime = home/'runtime'
    site = {'backend': 'compose' if cfg['backend'] == 'compose' else 'helm', 'name': cfg['name'],
            'namespace': cfg['name'], 'context': context, 'port': cfg['port'],
            'guardrail_cpus': cfg.get('guardrail_cpus', 4), 'smoke_command': smoke}
    with uterctl.locked(home):
        if os.path.lexists(home/'redis-fence-operation.json'):
            raise ValueError('REDIS_FENCE_REQUIRES_INSPECTION')
        smoke_files = []
        if prepare_smoke is not None:
            smoke, smoke_files = prepare_smoke()
            if not isinstance(smoke, list) or not smoke or not all(isinstance(x, str) and x for x in smoke):
                for path in smoke_files: path.unlink(missing_ok=True)
                raise ValueError('Smoke command must be a non-empty JSON argv array')
            site['smoke_command'] = smoke
        try:
            _adopt_locked(home, bundle, key, smoke, manifest, cfg, runtime, site)
        except BaseException:
            for path in smoke_files: path.unlink(missing_ok=True)
            raise
    print(f'Adopted {cfg["backend"]} installation {cfg["name"]}; workloads unchanged.')


def _adopt_locked(home, bundle, key, smoke, manifest, cfg, runtime, site):
    """Caller owns the controller lock and has checked the fence marker."""
    for path in (home/'state.json', runtime/'site.json', runtime/'values.yaml', home/'releases'/manifest['version']):
        if path.exists(): raise ValueError('Controller adoption destination already exists; refusing overwrite')
    verify_live(home, cfg, manifest)
    # The operator-supplied smoke command must succeed before state is adopted.
    result = subprocess.run(smoke, cwd=runtime, capture_output=True)
    if result.returncode: raise ValueError('Pre-adoption smoke failed; output withheld')
    destination = home/'releases'/manifest['version']
    destination.parent.mkdir(exist_ok=True)
    created = []
    try:
        with tempfile.TemporaryDirectory(dir=destination.parent) as tmp:
            staged = Path(tmp)/'bundle'
            shutil.copytree(bundle, staged)
            if uterctl.verify(staged, key) != manifest: raise ValueError('Staged bundle changed')
            staged.rename(destination);created.append(destination)
        if cfg['backend'] == 'kubernetes':
            with (runtime/'values.yaml').open('xb') as f: f.write((home/'values.yaml').read_bytes())
            created.append(runtime/'values.yaml')
        with (runtime/'site.json').open('x', encoding='utf-8') as f: json.dump(site, f, indent=2)
        os.chmod(runtime/'site.json', 0o600);created.append(runtime/'site.json')
        uterctl.site_config(home)
        uterctl.write(home/'state.json', {'current': manifest, 'previous': None, 'pending': None,
                                           'adopted_installer': True})
    except BaseException:
        for path in reversed(created):
            if path.is_dir(): shutil.rmtree(path)
            else: path.unlink(missing_ok=True)
        raise


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--home',type=Path,required=True);p.add_argument('--bundle',type=Path,required=True)
    p.add_argument('--key',type=Path,required=True);p.add_argument('--smoke-argv-json',type=Path,required=True)
    args=p.parse_args()
    adopt(args.home,args.bundle,args.key,json.loads(args.smoke_argv_json.read_text(encoding='utf-8')))


if __name__=='__main__':
    try: main()
    except (ValueError,OSError,KeyError,TypeError) as exc:
        print(f'adopt: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
