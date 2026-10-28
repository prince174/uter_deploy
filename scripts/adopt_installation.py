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
from scripts import install as installer


def output(command, env=None):
    p = subprocess.run([str(x) for x in command], env=env, capture_output=True)
    if p.returncode:
        raise ValueError(f'{command[0]} inspection failed; output withheld because it may contain secrets')
    return p.stdout


def same_tree(left, right):
    return uterctl.inventory(left) == uterctl.inventory(right)


def verify_live(home, cfg, manifest):
    cmd, env = installer.commands(home, cfg)
    expected = manifest['images']
    if cfg['backend'] == 'compose':
        if cfg['context'] != 'default' or os.environ.get('DOCKER_HOST'):
            raise ValueError('Only the local default Docker context is supported')
        host = json.loads(output(['docker', '--context', 'default', 'context', 'inspect', 'default']))[0]['Endpoints']['docker']['Host']
        if not host.startswith('unix://'):
            raise ValueError('A local Unix Docker socket is required')
        for service, ref in expected.items():
            ids = output(cmd + ['ps', '-q', service], env).decode().split()
            if len(ids) != 1: raise ValueError(f'Expected exactly one running {service} container')
            running = json.loads(output(['docker', '--context', 'default', 'inspect', ids[0]]))[0]
            image = json.loads(output(['docker', '--context', 'default', 'image', 'inspect', ref]))[0]
            labels = running['Config'].get('Labels') or {}
            if (not running['State']['Running'] or labels.get('com.docker.compose.project') != cfg['name'] or
                    labels.get('com.docker.compose.service') != service or running['Config']['Image'] != ref or
                    running['Image'] != image['Id']):
                raise ValueError(f'Running {service} does not match the signed image')
            if manifest.get('image_config_ids') and image['Id'] != manifest['image_config_ids'][service]:
                # Docker's containerd image store may expose the manifest digest as Id.
                # Accept that representation only when the descriptor and signed ref agree.
                digest = ref.rsplit('@', 1)[-1]
                descriptor = image.get('Descriptor') or {}
                if image['Id'] != digest or descriptor.get('digest') != digest:
                    raise ValueError(f'Image configuration ID mismatch for {service}')
    else:
        kube = ['kubectl', '--context', cfg['context'], '-n', cfg['name']]
        pods = json.loads(output(kube + ['get', 'pods', '-o', 'json']))['items']
        for service, ref in expected.items():
            deployment = json.loads(output(kube + ['get', 'deployment', cfg['name']+'-'+service, '-o', 'json']))
            if deployment['spec']['template']['spec']['containers'][0]['image'] != ref:
                raise ValueError(f'Deployment {service} does not match the signed image')
            podset = [p for p in pods if p['metadata'].get('labels', {}).get('app.kubernetes.io/instance') == cfg['name']
                      and p['metadata'].get('labels', {}).get('app.kubernetes.io/name') == service
                      and not p['metadata'].get('deletionTimestamp')]
            expected_ids = {ref.split('@', 1)[1]}
            if manifest.get('image_config_ids'): expected_ids.add(manifest['image_config_ids'][service])
            valid = [c for p in podset if p['spec']['containers'][0]['image'] == ref
                     for c in p.get('status', {}).get('containerStatuses', []) if c.get('ready')
                     and any(c.get('imageID', '').endswith(x) for x in expected_ids)]
            if len(podset) != 1 or len(valid) != 1:
                raise ValueError(f'Expected one ready {service} pod with signed registry or configuration digest')


def adopt(home, bundle, key, smoke):
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
    if not isinstance(smoke, list) or not smoke or not all(isinstance(x, str) and x for x in smoke):
        raise ValueError('Smoke command must be a non-empty JSON argv array')
    if not same_tree(home/'compose', bundle/'compose') or not same_tree(home/'charts', bundle/'charts'):
        raise ValueError('Installation deployment assets do not match signed bundle')
    runtime = home/'runtime'
    site = {'backend': 'compose' if cfg['backend'] == 'compose' else 'helm', 'name': cfg['name'],
            'namespace': cfg['name'], 'context': context, 'port': cfg['port'],
            'guardrail_cpus': cfg.get('guardrail_cpus', 4), 'smoke_command': smoke}
    with uterctl.locked(home):
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
    print(f'Adopted {cfg["backend"]} installation {cfg["name"]}; workloads unchanged.')


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
