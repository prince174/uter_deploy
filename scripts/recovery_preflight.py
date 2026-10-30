"""Authenticate a backup and stage the matching signed installation before recovery.

Preflight does not change workloads, restore data, or perform cutover.
"""
import argparse
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True  # Signed bundles must remain byte-for-byte immutable.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import backup_crypto, backup_store, restore_backup


def preflight(home, backup, backup_key, publisher_key, output):
    home=Path(home).resolve()
    key=backup_crypto.read_key(backup_key)
    # Authenticate before staging; identity is checked against staged state below.
    manifest=backup_store.verify_set(backup,key)
    live_site=uterctl.site_config(home) if home.exists() else None
    if live_site is not None:
        backup_store.verify_set(backup,key,home=home,site=live_site)
    output=Path(output).resolve()
    if output == home or output.is_relative_to(home):
        raise ValueError('Recovery staging must be outside the original installation')
    restore_backup.prepare_staging(backup,backup_key,output)
    marker=output/'INCOMPLETE'
    marker.write_text('Sensitive recovery data. Preflight has not completed.\n')
    if os.name=='posix': marker.chmod(0o600)
    staged=output/'runtime-staged'
    state=uterctl.read(staged/'state.json')
    config=uterctl.read(staged/'install.json')
    staged_site=uterctl.site_config(staged)
    backup_store.verify_set(backup,key,home=home,site=staged_site)
    if manifest['backend'] != staged_site['backend']:
        raise ValueError('Backup backend and staged installation state differ')
    site=live_site if live_site is not None else staged_site
    if state.get('adopted_installer') is not True or state.get('pending') is not None:
        raise ValueError('Backup must contain a completed adopted installation state')
    current=state.get('current')
    if not isinstance(current,dict) or current.get('version') != manifest['version']:
        raise ValueError('Backup version and recorded installation state differ')
    signed=uterctl.verify(staged/'releases'/manifest['version'],publisher_key)
    if signed != current:
        raise ValueError('Backed-up installation state does not match its signed release')
    for field in ('backend','name','namespace','context'):
        if staged_site.get(field) != site.get(field):
            raise ValueError('Backed-up installation identity does not match selected installation')
    expected_backend='kubernetes' if site['backend']=='helm' else 'compose'
    if (config.get('backend') != expected_backend or config.get('name') != site['name'] or
            config.get('context') != site.get('context')):
        raise ValueError('Backed-up installer identity does not match selected installation')
    if manifest['backend']=='helm':
        from scripts.backup_snapshot import kube_objects, maintenance_enabled, validate_maintenance_secret
        import yaml
        objects=json.loads((output/'kubernetes.json').read_text(encoding='utf-8'))
        if not isinstance(objects.get('items'),list): raise ValueError('Kubernetes resource list is missing')
        if any(item.get('metadata',{}).get('namespace') != site['namespace'] for item in objects['items']):
            raise ValueError('Kubernetes backup contains resources outside the installation namespace')
        kinds={'Secret':'secret','ConfigMap':'configmap','PersistentVolumeClaim':'pvc'}
        actual=[]
        for item in objects['items']:
            kind=kinds.get(item.get('kind'));name=item.get('metadata',{}).get('name')
            if not kind or not isinstance(name,str): raise ValueError('Unsupported Kubernetes backup resource')
            actual.append(kind+'/'+name)
        expected=kube_objects(staged,staged_site,manifest=signed)
        if len(actual)!=len(set(actual)) or set(actual)!=set(expected):
            raise ValueError('Kubernetes backup resources do not match installation configuration')
        values=yaml.safe_load((staged/'runtime/values.yaml').read_text())
        if maintenance_enabled(staged,values,staged_site,signed):
            name=staged_site['name']+'-maintenance'
            matches=[item for item in objects['items'] if item.get('kind')=='Secret'
                     and item.get('metadata',{}).get('name')==name]
            if len(matches)!=1: raise ValueError('Maintenance Secret missing or duplicated')
            validate_maintenance_secret(matches[0],name,staged_site['namespace'],home=staged)
    marker.unlink()
    return {'backup_id':manifest['id'],'version':manifest['version'],'backend':manifest['backend']}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--home',type=Path,required=True)
    p.add_argument('--backup',type=Path,required=True)
    p.add_argument('--backup-key',type=Path,required=True)
    p.add_argument('--publisher-key',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    result=preflight(a.home,a.backup,a.backup_key,a.publisher_key,a.output)
    print(json.dumps(result))
    print('Preflight only: workloads and volumes are unchanged; staging contains sensitive plaintext.')


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(f'recovery preflight: {type(exc).__name__}: {exc}',file=sys.stderr)
        sys.exit(1)
