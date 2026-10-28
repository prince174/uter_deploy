"""Build and verify an offline signed release from confirmed publication inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import bundle, release_manifest


def package(inputs,version,data_epoch,upgrade_from,private_key,public_key,expected_fingerprint,output):
    private=Path(private_key)
    if private.is_symlink() or not private.is_file():raise ValueError('Publisher private key must be a regular file')
    if private.resolve().is_relative_to(Path(__file__).resolve().parents[1]):
        raise ValueError('Publisher private key must be outside the repository')
    if os.name=='posix' and (private.stat().st_uid!=os.geteuid() or private.stat().st_mode & 0o077):
        raise ValueError('Publisher private key must be owner-only and owned by the current user')
    public=Path(public_key).read_bytes()
    actual=hashlib.sha256(public).hexdigest()
    if actual!=expected_fingerprint.lower():raise ValueError('Publisher public-key fingerprint does not match trusted value')
    output=Path(output)
    if output.exists() or output.is_symlink():raise ValueError('Release output already exists')
    manifest=release_manifest.make_manifest(inputs,version,data_epoch,upgrade_from)
    output.mkdir(mode=0o700,parents=False)
    marker=output/'INCOMPLETE';marker.write_text('Signed release packaging incomplete.\n')
    manifest_path=output/'manifest.json'
    manifest_path.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    bundle_dir=output/'bundle';bundle.build(manifest_path,bundle_dir,Path(private_key))
    if uterctl.verify(bundle_dir,public_key)!=manifest:raise ValueError('Signed release verification failed')
    archive=output/'signed-bundle.tar.gz'
    with tarfile.open(archive,'w:gz') as tar:tar.add(bundle_dir,arcname='bundle')
    with archive.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    (output/'signed-bundle.tar.gz.sha256').write_text(digest+'  '+archive.name+'\n',encoding='ascii')
    (output/'publisher-public.pem').write_bytes(public)
    marker.unlink()
    return {'version':version,'public_key_sha256':actual,'archive_sha256':digest,'upgrade_from':upgrade_from}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('inputs','private-key','public-key','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--version',required=True);p.add_argument('--data-epoch',type=int,required=True)
    p.add_argument('--upgrade-from',action='append',default=[]);p.add_argument('--expected-fingerprint',required=True)
    a=p.parse_args();print(json.dumps(package(a.inputs,a.version,a.data_epoch,a.upgrade_from,a.private_key,a.public_key,a.expected_fingerprint,a.output),indent=2))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(f'package release: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
