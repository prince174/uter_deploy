"""Build and verify an offline signed release from confirmed publication inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import bundle, release_manifest


def export_git_snapshot(destination):
    """Use tracked Git bytes, not platform-specific working-tree line endings."""
    root=Path(__file__).resolve().parents[1]
    commit=subprocess.check_output(['git','-C',str(root),'rev-parse','--verify','HEAD^{commit}'],text=True).strip()
    with tempfile.TemporaryFile() as stream:
        subprocess.run(['git','-C',str(root),'archive','--format=tar',commit,'--',
                        'compose','charts','docs','scripts','uterctl.py','requirements.txt','examples/redis.conf.example'],
                       stdout=stream,check=True)
        stream.seek(0)
        with tarfile.open(fileobj=stream,mode='r:') as tar:
            total=0;seen=set()
            for m in tar:
                p=PurePosixPath(m.name);total+=m.size
                if (p.is_absolute() or '..' in p.parts or '\\' in m.name or m.name in seen or
                        not (m.isdir() or m.isfile()) or m.size<0 or total>1024*1024*1024 or len(seen)>=10000):
                    raise ValueError('Unsafe deployment Git archive')
                seen.add(m.name);target=Path(destination).joinpath(*p.parts)
                if m.isdir():target.mkdir(mode=0o700,parents=True,exist_ok=True)
                else:
                    target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                    with target.open('xb') as out,tar.extractfile(m) as src:shutil.copyfileobj(src,out,1024*1024)
    return commit


def package(inputs,version,data_epoch,upgrade_from,private_key,public_key,expected_fingerprint,output, installation_archive=None):
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
    if installation_archive is not None:
        archive_path=Path(installation_archive)
        # Compare every archive member with the data used to construct the manifest.
        from scripts.extract_release_inputs import REQUIRED, OPTIONAL
        with tarfile.open(archive_path, 'r:gz') as tar:
            members=tar.getmembers(); names=[m.name for m in members]
            if len(names)!=len(set(names)) or not REQUIRED <= set(names) or set(names)-REQUIRED-OPTIONAL:
                raise ValueError('Unexpected installation archive contents')
            for member in members:
                if not member.isfile() or member.size>1024*1024:
                    raise ValueError('Unexpected installation archive member')
                path=Path(inputs)/member.name
                if not path.is_file() or path.is_symlink() or tar.extractfile(member).read()!=path.read_bytes():
                    raise ValueError('Installation archive differs from release inputs')
        with archive_path.open('rb') as stream:
            manifest['installation_archive_sha256']=hashlib.file_digest(stream,'sha256').hexdigest()
    output.mkdir(mode=0o700,parents=False)
    marker=output/'INCOMPLETE';marker.write_text('Signed release packaging incomplete.\n')
    with tempfile.TemporaryDirectory(prefix='.uter-source-',dir=output) as tmp:
        deployment_commit=export_git_snapshot(tmp)
        manifest['deployment_commit']=deployment_commit
        manifest_path=output/'manifest.json'
        manifest_path.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n',encoding='utf-8')
        bundle_dir=output/'bundle';bundle.build(manifest_path,bundle_dir,Path(private_key),source_root=tmp)
        verifier=subprocess.run([sys.executable,str(Path(tmp)/'uterctl.py'),'verify','--bundle',str(bundle_dir),
                                 '--key',str(public_key)],capture_output=True)
        if verifier.returncode:raise ValueError('Committed deployment verifier rejected the signed bundle')
    if uterctl.verify(bundle_dir,public_key)!=manifest:raise ValueError('Signed release verification failed')
    archive=output/'signed-bundle.tar.gz'
    def public_metadata(item):
        item.uid=item.gid=0;item.uname=item.gname='';item.mtime=0
        item.mode=0o755 if item.isdir() else 0o644
        return item
    with tarfile.open(archive,'w:gz') as tar:tar.add(bundle_dir,arcname='bundle',filter=public_metadata)
    with archive.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    (output/'signed-bundle.tar.gz.sha256').write_text(digest+'  '+archive.name+'\n',encoding='ascii')
    (output/'publisher-public.pem').write_bytes(public)
    marker.unlink()
    return {'version':version,'deployment_commit':deployment_commit,'public_key_sha256':actual,'archive_sha256':digest,'upgrade_from':upgrade_from}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('inputs','private-key','public-key','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--installation-archive',type=Path,required=True)
    p.add_argument('--version',required=True);p.add_argument('--data-epoch',type=int,required=True)
    p.add_argument('--upgrade-from',action='append',default=[]);p.add_argument('--expected-fingerprint',required=True)
    a=p.parse_args();print(json.dumps(package(a.inputs,a.version,a.data_epoch,a.upgrade_from,a.private_key,a.public_key,a.expected_fingerprint,a.output,a.installation_archive),indent=2))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(f'package release: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
