"""Extract a signed bundle into a new private directory after full verification."""
import argparse
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import uterctl

MAX_FILES=10000
MAX_EXPANDED=1024*1024*1024


def extract(archive,key,destination):
    archive=Path(archive);destination=Path(destination).absolute()
    if archive.is_symlink() or not archive.is_file():raise ValueError('Archive must be a regular file')
    if destination.exists() or destination.is_symlink():raise ValueError('Destination already exists')
    parent=destination.parent.resolve(strict=True);destination=parent/destination.name
    with tempfile.TemporaryDirectory(prefix='.uter-bundle-',dir=parent) as tmp:
        staged=Path(tmp)/'bundle';staged.mkdir(mode=0o700)
        with tarfile.open(archive,'r:*') as tar:
            members=[];total=0
            for m in tar:
                total+=m.size
                if m.size<0 or len(members)>=MAX_FILES or total>MAX_EXPANDED:
                    raise ValueError('Archive exceeds extraction limits')
                members.append(m)
            if not members:raise ValueError('Archive is empty')
            seen=set()
            for m in members:
                if '\\' in m.name or m.name.startswith('/'):
                    raise ValueError('Unsafe bundle path')
                p=PurePosixPath(m.name)
                if not p.parts or p.parts[0]!='bundle' or '..' in p.parts:
                    raise ValueError('Unsafe bundle path')
                name=p.as_posix()
                if name in seen:raise ValueError('Duplicate bundle path')
                seen.add(name)
                if not (m.isdir() or m.isfile()):raise ValueError('Links and special files are forbidden')
            for m in members:
                relative=PurePosixPath(m.name).parts[1:]
                if not relative:
                    if not m.isdir():raise ValueError('Bundle root must be a directory')
                    continue
                target=staged.joinpath(*relative)
                if m.isdir():target.mkdir(mode=0o700,parents=True,exist_ok=True)
                else:
                    target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                    with os.fdopen(fd,'wb') as out,tar.extractfile(m) as src:
                        shutil.copyfileobj(src,out,1024*1024)
        manifest=uterctl.verify(staged,key)
        destination.mkdir(mode=0o700)
        marker=destination/'INCOMPLETE';marker.write_text('Verified bundle extraction is incomplete.\n')
        if os.name=='posix':marker.chmod(0o600)
        for item in staged.iterdir():item.rename(destination/item.name)
        marker.unlink()
        try:
            if uterctl.verify(destination,key)!=manifest:raise ValueError('Copied bundle verification failed')
        except BaseException:
            marker.write_text('Copied bundle verification failed.\n')
            if os.name=='posix':marker.chmod(0o600)
            raise
        return manifest


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',type=Path,required=True);p.add_argument('--key',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();result=extract(args.archive,args.key,args.output)
    print('Verified signed bundle:',result['version'])


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(f'bundle extraction: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
