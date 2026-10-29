"""Extract a signed bundle into a new private directory after full verification."""
import argparse
import contextlib
import gzip
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True  # Signed bundles must remain byte-for-byte immutable.
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import uterctl

MAX_FILES=10000
MAX_EXPANDED=1024*1024*1024
# Tar headers, padding and small metadata add overhead beyond the file contents.
MAX_TAR_STREAM=MAX_EXPANDED+32*1024*1024
MAX_TAR_READ=2*1024*1024


class BoundedTarReader:
    """Bound logical output and tarfile reads before compressed metadata is parsed."""
    def __init__(self, stream):
        self.stream=stream
        self.work=0
        self.work_limit=4*MAX_TAR_STREAM

    def tell(self):
        return self.stream.tell()

    def charge(self, amount):
        if amount < 0 or self.work + amount > self.work_limit:
            raise ValueError('Decompressed tar processing exceeds limit')
        self.work += amount

    def read(self, size=-1):
        if size < 0 or size > MAX_TAR_READ:
            raise ValueError('Tar metadata or read request exceeds limit')
        if self.tell()+size > MAX_TAR_STREAM:
            raise ValueError('Decompressed tar stream exceeds limit')
        self.charge(size)
        return self.stream.read(size)

    def seek(self, offset, whence=os.SEEK_SET):
        current=self.tell()
        if whence == os.SEEK_SET:
            target=offset
        elif whence == os.SEEK_CUR:
            target=current+offset
        else:
            raise ValueError('Unsupported tar seek')
        if target < 0 or target > MAX_TAR_STREAM:
            raise ValueError('Decompressed tar stream exceeds limit')
        # A backward gzip seek may rewind and decompress again from the start.
        self.charge(target if target < current else target-current)
        return self.stream.seek(target, os.SEEK_SET)


@contextlib.contextmanager
def bounded_tar(archive):
    """Open gzip or raw tar without allowing special-file, link or metadata bombs."""
    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
    fd=os.open(archive,flags)
    with contextlib.ExitStack() as stack:
        source=stack.enter_context(os.fdopen(fd,'rb'))
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError('Archive must be a regular file')
        magic=source.read(6);source.seek(0)
        if magic.startswith(b'BZh') or magic.startswith(b'\xfd7zXZ\x00'):
            raise ValueError('Only gzip or uncompressed tar bundles are supported')
        stream=stack.enter_context(gzip.GzipFile(fileobj=source,mode='rb')) if magic.startswith(b'\x1f\x8b') else source
        tar=stack.enter_context(tarfile.open(fileobj=BoundedTarReader(stream),mode='r:'))
        yield tar


def extract(archive,key,destination):
    archive=Path(archive);destination=Path(destination).absolute()
    if archive.is_symlink() or not archive.is_file():raise ValueError('Archive must be a regular file')
    if destination.exists() or destination.is_symlink():raise ValueError('Destination already exists')
    parent=destination.parent.resolve(strict=True);destination=parent/destination.name
    with tempfile.TemporaryDirectory(prefix='.uter-bundle-',dir=parent) as tmp:
        staged=Path(tmp)/'bundle';staged.mkdir(mode=0o700)
        with bounded_tar(archive) as tar:
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
