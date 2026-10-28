"""Strict archive validation without application or cryptography dependencies."""
import posixpath
import tarfile


def check_tar_members(archive):
    seen=set(); entries=0
    for member in archive:
        normalized=posixpath.normpath(member.name)
        if member.name.startswith('/') or '\\' in member.name or normalized=='..' or normalized.startswith('../'):
            raise ValueError('Unsafe path in backup archive')
        if not (member.isfile() or member.isdir()):
            raise ValueError('Links and special files are forbidden in backup archives')
        if normalized in seen: raise ValueError('Duplicate archive entry')
        seen.add(normalized);entries+=1
        if member.isfile():
            source=archive.extractfile(member)
            while source.read(1024*1024): pass
    if not entries: raise ValueError('Backup archive is empty')


def check_tar(path):
    with tarfile.open(path,'r:*') as archive: check_tar_members(archive)
