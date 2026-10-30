"""Authenticate exact runtime files and the encrypted archive contents."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import posixpath
import stat
import tarfile
import threading

from scripts import backup_crypto, backup_installation, backup_store, kubernetes_writer_quiesce as storage

NAME='kubernetes-runtime-pin.json'
NAMES=('runtime','install.json','install-state.json','credentials.json','empty.env','values.yaml','resources.yaml','state.json','releases')
MAX_FILE=128*1024*1024


class RuntimePinError(ValueError):pass


def _digest(key,data):return hmac.new(backup_crypto.derive_key(key,b'kubernetes-runtime-v1'),data,hashlib.sha256).hexdigest()


def _combined(key,entries):
    raw=json.dumps(sorted(entries),ensure_ascii=True,separators=(',',':')).encode()
    return _digest(key,raw)


def _inventory(home,key):
    home=backup_installation.private_directory(home);entries=[]
    def add(path):
        info=path.lstat();relative=path.relative_to(home).as_posix()
        if stat.S_ISLNK(info.st_mode):raise ValueError
        if stat.S_ISDIR(info.st_mode):
            if info.st_uid not in (0,os.geteuid()) or info.st_mode&0o022:raise ValueError
            backup_installation.checked_existing_path(path)
            entries.append([relative,'dir',''])
            for child in sorted(path.iterdir(),key=lambda x:x.name):add(child)
        elif stat.S_ISREG(info.st_mode):
            raw=backup_installation.safe_file(path,limit=MAX_FILE)
            entries.append([relative,'file',_digest(key,raw)])
        else:raise ValueError
    for name in NAMES:
        path=home/name
        if os.path.lexists(path):add(path)
    return _combined(key,entries)


def seal(session,operation,key):
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        if backup_installation.safe_file(session._key_path,private=True,limit=32)!=key:raise ValueError
        session.reverify()
        value={'schema':1,'operation':operation,'profile_sha256':session._profile_digest,
               'runtime_hmac':_inventory(session.home,key)}
        storage._write(session.home,NAME,value,key)
        session._guard()
        return {'runtime_pin_saved':True,'safe_to_update':False}
    except Exception:raise RuntimePinError('KUBE_RUNTIME_PIN_UNVERIFIED') from None


def verify(session,operation,key):
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        if backup_installation.safe_file(session._key_path,private=True,limit=32)!=key:raise ValueError
        session._guard();value=storage._read(session.home,NAME,key)
        if (set(value)!={'schema','operation','profile_sha256','runtime_hmac'} or type(value['schema']) is not int
                or value['schema']!=1 or value['operation']!=operation or value['profile_sha256']!=session._profile_digest
                or not hmac.compare_digest(value['runtime_hmac'],_inventory(session.home,key))):raise ValueError
        session._guard();return value['runtime_hmac']
    except Exception:raise RuntimePinError('KUBE_RUNTIME_CHANGED') from None


def verify_archive(writer,key,expected):
    """Compare each decrypted tar entry to the independently pinned runtime."""
    read_fd,write_fd=os.pipe();errors=[];entries=[];seen=set()
    def decrypt():
        try:
            with os.fdopen(write_fd,'wb') as sink:
                backup_crypto.decrypt_verify(writer.path/'runtime.enc',key,backup_store.aad(writer.manifest['id'],'runtime'),
                                             writer.manifest['files']['runtime'],sink)
        except BaseException:errors.append(True)
    thread=threading.Thread(target=decrypt,daemon=True);thread.start()
    try:
        with os.fdopen(read_fd,'rb') as stream:
            with tarfile.open(fileobj=stream,mode='r|*') as archive:
                for item in archive:
                    name=posixpath.normpath(item.name)
                    if (item.name.startswith('/') or '\\' in item.name or name in ('.','..') or name.startswith('../')
                            or name in seen or name.split('/')[0] not in NAMES or not (item.isdir() or item.isfile())):
                        raise ValueError
                    seen.add(name)
                    if item.isdir():entries.append([name,'dir','']);continue
                    if item.size<0 or item.size>MAX_FILE:raise ValueError
                    mac=hmac.new(backup_crypto.derive_key(key,b'kubernetes-runtime-v1'),digestmod=hashlib.sha256)
                    with archive.extractfile(item) as source:
                        while True:
                            chunk=source.read(1024*1024)
                            if not chunk:break
                            mac.update(chunk)
                    entries.append([name,'file',mac.hexdigest()])
            while stream.read(1024*1024):pass
        thread.join(timeout=300)
        if thread.is_alive() or errors or not hmac.compare_digest(_combined(key,entries),expected):raise ValueError
    except Exception:raise RuntimePinError('KUBE_RUNTIME_ARCHIVE_UNVERIFIED') from None
    finally:
        thread.join(timeout=10)
