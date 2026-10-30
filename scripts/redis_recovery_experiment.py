"""Fixture-only preparation of a Redis snapshot; this never authorizes cutover.

The backup directory, installation identity and caller must be trusted and
protected from concurrent modification. The caller must keep plaintext in a
disposable environment; this function does not start Redis or verify contents.
"""
import io
from pathlib import Path

from scripts import backup_crypto, backup_store

MAX_RDB_BYTES=100*1024*1024


class RecoveryExperimentError(ValueError): pass


class Sink:
    def __init__(self): self._out=io.BytesIO()
    def write(self, data):
        if len(data)>MAX_RDB_BYTES-self._out.tell(): raise ValueError
        return self._out.write(data)
    def value(self): return self._out.getvalue()


def prepare(backup, *, key, home, site, version):
    """Authenticate all components twice before returning a bounded RDB copy."""
    try:
        if not isinstance(key,bytes) or len(key)!=32: raise ValueError
        manifest=backup_store.verify_set(backup,key,home=home,site=site,version=version)
        meta=manifest['files']['redis']
        if type(meta.get('plaintext_bytes')) is not int or not 5<=meta['plaintext_bytes']<=MAX_RDB_BYTES:
            raise ValueError
        sink=Sink()
        backup_crypto.decrypt_verify(Path(backup)/'redis.enc',key,
                                     backup_store.aad(manifest['id'],'redis'),meta,sink)
        rdb=sink.value()
        if len(rdb)!=meta['plaintext_bytes'] or not rdb.startswith(b'REDIS'): raise ValueError
        if backup_store.verify_set(backup,key,home=home,site=site,version=version)!=manifest: raise ValueError
        return {'rdb':rdb,'backup_id':manifest['id'],'safe_to_update':False,'safe_to_resume':False}
    except Exception:
        raise RecoveryExperimentError('REDIS_RECOVERY_FIXTURE_UNVERIFIED') from None
