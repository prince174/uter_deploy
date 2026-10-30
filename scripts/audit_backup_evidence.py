"""Experimental backup/maintenance audit comparison; never authorizes mutation.

The caller must independently authenticate the operation scope and hold its
lock throughout. `strict_auditor` is a trusted injected verifier, not proof of
image identity: only a separately isolated CI adapter may supply it. Plaintext
is bounded and kept in memory here. No production backup/update path uses this.
"""
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import tarfile

from scripts import backup_crypto, backup_store, maintenance_protocol, redis_fence_journal as journal

LIMIT = 128 * 1024 * 1024
MAX_ENTRIES = 10000


class AuditEvidenceError(ValueError):
    pass


class _Sink:
    def __init__(self): self.data = bytearray()
    def write(self, block):
        if len(block) > LIMIT-len(self.data): raise ValueError
        self.data.extend(block)
        return len(block)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise ValueError
        result[key] = value
    return result


def _files(data):
    """Read safe regular files only, rejecting duplicates, links and overflow."""
    files = {}; seen = set(); total = 0; count = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
        for item in archive:
            count += 1
            name = posixpath.normpath(item.name)
            if (count > MAX_ENTRIES or item.name.startswith('/') or '\\' in item.name
                    or name == '..' or name.startswith('../') or name in seen
                    or not (item.isdir() or item.isfile())):
                raise ValueError
            seen.add(name)
            if item.isfile():
                if item.size < 0 or item.size > LIMIT-total: raise ValueError
                source = archive.extractfile(item)
                if source is None: raise ValueError
                raw = source.read(item.size+1)
                if len(raw) != item.size: raise ValueError
                total += len(raw); files[name] = raw
    if not seen: raise ValueError
    return files


def _audit_files(files):
    """Require active file, contiguous rotations and an unbroken first genesis."""
    normalized = {}
    for name, value in files.items():
        leaf = name.removeprefix('audit/')
        if not re.fullmatch(r'audit\.jsonl(?:\.[1-9][0-9]{0,3})?', leaf): raise ValueError
        if leaf in normalized: raise ValueError
        normalized[leaf] = value
    if 'audit.jsonl' not in normalized: raise ValueError
    rotations = sorted(int(x.split('.')[-1]) for x in normalized if x != 'audit.jsonl')
    if rotations != list(range(1, len(rotations)+1)): raise ValueError
    oldest = 'audit.jsonl.'+str(rotations[-1]) if rotations else 'audit.jsonl'
    for name, raw in normalized.items():
        lines = [line for line in raw.splitlines() if line.strip()]
        if not lines: raise ValueError
        for index, line in enumerate(lines):
            item = json.loads(line, object_pairs_hook=_pairs)
            if not isinstance(item, dict): raise ValueError
            if index == 0:
                if type(item.get('audit_seq')) is not int or item['audit_seq'] != 1 or item.get('audit_prev_hash') is not None:
                    raise ValueError
                if name == oldest and 'audit_rotation_prev_hash' in item: raise ValueError
            elif item.get('audit_seq') == 1 and item.get('audit_prev_hash') is None:
                raise ValueError
    return normalized


def _decrypt(backup, key, manifest, label):
    meta = manifest['files'][label]
    if type(meta.get('plaintext_bytes')) is not int or not 0 < meta['plaintext_bytes'] <= LIMIT:
        raise ValueError
    sink = _Sink()
    backup_crypto.decrypt_verify(Path(backup)/(label+'.enc'), key,
                                 backup_store.aad(manifest['id'], label), meta, sink)
    return bytes(sink.data)


def verify(*, home, backup, key, bundle, publisher, recorder, site, resource, instance, boot, strict_auditor):
    """Compare one authenticated backup and receipt; return authenticated evidence.

    `strict_auditor(files, audit_key, image)` must execute the exact signed
    Guardrail verifier with strict=True and return only its fixed aggregate
    fields. It is trusted by this experimental library; this is not a production
    image-execution boundary or proof of continuous Redis/ingress isolation.
    Backup directory contents must be locally controlled and trusted against
    concurrent modification and size-based denial of service. This profile
    requires full history from genesis and intentionally rejects a history
    whose old rotations have expired under normal retention.
    """
    try:
        if not isinstance(key, bytes) or len(key) != 32 or not callable(strict_auditor): raise ValueError
        if (Path(home).resolve(strict=True) != recorder.home.resolve(strict=True)
                or not hmac.compare_digest(recorder.key,backup_crypto.derive_key(key,b'maintenance-evidence-v1'))):
            raise ValueError
        before = recorder._read_scope(site['name'], resource)
        if (before['backend'] != ('kubernetes' if site['backend'] == 'helm' else 'compose')
                or site.get('namespace') != site['name']): raise ValueError
        receipt = recorder.read_receipt('guardrail', instance, boot, site=site['name'], resource=resource)
        product = maintenance_protocol.verify_capability(bundle, publisher)
        bundle_hash=hashlib.sha256((Path(bundle)/'checksums.json').read_bytes()).hexdigest()
        manifest = backup_store.verify_set(backup, key, home=home, site=site, version=product['version'])
        if manifest['backend'] != site['backend']: raise ValueError
        runtime = _files(_decrypt(backup, key, manifest, 'runtime'))
        audit_key = runtime.get('runtime/audit-hmac-key')
        if not isinstance(audit_key, bytes) or not 1 <= len(audit_key) <= 4096: raise ValueError
        audit_key = audit_key.decode('utf-8').strip()
        if not audit_key: raise ValueError
        logs = _audit_files(_files(_decrypt(backup, key, manifest, 'audit')))
        result = strict_auditor(logs, audit_key, product['images']['guardrail'])
        audit = receipt['evidence']['audit']
        if (not isinstance(result, dict) or set(result) != {'last_seq','last_hash','files_verified','verified_entries',
                                                           'segments_verified','hmac_enabled','ignored_trailing_entries',
                                                           'ignored_orphan_entries','ignored_malformed_entries','legacy_entries_skipped'}
                or type(result['last_seq']) is not int or result['last_seq'] != audit['last_seq']
                or not isinstance(result['last_hash'],str) or result['last_hash'] != audit['last_hash']
                or type(result['files_verified']) is not int or result['files_verified'] != len(logs)
                or type(result['verified_entries']) is not int or result['verified_entries'] < len(logs)
                or type(result['segments_verified']) is not int or result['segments_verified'] != 1
                or result['hmac_enabled'] is not True
                or any(type(result[x]) is not int or result[x] != 0 for x in
                       ('ignored_trailing_entries','ignored_orphan_entries','ignored_malformed_entries','legacy_entries_skipped'))):
            raise ValueError
        if recorder._read_scope(site['name'], resource) != before: raise ValueError
        if recorder.read_receipt('guardrail', instance, boot, site=site['name'], resource=resource) != receipt: raise ValueError
        if backup_store.verify_set(backup, key, home=home, site=site, version=product['version']) != manifest: raise ValueError
        if maintenance_protocol.verify_capability(bundle, publisher) != product: raise ValueError
        if hashlib.sha256((Path(bundle)/'checksums.json').read_bytes()).hexdigest()!=bundle_hash: raise ValueError
        binding = {'schema':1,'operation':before['operation'],'backend':before['backend'],'site':site['name'],
                   'resource':resource,'plan_sha256':before['plan_sha256'],'boot_id':boot,
                   'instance_sha256':hashlib.sha256(instance.encode()).hexdigest(),
                   'backup_id':manifest['id'],'audit_sha256':manifest['files']['audit']['sha256'],
                   'runtime_sha256':manifest['files']['runtime']['sha256'],
                   'manifest_sha256':hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                   'bundle_sha256':bundle_hash,
                   'guardrail_image':product['images']['guardrail'], 'audit_last_seq':audit['last_seq'],
                   'audit_last_hash':audit['last_hash'],'audit_files':len(logs)}
        raw=json.dumps(binding,sort_keys=True,separators=(',',':')).encode()
        mac=hmac.new(backup_crypto.derive_key(key,b'audit-maintenance-evidence-v1'),raw,hashlib.sha256).hexdigest()
        if recorder._read_scope(site['name'], resource) != before: raise ValueError
        return {'record':binding,'mac':mac,'safe_to_backup':False,'safe_to_update':False}
    except Exception:
        raise AuditEvidenceError('AUDIT_BACKUP_COMPARISON_UNVERIFIED') from None


def save(evidence, *, home, key, recorder, site, resource):
    """Persist the exact HMAC-bound comparison once, without authorizing actions."""
    try:
        if (not isinstance(key,bytes) or len(key)!=32 or Path(home).resolve(strict=True)!=recorder.home.resolve(strict=True)
                or not hmac.compare_digest(recorder.key,backup_crypto.derive_key(key,b'maintenance-evidence-v1'))):
            raise ValueError
        before=recorder._read_scope(site,resource)
        if (not isinstance(evidence,dict) or set(evidence)!={'record','mac','safe_to_backup','safe_to_update'}
                or evidence['safe_to_backup'] is not False or evidence['safe_to_update'] is not False):raise ValueError
        record=evidence['record']
        if (not isinstance(record,dict) or any(record.get(k)!=before[k] for k in ('operation','backend','site','resource','plan_sha256'))):
            raise ValueError
        raw=json.dumps(record,sort_keys=True,separators=(',',':')).encode()
        expected=hmac.new(backup_crypto.derive_key(key,b'audit-maintenance-evidence-v1'),raw,hashlib.sha256).hexdigest()
        if not isinstance(evidence['mac'],str) or not hmac.compare_digest(evidence['mac'],expected):raise ValueError
        encoded=json.dumps(evidence,sort_keys=True,separators=(',',':')).encode()+b'\n'
        if len(encoded)>16384:raise ValueError
        directory=journal._directory(home)
        try:
            name='audit-maintenance-match-'+before['operation']+'.json'
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as stream:
                os.fchmod(stream.fileno(),0o600);stream.write(encoded);stream.flush();os.fsync(stream.fileno())
            os.fsync(directory)
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
                        or info.st_mode&0o077 or info.st_size!=len(encoded) or stream.read(len(encoded)+1)!=encoded):
                    raise ValueError
        finally:
            os.close(directory)
        if recorder._read_scope(site,resource)!=before:raise ValueError
        return name
    except Exception:
        raise AuditEvidenceError('AUDIT_BACKUP_EVIDENCE_WRITE_UNCERTAIN') from None
