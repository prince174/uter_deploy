"""Bind experimental Redis and audit observations to one authenticated backup.

The Redis restore oracle and audit verifier are trusted fixture dependencies,
not production isolation boundaries. This module never authorizes a mutation,
proves continuous writer exclusion, or verifies recovery of a whole service.
"""
import hashlib
import hmac
import json
from pathlib import Path
import re

from scripts import backup_crypto, backup_store, maintenance_protocol, redis_recovery_experiment


class EvidenceError(ValueError):pass


AUDIT_FIELDS={'schema','operation','backend','site','resource','plan_sha256','boot_id','instance_sha256',
              'backup_id','audit_sha256','runtime_sha256','manifest_sha256','bundle_sha256',
              'guardrail_image','audit_last_seq','audit_last_hash','audit_files'}
REDIS_FIELDS={'schema','operation','backend','site','resource','plan_sha256','backup_id','manifest_sha256',
              'redis_sha256','redis_plaintext_sha256','fingerprint','databases','keys'}


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()
def sign(key,purpose,value):return hmac.new(backup_crypto.derive_key(key,purpose),canonical(value),hashlib.sha256).hexdigest()
def hex64(value):return isinstance(value,str) and re.fullmatch(r'[0-9a-f]{64}',value) is not None


def context(home,key,recorder,site,resource):
    if (not isinstance(key,bytes) or len(key)!=32 or Path(home).resolve(strict=True)!=recorder.home.resolve(strict=True)
            or not hmac.compare_digest(recorder.key,backup_crypto.derive_key(key,b'maintenance-evidence-v1'))):raise ValueError
    state=recorder._read_scope(site['name'],resource)
    if (site.get('namespace')!=site['name'] or site['backend'] not in ('compose','helm')
            or state['backend']!=('kubernetes' if site['backend']=='helm' else 'compose')):raise ValueError
    return state


def scope(state):return {name:state[name] for name in ('operation','backend','site','resource','plan_sha256')}


def check_fingerprint(value):
    if (not isinstance(value,dict) or set(value)!={'schema','digest','databases','keys','rdb_compared','safe_to_resume'}
            or type(value['schema']) is not int or value['schema']!=1 or not hex64(value['digest'])
            or type(value['databases']) is not int or not 1<=value['databases']<=64
            or type(value['keys']) is not int or not 1<=value['keys']<=100000
            or value['rdb_compared'] is not False or value['safe_to_resume'] is not False):raise ValueError


def capture_redis(*,home,backup,key,site,version,resource,recorder,restore_oracle):
    """Authenticate a fixture backup, then bind trusted oracle observations."""
    try:
        if not callable(restore_oracle):raise ValueError
        state=context(home,key,recorder,site,resource)
        manifest=backup_store.verify_set(backup,key,home=home,site=site,version=version)
        prepared=redis_recovery_experiment.prepare(backup,key=key,home=home,site=site,version=version)
        if (prepared['backup_id']!=manifest['id'] or prepared['safe_to_update'] is not False
                or prepared['safe_to_resume'] is not False):raise ValueError
        observation=restore_oracle(prepared['rdb'])
        if (not isinstance(observation,dict) or set(observation)!={'rdb_sha256','before','after','source_again'}
                or observation['rdb_sha256']!=manifest['files']['redis']['plaintext_sha256']):raise ValueError
        for name in ('before','after','source_again'):check_fingerprint(observation[name])
        if observation['before']!=observation['after'] or observation['before']!=observation['source_again']:raise ValueError
        if backup_store.verify_set(backup,key,home=home,site=site,version=version)!=manifest:raise ValueError
        if context(home,key,recorder,site,resource)!=state:raise ValueError
        fingerprint=observation['before']
        record={'schema':1,**scope(state),'backup_id':manifest['id'],'manifest_sha256':digest(manifest),
                'redis_sha256':manifest['files']['redis']['sha256'],
                'redis_plaintext_sha256':manifest['files']['redis']['plaintext_sha256'],
                'fingerprint':fingerprint['digest'],'databases':fingerprint['databases'],'keys':fingerprint['keys']}
        return {'record':record,'mac':sign(key,b'redis-recovery-experiment-v1',record),
                'safe_to_update':False,'safe_to_resume':False}
    except Exception:raise EvidenceError('REDIS_RECOVERY_EVIDENCE_UNVERIFIED') from None


def combine(*,home,backup,key,bundle,publisher,recorder,site,resource,instance,boot,audit,redis):
    """Check both authenticated records against the same backup and receipt."""
    try:
        state=context(home,key,recorder,site,resource)
        receipt=recorder.read_receipt('guardrail',instance,boot,site=site['name'],resource=resource)
        product=maintenance_protocol.verify_capability(bundle,publisher)
        bundle_hash=hashlib.sha256((Path(bundle)/'checksums.json').read_bytes()).hexdigest()
        manifest=backup_store.verify_set(backup,key,home=home,site=site,version=product['version'])
        if (not isinstance(audit,dict) or set(audit)!={'record','mac','safe_to_backup','safe_to_update'}
                or audit['safe_to_backup'] is not False or audit['safe_to_update'] is not False
                or not isinstance(audit['record'],dict) or set(audit['record'])!=AUDIT_FIELDS
                or not isinstance(audit['mac'],str)
                or not hmac.compare_digest(audit['mac'],sign(key,b'audit-maintenance-evidence-v1',audit['record']))):raise ValueError
        if (not isinstance(redis,dict) or set(redis)!={'record','mac','safe_to_update','safe_to_resume'}
                or redis['safe_to_update'] is not False or redis['safe_to_resume'] is not False
                or not isinstance(redis['record'],dict) or set(redis['record'])!=REDIS_FIELDS
                or not isinstance(redis['mac'],str)
                or not hmac.compare_digest(redis['mac'],sign(key,b'redis-recovery-experiment-v1',redis['record']))):raise ValueError
        a=audit['record'];r=redis['record'];common={'schema':1,**scope(state),'backup_id':manifest['id'],
                                                   'manifest_sha256':digest(manifest)}
        if type(a['schema']) is not int or type(r['schema']) is not int:raise ValueError
        if any(a.get(k)!=v or r.get(k)!=v for k,v in common.items()):raise ValueError
        if (a['boot_id']!=boot or a['instance_sha256']!=hashlib.sha256(instance.encode()).hexdigest()
                or type(a['audit_last_seq']) is not int or a['audit_last_seq']!=receipt['evidence']['audit']['last_seq']
                or a['audit_last_hash']!=receipt['evidence']['audit']['last_hash']
                or a['guardrail_image']!=product['images']['guardrail'] or a['bundle_sha256']!=bundle_hash
                or a['audit_sha256']!=manifest['files']['audit']['sha256']
                or a['runtime_sha256']!=manifest['files']['runtime']['sha256']
                or r['redis_sha256']!=manifest['files']['redis']['sha256']
                or r['redis_plaintext_sha256']!=manifest['files']['redis']['plaintext_sha256']
                or type(a['audit_files']) is not int or a['audit_files']<1 or not hex64(r['fingerprint'])
                or type(r['databases']) is not int or not 1<=r['databases']<=64
                or type(r['keys']) is not int or not 1<=r['keys']<=100000):raise ValueError
        if backup_store.verify_set(backup,key,home=home,site=site,version=product['version'])!=manifest:raise ValueError
        if maintenance_protocol.verify_capability(bundle,publisher)!=product:raise ValueError
        if hashlib.sha256((Path(bundle)/'checksums.json').read_bytes()).hexdigest()!=bundle_hash:raise ValueError
        if recorder.read_receipt('guardrail',instance,boot,site=site['name'],resource=resource)!=receipt:raise ValueError
        if context(home,key,recorder,site,resource)!=state:raise ValueError
        record={'schema':1,**scope(state),'backup_id':manifest['id'],'manifest_sha256':digest(manifest),
                'audit_record_sha256':digest(a),'redis_record_sha256':digest(r)}
        return {'record':record,'mac':sign(key,b'combined-recovery-experiment-v1',record),
                'safe_to_update':False,'safe_to_resume':False}
    except Exception:raise EvidenceError('COMBINED_RECOVERY_EVIDENCE_UNVERIFIED') from None
