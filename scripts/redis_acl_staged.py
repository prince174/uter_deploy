"""Experimental staged Redis writer admission; not an update/backup gate.

Caller supplies a pinned persistent admin connection, signed profile, verified
Redis identity and durable write-once records. Existing authenticated writer
connections are kept during drain. Any unknown outcome blocks this object;
there is no automatic retry, rollback, restart recovery or fence release.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from scripts import maintenance_protocol, redis_acl_experiment, workload_preflight

PROFILE='compose/redis-acl-maintenance.json'
PROFILE_SHA='06a6ec5386bc678e766054ece089768d90b106864e087fb0772eebe240327b2d'
WRITER='uter-writer'


class StagedError(ValueError):pass


def _read(path,limit):
    return workload_preflight.read_trusted_file(path,limit,secret=False,error='REDIS_STAGED_PROFILE_UNVERIFIED')


def verify_profile(bundle,publisher):
    """Authenticate exact profile and source service capability; no runtime claims."""
    try:
        signed=maintenance_protocol.verify_capability(bundle,publisher);bundle=Path(bundle)
        raw=_read(bundle/'checksums.json',1048576);signature=base64.b64decode(_read(bundle/'checksums.sig',1024),validate=True)
        public=load_pem_public_key(_read(publisher,32768))
        if not isinstance(public,Ed25519PublicKey):raise ValueError
        public.verify(signature,raw);inventory=json.loads(raw)
        manifest=_read(bundle/'manifest.json',1048576);profile=_read(bundle/PROFILE,65536)
        if (not isinstance(inventory,dict) or inventory.get('manifest.json')!=hashlib.sha256(manifest).hexdigest()
                or json.loads(manifest)!=signed or inventory.get(PROFILE)!=hashlib.sha256(profile).hexdigest()
                or hashlib.sha256(profile).hexdigest()!=PROFILE_SHA):raise ValueError
        return signed
    except Exception:raise StagedError('REDIS_STAGED_PROFILE_UNVERIFIED') from None


def _acl(execute,user,*,enabled,commands,default=False):
    info=execute('ACL','GETUSER',user)
    if not isinstance(info,dict):raise ValueError
    flags=info.get('flags');passwords=info.get('passwords');tokens=info.get('commands','').split()
    if (not isinstance(flags,list) or len(flags)!=len(set(flags)) or ('on' in flags)!=enabled
            or ('off' in flags)==enabled or info.get('selectors')!=[] or not isinstance(passwords,list)):
        raise ValueError
    if default:
        if passwords or tokens!=['-@all']:raise ValueError
    elif (len(passwords)!=1 or not isinstance(passwords[0],str) or not re.fullmatch(r'[0-9a-f]{64}',passwords[0])
          or 'nopass' in flags or not tokens or tokens[0]!='-@all'
          or len(tokens)!=len(set(tokens)) or set(tokens[1:])!=commands
          or info.get('keys')!='~*' or info.get('channels')!='&*'):raise ValueError
    return None if default else passwords[0]


def _clients(raw,admin_user,admin_id,*,only_admin):
    if not isinstance(raw,str) or len(raw)>262144:raise ValueError
    writers=set();seen=set()
    for line in raw.splitlines():
        fields={}
        for item in line.split():
            key,sep,value=item.partition('=')
            if not sep or not key or key in fields:raise ValueError
            fields[key]=value
        ident,user=fields.get('id'),fields.get('user')
        if not isinstance(ident,str) or not re.fullmatch(r'[1-9][0-9]{0,19}',ident) or ident in seen:raise ValueError
        seen.add(ident)
        if ident==admin_id:
            if user!=admin_user:raise ValueError
        elif only_admin or user!=WRITER:raise ValueError
        else:writers.add(ident)
    if admin_id not in seen:raise ValueError
    return frozenset(writers)


class StagedAdmission:
    """One in-memory attempt only; injected evidence callbacks are experimental."""
    def __init__(self,execute,*,bundle,publisher,admin_user,run_id,client_id,record_intent,record_receipt,identity_guard,
                 durable_prepare=None):
        if (not callable(execute) or not callable(record_intent) or not callable(record_receipt)
                or not callable(identity_guard) or not isinstance(admin_user,str)
                or not re.fullmatch(r'uter-maint-[a-z0-9]{1,24}',admin_user)
                or not isinstance(run_id,str) or not re.fullmatch(r'[0-9a-f]{40}',run_id)
                or not isinstance(client_id,str) or not re.fullmatch(r'[1-9][0-9]{0,19}',client_id)):
            raise StagedError('REDIS_STAGED_ARGUMENT_INVALID')
        self.execute=execute;self.admin=admin_user;self.run_id=run_id;self.client_id=client_id
        self.intent=record_intent;self.receipt=record_receipt;self.guard=identity_guard
        self.bundle=Path(bundle);self.publisher=Path(publisher);self.manifest=verify_profile(self.bundle,self.publisher)
        if durable_prepare is not None:
            from scripts import redis_acl_durable
            if (type(durable_prepare) is not redis_acl_durable.DurablePrepare or durable_prepare.manifest!=self.manifest
                    or durable_prepare.admin_user!=self.admin):raise StagedError('REDIS_STAGED_ARGUMENT_INVALID')
        self.durable=durable_prepare;self.durable_ready=False
        self.failure_phase='INITIAL'
        self.phase='new';self.writer_clients=frozenset()

    def _observe(self,*,disabled):
        if (self.guard() is not True or verify_profile(self.bundle,self.publisher)!=self.manifest
                or self.durable_ready and self.durable.verify_off() is not True):raise ValueError
        server=redis_acl_experiment._fields(self.execute('INFO','SERVER'))
        replication=redis_acl_experiment._fields(self.execute('INFO','REPLICATION'))
        persistence=redis_acl_experiment._fields(self.execute('INFO','PERSISTENCE'))
        if (server.get('run_id')!=self.run_id or replication.get('role')!='master'
                or replication.get('connected_slaves')!='0' or persistence.get('loading')!='0'
                or persistence.get('aof_enabled')!='1' or persistence.get('aof_last_write_status')!='ok'
                or persistence.get('aof_rewrite_in_progress')!='0' or persistence.get('rdb_bgsave_in_progress')!='0'
                or self.execute('MODULE','LIST')!=[] or self.execute('FUNCTION','LIST')!=[]
                or str(self.execute('CLIENT','ID'))!=self.client_id):raise ValueError
        users=self.execute('ACL','USERS')
        if not isinstance(users,list) or sorted(users)!=sorted(['default',WRITER,self.admin]):raise ValueError
        _acl(self.execute,'default',enabled=False,commands=frozenset(),default=True)
        writer_password_hash=_acl(self.execute,WRITER,enabled=not disabled,commands=redis_acl_experiment._UTER_TEST)
        admin=self.execute('ACL','GETUSER',self.admin)
        if (not isinstance(admin,dict) or 'on' not in admin.get('flags',[]) or 'off' in admin.get('flags',[])
                or 'nopass' in admin.get('flags',[]) or len(admin.get('passwords',[]))!=1
                or not isinstance(admin['passwords'][0],str) or not re.fullmatch(r'[0-9a-f]{64}',admin['passwords'][0])
                or admin.get('selectors')!=[] or admin.get('commands')!='+@all'):raise ValueError
        if hmac.compare_digest(writer_password_hash,admin['passwords'][0]):raise ValueError
        if self.durable is not None and (not hmac.compare_digest(writer_password_hash,self.durable.writer_hash)
                or not hmac.compare_digest(admin['passwords'][0],self.durable.admin_hash)):raise ValueError
        if (self.guard() is not True or verify_profile(self.bundle,self.publisher)!=self.manifest
                or self.durable_ready and self.durable.verify_off() is not True):raise ValueError

    def disable_new_auth(self):
        try:
            if self.phase!='new':raise ValueError
            self.failure_phase='OBSERVE_ON'
            self._observe(disabled=False)
            self.failure_phase='CLIENTS_ON'
            before=_clients(self.execute('CLIENT','LIST'),self.admin,self.client_id,only_admin=False)
            if not before or self.intent('disable-writer-auth') is not True:raise ValueError
            self.phase='uncertain'
            self.failure_phase='REOBSERVE_ON'
            self._observe(disabled=False)
            if (_clients(self.execute('CLIENT','LIST'),self.admin,self.client_id,only_admin=False)!=before
                    or self.guard() is not True):raise ValueError
            if self.durable is not None:
                self.failure_phase='DURABLE_PREPARE'
                prepared=self.durable.prepare_off()
                if (prepared.get('disk_off_prepared') is not True or prepared.get('safe_to_update') is not False
                        or self.durable.verify_off() is not True):raise ValueError
                self.durable_ready=True
                self.failure_phase='DURABLE_REOBSERVE_ON'
                self._observe(disabled=False)
            self.failure_phase='ACL_OFF'
            if self.execute('ACL','SETUSER',WRITER,'off')!='OK':raise ValueError
            self.failure_phase='OBSERVE_OFF'
            self._observe(disabled=True)
            self.failure_phase='CLIENTS_OFF'
            after=_clients(self.execute('CLIENT','LIST'),self.admin,self.client_id,only_admin=False)
            if not after.issubset(before) or self.receipt('writer-auth-disabled') is not True:raise ValueError
            self.failure_phase='FINAL_OBSERVE'
            self._observe(disabled=True)
            if (_clients(self.execute('CLIENT','LIST'),self.admin,self.client_id,only_admin=False)!=after
                    or self.guard() is not True):raise ValueError
            self.writer_clients=after;self.phase='auth-disabled';self.failure_phase='COMPLETE'
            return {'new_writer_auth_disabled':True,'prior_writer_connections_retained':len(after),
                    'host_acl_file_verified':self.durable_ready,'redis_acl_source_verified':False,
                    'safe_to_backup':False,'safe_to_update':False}
        except Exception:
            self.phase='uncertain';raise StagedError('REDIS_STAGED_DISABLE_UNCERTAIN') from None

    def finish_after_drain(self,drain_guard):
        """CI callback is not itself evidence of a real drain or production fence."""
        try:
            if self.phase!='auth-disabled' or not callable(drain_guard) or drain_guard() is not True:raise ValueError
            self._observe(disabled=True)
            current=_clients(self.execute('CLIENT','LIST'),self.admin,self.client_id,only_admin=False)
            if not current.issubset(self.writer_clients) or self.intent('kill-writer-clients') is not True:raise ValueError
            self.phase='uncertain'
            self._observe(disabled=True)
            if (_clients(self.execute('CLIENT','LIST'),self.admin,self.client_id,only_admin=False)!=current
                    or self.guard() is not True or drain_guard() is not True):raise ValueError
            count=self.execute('CLIENT','KILL','USER',WRITER,'SKIPME','yes')
            if type(count) is not int or count<0:raise ValueError
            self._observe(disabled=True)
            _clients(self.execute('CLIENT','LIST'),self.admin,self.client_id,only_admin=True)
            self._observe(disabled=True)
            if drain_guard() is not True or self.receipt('writer-clients-killed') is not True:raise ValueError
            self._observe(disabled=True)
            if (_clients(self.execute('CLIENT','LIST'),self.admin,self.client_id,only_admin=True)
                    or self.guard() is not True or drain_guard() is not True):raise ValueError
            self.phase='finished'
            return {'writer_auth_disabled':True,'writer_clients_killed':count,
                    'safe_to_backup':False,'safe_to_update':False}
        except Exception:
            self.phase='uncertain';raise StagedError('REDIS_STAGED_FINISH_UNCERTAIN') from None
