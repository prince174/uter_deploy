"""Experimental live Redis read-only connection through pinned kubectl.

One new admin connection is bound to one exact Redis Pod and server run_id.
The connection is not the admin connection from an earlier failed operation;
its identity is never accepted as recovery authority. No ACL mutation, replay,
backup, update, or continuous network isolation is implemented here.
The RESP2 peer is the trusted pinned Redis process. Checks for extra frames
cannot exclude malicious delayed traffic from a compromised peer.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import time

from scripts import (backup_installation, kubernetes_fence_coordinator as coordinator,
                     kubernetes_fence_finalizer as finalizer, kubernetes_sealed_config,
                     kubernetes_trusted_kubectl, redis_acl_experiment,
                     redis_acl_operation_inspection)

_ALLOWED=frozenset((('INFO','SERVER'),('INFO','REPLICATION'),('INFO','PERSISTENCE'),
    ('CLIENT','ID'),('CLIENT','LIST'),('ACL','USERS'),('ACL','GETUSER','default'),
    ('MODULE','LIST'),('FUNCTION','LIST')))


class ReadonlyTransportError(ValueError):
    def __init__(self,code,stage='UNVERIFIED'):
        super().__init__(code);self.stage=stage


def _cleanup(process):
    failed=False
    try: os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError: pass
    except OSError: failed=True
    try: process.wait(timeout=5)
    except (OSError,subprocess.TimeoutExpired): failed=True
    for stream in (process.stdin,process.stdout):
        if stream is not None:
            try: stream.close()
            except Exception: failed=True
    if failed: raise ReadonlyTransportError('KUBE_REDIS_READONLY_CLEANUP_UNCERTAIN') from None


class Connection:
    def __init__(self,process,session,plan,operation,expected_run_id):
        self.process=process;self.session=session;self.plan=plan;self.operation=operation;self.expected_run_id=expected_run_id
        self.client_id=None;self.buffer=bytearray();self.deadline=time.monotonic()+120;self.failed=False
        self._reply_bytes=0;self._reply_items=0
        self.identity_detail='INFO_REQUEST'

    def _scope(self):
        if time.monotonic()>=self.deadline: raise TimeoutError
        self.session._guard();self.session.reverify()
        finalizer._check_journal(self.session.home,self.plan,self.operation,'prepared')
        redis_acl_operation_inspection._verify_plan_pod(self.session,self.plan)
        kubernetes_trusted_kubectl.verify(self.session._inner.api.binary_fd,self.session._record['kubectl_sha256'])
        kubernetes_sealed_config.verify_sealed(self.session._inner.config_fd,self.session.config_sha256)
        if time.monotonic()>=self.deadline: raise TimeoutError

    def _exchange(self, parts):
        if self.buffer or select.select([self.process.stdout.fileno()],[],[],0)[0]:
            raise ValueError
        encoded=[part.encode('ascii') for part in parts]
        message=b'*'+str(len(encoded)).encode()+b'\r\n'+b''.join(
            b'$'+str(len(value)).encode()+b'\r\n'+value+b'\r\n' for value in encoded)
        if len(message)>512: raise ValueError
        deadline=min(self.deadline,time.monotonic()+8)
        fd=self.process.stdin.fileno()
        while message:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([],[fd],[],remaining)[1]: raise TimeoutError
            written=os.write(fd,message)
            if written<=0: raise ValueError
            message=message[written:]
        self._reply_bytes=0;self._reply_items=0
        value=self._reply(deadline,0)
        # A RESP2 request is never pipelined. Buffered trailing data is not an
        # acceptable response and must not become the next command's answer.
        if self.buffer or select.select([self.process.stdout.fileno()],[],[],0)[0]: raise ValueError
        return value

    def _read(self,count,deadline):
        if count<0 or count>262144 or self._reply_bytes+count>262144: raise ValueError
        fd=self.process.stdout.fileno()
        while len(self.buffer)<count:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([fd],[],[],remaining)[0]: raise TimeoutError
            chunk=os.read(fd,min(4096,262145-len(self.buffer)))
            if not chunk: raise ValueError
            self.buffer.extend(chunk)
            if len(self.buffer)>262144: raise ValueError
        value=bytes(self.buffer[:count]);del self.buffer[:count];self._reply_bytes+=count
        return value

    def _line(self,deadline):
        result=bytearray()
        while len(result)<=128:
            byte=self._read(1,deadline)
            if (result and result[-1]==13 and byte!=b'\n') or (byte==b'\n' and (not result or result[-1]!=13)):
                raise ValueError
            result.extend(byte)
            if result.endswith(b'\r\n'): return bytes(result[:-2])
        raise ValueError

    def _reply(self,deadline,depth):
        if depth>4: raise ValueError
        kind=self._read(1,deadline);head=self._line(deadline)
        if kind in (b'+',b'-'):
            if kind==b'-': raise ValueError
            return head.decode('utf-8')
        if kind not in (b':',b'$',b'*') or not re.fullmatch(rb'-?(?:0|[1-9][0-9]{0,18})',head):
            raise ValueError
        if head==b'-0': raise ValueError
        number=int(head)
        if kind==b':': return number
        if number==-1: return None
        if number<0: raise ValueError
        if kind==b'$':
            raw=self._read(number+2,deadline)
            if raw[-2:]!=b'\r\n': raise ValueError
            return raw[:-2].decode('utf-8')
        self._reply_items+=number
        if self._reply_items>4096: raise ValueError
        return [self._reply(deadline,depth+1) for _ in range(number)]

    def _identity(self):
        self.identity_detail='INFO_REQUEST'
        raw=self._exchange(('INFO','SERVER'))
        self.identity_detail='INFO_FORMAT'
        info=redis_acl_experiment._fields(raw)
        self.identity_detail='RUN_MISMATCH'
        if info.get('run_id')!=self.expected_run_id: raise ValueError
        self.identity_detail='CLIENT_REQUEST'
        ident=self._exchange(('CLIENT','ID'))
        self.identity_detail='CLIENT_TYPE'
        if type(ident) is not int or ident<1: raise ValueError
        self.identity_detail='CLIENT_CHANGED'
        if self.client_id is not None and str(ident)!=self.client_id: raise ValueError
        return str(ident)

    def execute(self,*parts):
        """Read only fixed commands; any error invalidates this observation."""
        try:
            if self.failed or parts not in _ALLOWED: raise ValueError
            self._scope();self._identity()
            value=self._exchange(parts)
            self._identity();self._scope()
            if parts == ('ACL','GETUSER','default'):
                if (not isinstance(value,list) or len(value)%2
                        or any(not isinstance(k,str) for k in value[::2])
                        or len(set(value[::2]))!=len(value[::2])): raise ValueError
                value=dict(zip(value[::2],value[1::2]))
            return value
        except Exception:
            self.failed=True
            raise ReadonlyTransportError('KUBE_REDIS_READONLY_UNVERIFIED') from None


@contextmanager
def connect(session,operation,admin_user,credential_path,expected_run_id):
    """Open a newly authenticated fixed read-only session, never a recovery grant."""
    process=None;stage='ARGUMENTS'
    try:
        if (type(session) is not coordinator.BoundSession or session._executor is None
                or not isinstance(admin_user,str) or not re.fullmatch(r'uter-maint-[a-z0-9]{1,24}',admin_user)
                or not isinstance(expected_run_id,str) or not re.fullmatch(r'[0-9a-f]{40}',expected_run_id)):
            raise ValueError
        stage='SESSION';session._guard();session.reverify()
        plan=finalizer.read_plan(session.home)
        finalizer._check_journal(session.home,plan,operation,'prepared')
        redis_acl_operation_inspection._verify_plan_pod(session,plan)
        stage='CREDENTIAL';secret_path=backup_installation.checked_existing_path(credential_path)
        if secret_path.is_relative_to(Path(session.home).resolve()) or secret_path.is_relative_to(Path(session._inner.bundle).resolve()):
            raise ValueError
        secret=backup_installation.safe_file(secret_path,private=True,limit=128).decode('ascii').strip()
        if not re.fullmatch(r'[0-9a-f]{64}',secret): raise ValueError
        stage='BINARY';api=session._inner.api;binary,config=api.binary_fd,session._inner.config_fd
        kubernetes_trusted_kubectl.verify(binary,session._record['kubectl_sha256'])
        kubernetes_sealed_config.verify_sealed(config,session.config_sha256)
        command=['/proc/self/fd/'+str(binary),'--kubeconfig=/proc/self/fd/'+str(config),
                 '--context='+api.context,'--namespace='+session.site,'--request-timeout=180s',
                 'exec','-i','pod/'+plan['pod'],'-c','redis','--','nc','127.0.0.1','6379']
        stage='SPAWN';process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env=dict(kubernetes_trusted_kubectl.ENV),pass_fds=(binary,config),start_new_session=True,bufsize=0)
        connection=Connection(process,session,plan,operation,expected_run_id)
        stage='AUTH';
        if connection._exchange(('AUTH',admin_user,secret)) != 'OK': raise ValueError
        del secret
        stage='SCOPE_BEFORE';connection._scope()
        stage='REDIS_IDENTITY';connection.client_id=connection._identity()
        stage='SCOPE_AFTER';connection._scope()
        yield connection
    except GeneratorExit:
        raise
    except Exception as error:
        category='TIMEOUT' if isinstance(error,TimeoutError) else 'INVALID'
        if stage=='REDIS_IDENTITY' and process is not None:
            stage=connection.identity_detail
        raise ReadonlyTransportError('KUBE_REDIS_READONLY_UNVERIFIED',stage+'_'+category) from None
    finally:
        if process is not None: _cleanup(process)
