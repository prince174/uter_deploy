"""Experimental scoped Redis netns firewall. Not connected to the updater.

Trust: root, Docker daemon, kernel, namespace and firewall administrators; no
concurrent Docker/firewall automation. A journal is mandatory; unknown outcomes
must be inspected, never guessed. Only release BEFORE any capture/migration is
implemented. A held fd pins the inspected Redis netns; no host rule is changed.
"""
import hashlib
import os
from pathlib import Path
import select
import shlex
import signal
import socket
import struct
import subprocess
import time

from scripts import (compose_fence_adapter as compose, redis_fence_journal as journal,
                     compose_systemd_activation as systemd_activation,
                     compose_nsfirewall_checkpoint as checkpoint)

NSENTER='/usr/bin/nsenter'
IPTABLES='/usr/sbin/iptables'
MAX_OUTPUT=1024*1024
PROC_ROOT=Path('/proc')


class NamespaceFenceError(ValueError): pass


class Adapter(compose.Adapter):
    def __init__(self, home, bundle, publisher_key, backup_key):
        super().__init__(home,bundle,publisher_key,backup_key)
        self.fd=None;self.daemon_fd=None;self.daemon_pidfd=None;self.daemon_socket=None;self.daemon_pid=None;self.net_identity=None;self.initial_rules=None;self.initial_hash=None
        self.operation=None;self.redis_pid=None;self.installed=False;self.release_permit=None

    def close(self):
        """Close only the local FD; never silently remove or change firewall."""
        if self.fd is not None:os.close(self.fd);self.fd=None
        if self.daemon_fd is not None:os.close(self.daemon_fd);self.daemon_fd=None
        if self.daemon_pidfd is not None:os.close(self.daemon_pidfd);self.daemon_pidfd=None
        if self.daemon_socket is not None:self.daemon_socket.close();self.daemon_socket=None

    def _daemon_identity(self):
        """Require a visible root-owned dockerd peer for the local Unix socket."""
        try:
            if self.daemon_socket is None:
                self.daemon_socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                self.daemon_socket.settimeout(3);self.daemon_socket.connect('/var/run/docker.sock')
            peer=self.daemon_socket
            readable,_,exceptional=select.select([peer],[],[peer],0)
            if exceptional:raise NamespaceFenceError('NS_FENCE_DAEMON_SOCKET_STATE')
            if readable:
                try:peek=peer.recv(1,socket.MSG_PEEK|socket.MSG_DONTWAIT)
                except BlockingIOError:peek=None
                # No protocol bytes are expected; EOF also means the peer died.
                if peek is not None:raise NamespaceFenceError('NS_FENCE_DAEMON_SOCKET_STATE')
            pid,uid,_=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if uid!=0 or pid<=0:raise NamespaceFenceError('NS_FENCE_DAEMON_PEER_CREDENTIALS')
            if pid==1:
                try:return systemd_activation.daemon_pid()
                except systemd_activation.SystemdActivationError:
                    raise NamespaceFenceError('NS_FENCE_SYSTEMD_UNVERIFIED') from None
            proc=Path('/proc')/str(pid)
            if (proc/'comm').read_text(encoding='utf-8').strip()!='dockerd':
                raise NamespaceFenceError('NS_FENCE_DAEMON_PEER_PROCESS')
            namespaces=[os.stat('/proc/self/ns/pid'),os.stat('/proc/1/ns/pid'),os.stat(proc/'ns/pid')]
            if len({(item.st_dev,item.st_ino) for item in namespaces})!=1:
                raise NamespaceFenceError('NS_FENCE_DAEMON_PID_NAMESPACE')
            return pid
        except NamespaceFenceError:raise
        except (OSError,ValueError,UnicodeError,struct.error):
            raise NamespaceFenceError('NS_FENCE_DAEMON_SOCKET_OR_PROC') from None

    def _fd_nonhost(self):
        if self.fd is None:raise NamespaceFenceError('NS_FENCE_FD_UNAVAILABLE')
        if self.daemon_fd is None or self.daemon_pidfd is None:
            raise NamespaceFenceError('NS_FENCE_DAEMON_UNVERIFIED')
        if select.select([self.daemon_pidfd],[],[],0)[0]:
            raise NamespaceFenceError('NS_FENCE_DAEMON_PIDFD_EXITED')
        if self._daemon_identity()!=self.daemon_pid:
            raise NamespaceFenceError('NS_FENCE_DAEMON_PID_CHANGED')
        value=os.fstat(self.fd)
        blocked=(os.stat('/proc/self/ns/net'),os.stat('/proc/1/ns/net'),os.fstat(self.daemon_fd))
        if any((value.st_dev,value.st_ino)==(host.st_dev,host.st_ino) for host in blocked):
            raise NamespaceFenceError('NS_FENCE_HOST_NAMESPACE_REJECTED')
        current=os.stat('/proc/'+str(self.daemon_pid)+'/ns/net');old=os.fstat(self.daemon_fd)
        if (current.st_dev,current.st_ino)!=(old.st_dev,old.st_ino):
            raise NamespaceFenceError('NS_FENCE_DAEMON_NAMESPACE_CHANGED')
        return value.st_dev,value.st_ino

    def _journal(self,record,phases):
        current=journal.read(self.home)
        if (current.get('phase') not in phases or current.get('backend')!='compose'
                or any(current.get(k)!=record.get(k) for k in ('operation','site','resource','plan_sha256'))):
            raise NamespaceFenceError('NS_FENCE_JOURNAL_MISMATCH')
        return current

    def _exclusive_namespace(self, identity, allowed):
        """Reject visible foreign threads in netns; trusted host must prevent races."""
        try:
            for process in PROC_ROOT.iterdir():
                if not process.name.isdigit():continue
                try:tasks=list((process/'task').iterdir())
                except FileNotFoundError:continue
                for task in tasks:
                    if not task.name.isdigit():continue
                    try:ns=os.stat(task/'ns/net')
                    except FileNotFoundError:continue  # exited or kernel thread
                    if (ns.st_dev,ns.st_ino)==identity and int(process.name) not in allowed:
                        raise NamespaceFenceError('NS_FENCE_NAMESPACE_PEER')
        except NamespaceFenceError:raise
        except OSError:raise NamespaceFenceError('NS_FENCE_PROC_UNVERIFIED') from None

    def _live_namespace(self, plan, *, restart='no'):
        self._lock()
        value=self._fd_nonhost()
        if value!=self.net_identity:raise NamespaceFenceError('NS_FENCE_NAMESPACE_CHANGED')
        state=self._state(plan,detached=False,restart=restart,original_endpoint=True)
        if state['pid']!=self.redis_pid:raise NamespaceFenceError('NS_FENCE_PROCESS_CHANGED')
        observed=os.stat('/proc/'+str(self.redis_pid)+'/ns/net')
        if value!=(observed.st_dev,observed.st_ino):raise NamespaceFenceError('NS_FENCE_NAMESPACE_CHANGED')
        # Only the exact init and Redis process may share loopback. The host,
        # Docker daemon and all other controllers are trusted not to race this
        # observation; this is not a continuous monitor of hostile root.
        lines=self._run('top',plan['container_id'],'-eo','pid,ppid,comm').splitlines()
        if not lines or lines[0].split()!=['PID','PPID','COMMAND']:raise NamespaceFenceError('NS_FENCE_PROCESS_CHANGED')
        rows=[line.split(maxsplit=2) for line in lines[1:]]
        if len(rows)!=2 or any(len(row)!=3 for row in rows):raise NamespaceFenceError('NS_FENCE_PROCESS_CHANGED')
        child=[row for row in rows if row[2]=='redis-server' and row[1]==str(self.redis_pid)]
        init=[row for row in rows if row[0]==str(self.redis_pid) and row[2] in ('docker-init','tini')]
        if len(child)!=1 or len(init)!=1 or not child[0][0].isdigit():raise NamespaceFenceError('NS_FENCE_PROCESS_CHANGED')
        childpid=int(child[0][0]);childns=os.stat('/proc/'+str(childpid)+'/ns/net')
        if value!=(childns.st_dev,childns.st_ino):raise NamespaceFenceError('NS_FENCE_NAMESPACE_CHANGED')
        status=Path('/proc/'+str(childpid)+'/status').read_text(encoding='utf-8').splitlines()
        fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in status if ':' in line}
        if (any(fields.get(name)!='0000000000000000' for name in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd'))
                or fields.get('NoNewPrivs')!='1'):
            raise NamespaceFenceError('NS_FENCE_CAPABILITIES_UNSUPPORTED')
        self._exclusive_namespace(value,{self.redis_pid,childpid})

    def _cmd(self, args):
        """Bounded namespace command; timeout or error leaves mutation uncertain."""
        self._fd_nonhost()
        process=None
        try:
            process=subprocess.Popen([NSENTER,'--net=/proc/self/fd/'+str(self.fd),'--',IPTABLES,'-w','10',*args],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                pass_fds=(self.fd,),start_new_session=True,bufsize=0,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C'})
            out=bytearray();deadline=time.monotonic()+30
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise NamespaceFenceError('NS_FENCE_FIREWALL_UNCERTAIN')
                ready,_,_=select.select([process.stdout],[],[],remaining)
                if not ready:raise NamespaceFenceError('NS_FENCE_FIREWALL_UNCERTAIN')
                chunk=os.read(process.stdout.fileno(),min(65536,MAX_OUTPUT+1-len(out)))
                if not chunk:break
                out.extend(chunk)
                if len(out)>MAX_OUTPUT:raise NamespaceFenceError('NS_FENCE_FIREWALL_UNCERTAIN')
            # Do not reap the leader before killing a possible descendant in
            # the owned process group; otherwise the PID could be reused.
            while not os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT):
                if time.monotonic()>=deadline:raise NamespaceFenceError('NS_FENCE_FIREWALL_UNCERTAIN')
                time.sleep(.02)
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            if process.wait(timeout=5):raise NamespaceFenceError('NS_FENCE_FIREWALL_UNCERTAIN')
            return bytes(out)
        except NamespaceFenceError:raise
        except (OSError,ValueError,subprocess.SubprocessError):
            raise NamespaceFenceError('NS_FENCE_FIREWALL_UNCERTAIN') from None
        finally:
            if process is not None:
                if process.returncode is None:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:raise NamespaceFenceError('NS_FENCE_FIREWALL_UNCERTAIN') from None
                process.stdout.close()

    def _rule(self):
        # Input source is a checked journal operation UUID, never arbitrary CLI.
        if not isinstance(self.operation,str) or len(self.operation)!=32 or any(c not in '0123456789abcdef' for c in self.operation):
            raise NamespaceFenceError('NS_FENCE_OPERATION_INVALID')
        return ['-p','tcp','--dport','6379','!','-i','lo','-m','comment',
                '--comment','uter-fence-'+self.operation,'-j','DROP']

    def _rules(self):
        try:
            raw=self._cmd(['-S','INPUT'])
            text=raw.decode('utf-8')
            lines=text.splitlines(keepends=True)
            parsed=[shlex.split(line) for line in lines]
            return lines,parsed
        except NamespaceFenceError:raise
        except (ValueError,UnicodeError):raise NamespaceFenceError('NS_FENCE_FIREWALL_UNCERTAIN') from None

    def _check_firewall(self, *, installed):
        if self.initial_hash is None:raise NamespaceFenceError('NS_FENCE_BASELINE_UNAVAILABLE')
        lines,parsed=self._rules()
        token='uter-fence-'+self.operation
        matches=[index for index,p in enumerate(parsed) if '--comment' in p and
                 p.index('--comment')+1<len(p) and p[p.index('--comment')+1]==token]
        if installed:
            inputs=[i for i,p in enumerate(parsed) if p[:2]==['-A','INPUT']]
            if len(matches)!=1 or not inputs or matches[0]!=inputs[0]:
                raise NamespaceFenceError('NS_FENCE_RULE_UNVERIFIED')
            self._cmd(['-C','INPUT',*self._rule()])
            baseline=''.join(line for i,line in enumerate(lines) if i!=matches[0]).encode()
        else:
            if matches:raise NamespaceFenceError('NS_FENCE_RULE_UNVERIFIED')
            baseline=''.join(lines).encode()
        if hashlib.sha256(baseline).hexdigest()!=self.initial_hash:
            raise NamespaceFenceError('NS_FENCE_FIREWALL_CHANGED')

    def prepare(self,record):
        if self.fd is not None:raise NamespaceFenceError('NS_FENCE_ALREADY_PREPARED')
        self._journal(record,('prepared',))
        plan=self._plan(record)
        if not super().verify_preconditions(record):raise NamespaceFenceError('NS_FENCE_PRECONDITION_FAILED')
        state=self._state(plan,detached=False,restart='unless-stopped',original_endpoint=True)
        self.redis_pid=state['pid'];self.operation=record['operation']
        try:
            self.daemon_pid=self._daemon_identity()
            # A pidfd pins the checked process identity and detects exit even
            # if its numeric PID is immediately recycled.
            try:self.daemon_pidfd=os.pidfd_open(self.daemon_pid,0)
            except (AttributeError,OSError):raise NamespaceFenceError('NS_FENCE_DAEMON_PIDFD_UNAVAILABLE') from None
            if select.select([self.daemon_pidfd],[],[],0)[0]:
                raise NamespaceFenceError('NS_FENCE_DAEMON_PIDFD_EXITED')
            if self._daemon_identity()!=self.daemon_pid:
                raise NamespaceFenceError('NS_FENCE_DAEMON_PID_CHANGED')
            self.daemon_fd=os.open('/proc/'+str(self.daemon_pid)+'/ns/net',os.O_RDONLY)
            self.fd=os.open('/proc/'+str(self.redis_pid)+'/ns/net',os.O_RDONLY)
            self.net_identity=self._fd_nonhost()
            again=os.stat('/proc/'+str(self.redis_pid)+'/ns/net')
            if self.net_identity!=(again.st_dev,again.st_ino):raise NamespaceFenceError('NS_FENCE_NAMESPACE_CHANGED')
            lines,parsed=self._rules();token='uter-fence-'+self.operation
            if any('--comment' in p and p.index('--comment')+1<len(p) and p[p.index('--comment')+1]==token for p in parsed):
                raise NamespaceFenceError('NS_FENCE_RULE_ALREADY_EXISTS')
            self.initial_hash=hashlib.sha256(''.join(lines).encode()).hexdigest()
            # Check effective runtime binds; IPv6 or a different port is unsupported.
            if self._redis(plan,'CONFIG','GET','bind')!='bind\n0.0.0.0':
                raise NamespaceFenceError('NS_FENCE_BIND_UNSUPPORTED')
            if self._redis(plan,'CONFIG','GET','port')!='port\n6379':
                raise NamespaceFenceError('NS_FENCE_PORT_UNSUPPORTED')
            if self._redis(plan,'CONFIG','GET','tls-port')!='tls-port\n0':
                raise NamespaceFenceError('NS_FENCE_TLS_UNSUPPORTED')
            checkpoint.create(self.home,record,{
                'schema':1,'operation':record['operation'],'site':record['site'],
                'resource':record['resource'],'plan_sha256':record['plan_sha256'],
                'boot_id':checkpoint.boot_id(),'pid':self.redis_pid,
                'pid_start':checkpoint.process_start(self.redis_pid),
                'net_dev':self.net_identity[0],'net_ino':self.net_identity[1],
                'firewall_sha256':self.initial_hash},self.backup_key)
            return True
        except BaseException:
            self.close();raise

    def install_rule(self,record):
        self._journal(record,('isolating',))
        plan=self._plan(record);self._live_namespace(plan)
        self._check_firewall(installed=False)
        # Mark unknown BEFORE syscall; on error do not clean up automatically.
        self.installed=None
        self._cmd(['-I','INPUT','1',*self._rule()])
        self._check_firewall(installed=True);self._live_namespace(plan)
        self.installed=True

    def close_clients(self,record):
        self._journal(record,('isolating',))
        plan=self._plan(record);self._live_namespace(plan);self._check_firewall(installed=True);self._peers(plan)
        for kind in ('normal','pubsub','replica','master'):
            response=self._redis(plan,'CLIENT','KILL','TYPE',kind,'SKIPME','yes')
            if not response.isdigit():raise NamespaceFenceError('NS_FENCE_CLIENT_KILL_FAILED')
        self._no_other_clients(plan)

    def verify_fenced(self,record):
        self._journal(record,('isolating','isolated','capturing','captured','aborting','pre_capture_aborting'))
        plan=self._plan(record);self._signed(plan);self._live_namespace(plan)
        self._network_and_volume(plan);self._peers(plan);self._redis_config(plan)
        self._no_other_clients(plan);self._check_firewall(installed=True);self._live_namespace(plan)
        return True

    def authorize_release_before_capture(self,record):
        """Allow a direct isolated -> aborting path only while this process lives."""
        self._journal(record,('isolated',))
        if record.get('phase')!='isolated' or self.installed is not True:
            raise NamespaceFenceError('NS_FENCE_RELEASE_UNSUPPORTED')
        if self.verify_fenced(record) is not True:raise NamespaceFenceError('NS_FENCE_RELEASE_UNSUPPORTED')
        # Commit the direct transition before minting the in-memory permit.
        # Once aborting, journal transitions forbid starting a capture.
        journal.advance(self.home,operation=record['operation'],expected='isolated',next_phase='pre_capture_aborting')
        self.release_permit=record['operation']
        return True

    def release_before_capture(self,record):
        """Remove ONLY this rule and restore restart policy before any capture.

        authorize_release_before_capture records 'aborting' and gives this
        process a one-use permit. This is not crash recovery and cannot release
        a captured or potentially migrated data state.
        """
        self._journal(record,('pre_capture_aborting',))
        if (record.get('phase')!='isolated' or self.installed is not True
                or self.release_permit != record.get('operation')):
            raise NamespaceFenceError('NS_FENCE_RELEASE_UNSUPPORTED')
        if self.verify_fenced(record) is not True:raise NamespaceFenceError('NS_FENCE_RELEASE_UNSUPPORTED')
        plan=self._plan(record);self.installed=None;self.release_permit=None
        self._cmd(['-D','INPUT',*self._rule()])
        self._check_firewall(installed=False);self._live_namespace(plan)
        self._run('update','--restart=unless-stopped',plan['container_id'])
        self._state(plan,detached=False,restart='unless-stopped',original_endpoint=True)
        self.installed=False

    def attach_before_capture_recovery(self,record):
        return self._attach_recovery(record,('prepared','isolating','isolated','pre_capture_aborting'))

    def _attach_snapshot_recovery(self,record):
        return self._attach_recovery(record,('captured','snapshot_releasing'))

    def _attach_recovery(self,record,phases):
        """Reopen and verify the original live namespace; perform no mutation.

        This intentionally rejects a restarted Redis, different host boot,
        changed endpoint, unknown firewall state or missing authentication.
        Call only while the installation operation lock is held.
        """
        self._journal(record,phases)
        if self.fd is not None:raise NamespaceFenceError('NS_RECOVERY_ALREADY_ATTACHED')
        plan=self._plan(record)
        try:
            saved=checkpoint.read(self.home,record,self.backup_key)
            if checkpoint.boot_id()!=saved['boot_id'] or checkpoint.process_start(saved['pid'])!=saved['pid_start']:
                raise NamespaceFenceError('NS_RECOVERY_PROCESS_CHANGED')
            self.operation=record['operation'];self.redis_pid=saved['pid'];self.initial_hash=saved['firewall_sha256']
            self.daemon_pid=self._daemon_identity()
            self.daemon_pidfd=os.pidfd_open(self.daemon_pid,0)
            if select.select([self.daemon_pidfd],[],[],0)[0] or self._daemon_identity()!=self.daemon_pid:
                raise NamespaceFenceError('NS_FENCE_DAEMON_UNVERIFIED')
            self.daemon_fd=os.open('/proc/'+str(self.daemon_pid)+'/ns/net',os.O_RDONLY)
            self.fd=os.open('/proc/'+str(self.redis_pid)+'/ns/net',os.O_RDONLY)
            self.net_identity=self._fd_nonhost()
            if (self.net_identity!=(saved['net_dev'],saved['net_ino'])
                    or checkpoint.process_start(self.redis_pid)!=saved['pid_start']):
                raise NamespaceFenceError('NS_RECOVERY_NAMESPACE_CHANGED')
            self._signed(plan);self._network_and_volume(plan);self._peers(plan);self._redis_config(plan)
            restart=self._inspect_redis(plan['container_id']).get('restart')
            if restart not in ('no','unless-stopped'):raise NamespaceFenceError('NS_RECOVERY_RESTART_CHANGED')
            self._live_namespace(plan,restart=restart)
            _,parsed=self._rules();token='uter-fence-'+self.operation
            matches=[p for p in parsed if '--comment' in p and p.index('--comment')+1<len(p)
                     and p[p.index('--comment')+1]==token]
            if len(matches)>1:raise NamespaceFenceError('NS_RECOVERY_FIREWALL_CHANGED')
            self.installed=bool(matches);self._check_firewall(installed=self.installed)
            if self.installed and restart!='no':raise NamespaceFenceError('NS_RECOVERY_RESTART_CHANGED')
            self._live_namespace(plan,restart=restart)
            return True
        except BaseException:
            self.close();raise

    def recover_before_capture(self,record):
        """Idempotently release only the original Redis rule, before capture.

        Journal must already have committed pre_capture_aborting. Application
        writers stay stopped; this is not full installation recovery.
        """
        return self._recover_original_redis(record,('pre_capture_aborting',))

    def _recover_snapshot_only(self,record):
        """Release Redis only after the separate snapshot proof has been checked."""
        return self._recover_original_redis(record,('snapshot_releasing',))

    def _recover_original_redis(self,record,phases):
        self._journal(record,phases)
        plan=self._plan(record)
        restart=self._inspect_redis(plan['container_id']).get('restart')
        if restart not in ('no','unless-stopped'):raise NamespaceFenceError('NS_RECOVERY_RESTART_CHANGED')
        self._signed(plan);self._live_namespace(plan,restart=restart)
        if self.installed:
            if restart!='no':raise NamespaceFenceError('NS_RECOVERY_RESTART_CHANGED')
            self._check_firewall(installed=True)
            self._cmd(['-D','INPUT',*self._rule()])
            self._check_firewall(installed=False);self.installed=False
        else:self._check_firewall(installed=False)
        self._live_namespace(plan,restart=restart)
        if restart=='no':
            self._run('update','--restart=unless-stopped',plan['container_id'])
        self._live_namespace(plan,restart='unless-stopped')
        self._check_firewall(installed=False)
        return True
