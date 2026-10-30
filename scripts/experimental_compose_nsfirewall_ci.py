"""Synthetic Redis network-namespace firewall experiment; disposable runner only.

NEVER applies rules to the host namespace. This is not a production updater or
an authorization to migrate history. Names, credentials and data are synthetic.
"""
import os
import errno
import re
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from scripts import experimental_compose_fence_ci as helper, experimental_netns_probe as common
from scripts import redis_fence_journal as journal

IPTABLES='/usr/sbin/iptables'
NSENTER='/usr/bin/nsenter'
LABEL=helper.LABEL
PASS=common.OLD
PHASE='guard'
CLIENT=r'''
import socket,sys
s=socket.create_connection((sys.argv[1],6379),timeout=5);s.settimeout(2)
def req(*xs):
 b=b'*%d\r\n'%len(xs)+b''.join(b'$%d\r\n'%len(x.encode())+x.encode()+b'\r\n' for x in xs)
 s.sendall(b);return s.recv(1024)
assert req('AUTH','synthetic-old-only').startswith(b'+OK')
assert req('SET','synthetic:ns-test','before').startswith(b'+OK')
print('READY',flush=True);sys.stdin.readline()
try:
 req('SET','synthetic:ns-test','blocked-write')
 raise SystemExit(2)
except TimeoutError: print('BLOCKED',flush=True)
sys.stdin.readline()
try:
 r=req('SET','synthetic:ns-test','old-socket-write')
 if r:raise SystemExit(3)
except TimeoutError:raise
except OSError:pass
print('CLOSED',flush=True)
'''


def identity(fd):
    value=os.fstat(fd)
    return value.st_dev,value.st_ino


def ensure_nonhost_namespace(fd, *, host='/proc/self/ns/net'):
    hostinfo=os.stat(host)
    if identity(fd)==(hostinfo.st_dev,hostinfo.st_ino):
        raise RuntimeError('refusing host network namespace')


def command(fd, *iptables_args, expected=0):
    """Run fixed iptables arguments in the already-opened netns, not on host."""
    ensure_nonhost_namespace(fd)
    args=[NSENTER,'--net=/proc/self/fd/'+str(fd),'--',IPTABLES,'-w','10',*iptables_args]
    result=subprocess.run(args,pass_fds=(fd,),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL,timeout=30,check=False)
    if result.returncode!=expected: raise RuntimeError('synthetic namespace firewall command failed')
    if len(result.stdout)>1024*1024:raise RuntimeError('synthetic firewall output too large')
    return result.stdout.decode('utf-8')


def rule(comment):
    if not re.fullmatch(r'uter-ci-[0-9a-f]{32}',comment):raise RuntimeError('invalid synthetic rule id')
    return ['-p','tcp','--dport','6379','!','-i','lo','-m','comment','--comment',comment,'-j','DROP']


def assert_namespace(fd, redis, pid):
    """Exact owned fixture PID and open netns must still match before mutation."""
    ensure_nonhost_namespace(fd)
    live=helper.docker('inspect','--format','{{.State.Pid}} {{.State.Running}}',redis).split()
    if live != [str(pid),'true']:raise RuntimeError('synthetic Redis process changed')
    observed=os.stat('/proc/'+str(pid)+'/ns/net')
    if identity(fd)!=(observed.st_dev,observed.st_ino):raise RuntimeError('synthetic namespace changed')


def count_rule(fd, comment):
    lines=command(fd,'-S','INPUT').splitlines()
    # Matching only the randomly generated synthetic comment; no unrelated
    # firewall entries or addresses are printed or exposed in the report.
    return sum(1 for line in lines if ('--comment '+comment) in line)


def main():
    global PHASE
    common.guard(os.environ)
    if os.geteuid()!=0:raise RuntimeError('synthetic experiment requires root')
    if common.cmd(['docker','context','show'])!='default':raise RuntimeError('nondefault context')
    import json
    details=json.loads(common.cmd(['docker','context','inspect','default']))
    if len(details)!=1 or details[0]['Endpoints']['docker']['Host']!='unix:///var/run/docker.sock':
        raise RuntimeError('Docker endpoint is not local')
    owner=uuid.uuid4().hex;comment='uter-ci-'+owner
    net=None;containers=[];client=None;nsfd=None;uncertain=False;rule_possible=False
    try:
        uncertain=True
        net=helper.docker('network','create','--internal','--label',f'{LABEL}={owner}',
                          'uter-synthetic-nsfirewall-'+owner)
        if not re.fullmatch(r'[0-9a-f]{64}',net):raise RuntimeError('synthetic network ID invalid')
        uncertain=False
        uncertain=True
        redis=helper.docker('run','-d','--label',f'{LABEL}={owner}','--network',net,'--network-alias','redis',
            '--restart','unless-stopped','--tmpfs','/data:rw,mode=1777',helper.REDIS,'redis-server',
            '--bind','0.0.0.0','--requirepass',PASS,'--appendonly','yes','--appendfsync','always','--save','')
        if not re.fullmatch(r'[0-9a-f]{64}',redis):raise RuntimeError('synthetic container ID invalid')
        containers.append(redis);uncertain=False
        for _ in range(100):
            try:
                if helper.docker('exec',redis,'redis-cli','-a',PASS,'PING')=='PONG':break
            except RuntimeError:pass
            time.sleep(.1)
        else:raise RuntimeError('synthetic Redis not ready')
        fmt='{{json .NetworkSettings.Networks}}'
        endpoint_before=helper.docker('inspect','--format',fmt,redis)
        endpoints=json.loads(endpoint_before)
        if len(endpoints)!=1:raise RuntimeError('unexpected synthetic endpoint')
        endpoint=next(iter(endpoints.values()));ip=endpoint['IPAddress']
        pid=int(helper.docker('inspect','--format','{{.State.Pid}}',redis))
        cgroup=Path('/proc/'+str(pid)+'/cgroup').read_text(encoding='utf-8')
        if not re.search(r'(?<![0-9a-f])'+redis+r'(?![0-9a-f])',cgroup):
            raise RuntimeError('synthetic container cgroup mismatch')
        nsfd=os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY)
        assert_namespace(nsfd,redis,pid)
        if count_rule(nsfd,comment)!=0:raise RuntimeError('synthetic rule already exists')
        client=subprocess.Popen(['sudo','-n','-u','nobody','python3','-u','-c',CLIENT,ip],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,start_new_session=True)
        selector=selectors.DefaultSelector();selector.register(client.stdout,selectors.EVENT_READ)
        if not selector.select(15) or client.stdout.readline().strip()!='READY':raise RuntimeError('synthetic client not ready')
        with tempfile.TemporaryDirectory(prefix='uter-firewall-ci-') as folder:
            home=Path(folder)
            op=journal.create(home,backend='compose',site='synthetic',resource=redis,plan_sha256='a'*64)
            journal.advance(home,operation=op['operation'],expected='prepared',next_phase='isolating')
            helper.docker('update','--restart=no',redis)
            if helper.docker('inspect','--format','{{.HostConfig.RestartPolicy.Name}}',redis)!='no':
                raise RuntimeError('synthetic restart policy not disabled')
            assert_namespace(nsfd,redis,pid)
            PHASE='controller-crash'
            # The synthetic child inserts the one private rule and exits as if
            # the controller died before recording success. FD is inherited,
            # so no path can accidentally resolve to a different namespace.
            child=("import os,subprocess,sys\n"
                   "fd=int(sys.argv[1]);argv=sys.argv[2:]\n"
                   "r=subprocess.run(argv,pass_fds=(fd,),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                   "stderr=subprocess.DEVNULL,timeout=30)\n"
                   "os._exit(23 if r.returncode==0 else 24)\n")
            cmd=[NSENTER,'--net=/proc/self/fd/'+str(nsfd),'--',IPTABLES,'-w','10','-I','INPUT','1',*rule(comment)]
            rule_possible=True
            result=subprocess.run([sys.executable,'-c',child,str(nsfd),*cmd],pass_fds=(nsfd,),timeout=40,
                                  stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if result.returncode!=23 or journal.read(home)['phase']!='isolating' or count_rule(nsfd,comment)!=1:
                raise RuntimeError('synthetic crash did not preserve intent and rule')
            assert_namespace(nsfd,redis,pid)
            PHASE='blocked-old-client'
            client.stdin.write('try\n');client.stdin.flush()
            if not selector.select(10) or client.stdout.readline().strip()!='BLOCKED':
                raise RuntimeError('synthetic old connection was not blocked')
            # A new external connection must also fail within its test window.
            sock=socket.socket();sock.settimeout(2);started=time.monotonic()
            try:
                try: rc=sock.connect_ex((ip,6379))
                except TimeoutError:rc=-1
                if (rc not in (-1,errno.ETIMEDOUT,errno.EAGAIN) or time.monotonic()-started<1.9):
                    raise RuntimeError('synthetic new connection result is inconclusive')
            finally:sock.close()
            killed=helper.docker('exec',redis,'redis-cli','-a',PASS,'CLIENT','KILL','TYPE','normal','SKIPME','yes')
            if not killed.isdigit() or int(killed)<1:
                raise RuntimeError('synthetic old client was not killed')
            if helper.docker('exec',redis,'redis-cli','-a',PASS,'GET','synthetic:ns-test')!='before':
                raise RuntimeError('synthetic data changed while fenced')
            PHASE='snapshot'
            snap=subprocess.run(['docker','--context','default','exec',redis,'redis-cli','-a',PASS,'--rdb','-'],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=60,check=False)
            if snap.returncode or not snap.stdout.startswith(b'REDIS') or len(snap.stdout)>8*1024*1024:
                raise RuntimeError('synthetic fenced snapshot failed')
            assert_namespace(nsfd,redis,pid)
            PHASE='remove-owned-rule'
            command(nsfd,'-D','INPUT',*rule(comment))
            if count_rule(nsfd,comment)!=0:raise RuntimeError('synthetic rule removal not confirmed')
            rule_possible=False
            client.stdin.write('again\n');client.stdin.flush()
            if not selector.select(10) or client.stdout.readline().strip()!='CLOSED' or client.wait(timeout=5):
                raise RuntimeError('old synthetic socket became usable')
            client=None
            if helper.docker('exec',redis,'redis-cli','-a',PASS,'GET','synthetic:ns-test')!='before':
                raise RuntimeError('queued synthetic write was applied')
            if helper.docker('inspect','--format',fmt,redis)!=endpoint_before:
                raise RuntimeError('synthetic endpoint changed')
            if journal.read(home)['phase']!='isolating':raise RuntimeError('synthetic uncertainty was overwritten')
    finally:
        if client is not None:
            try:os.killpg(client.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            client.wait(timeout=5)
        errors=[]
        if rule_possible and nsfd is not None:
            try:
                assert_namespace(nsfd,redis,pid)
                if count_rule(nsfd,comment)==1:command(nsfd,'-D','INPUT',*rule(comment))
                if count_rule(nsfd,comment)!=0:raise RuntimeError('rule cleanup unconfirmed')
            except Exception:errors.append('namespace rule')
        if nsfd is not None:os.close(nsfd)
        for cid in reversed(containers):
            try:helper.cleanup('container',cid,owner)
            except Exception:errors.append('container')
        if net:
            try:helper.cleanup('network',net,owner)
            except Exception:errors.append('network')
        if uncertain:errors.append('unknown resource')
        if errors:raise RuntimeError('synthetic cleanup unconfirmed: '+', '.join(errors))
    print('Synthetic netns firewall, crash intent, closed sockets, snapshot and exact endpoint checks passed.')


if __name__=='__main__':
    try:main()
    except RuntimeError as error:
        raise SystemExit('Synthetic netns firewall failed at '+PHASE+': '+str(error))
    except (OSError,ValueError,KeyError,subprocess.TimeoutExpired) as error:
        raise SystemExit('Synthetic netns firewall failed at '+PHASE+': '+type(error).__name__)
