"""Read-only Docker socket-activation evidence, disposable hosted CI only.

This is not an isolation or recovery method and makes no Docker mutations.
It assumes a trusted host, complete host procfs and no concurrent privileged
socket sharing; observation is point-in-time, not protection from hostile root.
"""
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import sys

PROC_ROOT=Path('/proc')
class ProbeError(ValueError): pass


def parse_properties(raw, keys):
    result={}
    for line in raw.splitlines():
        key,separator,value=line.partition('=')
        if not separator or key not in keys or key in result:raise ProbeError('PROPERTIES_MALFORMED')
        result[key]=value
    if set(result)!=set(keys):
        missing=set(keys)-set(result)
        if len(missing)==1:raise ProbeError('PROPERTY_MISSING_'+next(iter(missing)).upper())
        raise ProbeError('PROPERTIES_MISSING_MULTIPLE')
    return result


def properties(unit,keys):
    try:
        command=['/usr/bin/systemctl','show',unit,*['--property='+key for key in keys]]
        result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                              timeout=10,check=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C'})
        if len(result.stdout)>8192:raise ProbeError('PROPERTIES_TOO_LARGE')
        return parse_properties(result.stdout.decode('utf-8'),keys)
    except FileNotFoundError:raise ProbeError('SYSTEMCTL_UNAVAILABLE') from None
    except subprocess.TimeoutExpired:raise ProbeError('SYSTEMCTL_TIMEOUT') from None
    except subprocess.CalledProcessError:raise ProbeError('SYSTEMCTL_FAILED') from None
    except UnicodeError:raise ProbeError('PROPERTIES_ENCODING') from None
    except OSError:raise ProbeError('SYSTEMCTL_EXECUTION') from None


def listening_inode(raw, path):
    found=[]
    for line in raw.splitlines()[1:]:
        parts=line.split(maxsplit=7)
        if len(parts)!=8 or os.path.realpath(parts[7])!=path:continue
        if parts[3]!='00010000' or parts[4]!='0001' or parts[5]!='01' or not parts[6].isdigit():
            raise ProbeError('LISTENER')
        found.append(parts[6])
    if len(found)!=1:raise ProbeError('LISTENER')
    return found[0]


def validate_units(socket_unit,service):
    # Triggers/TriggeredBy are systemd's implicit activation dependencies:
    # https://www.freedesktop.org/software/systemd/man/257/systemd.unit.html
    if (socket_unit.get('ActiveState')!='active' or socket_unit.get('Accept')!='no'
            or socket_unit.get('Triggers','').split()!=['docker.service']):
        raise ProbeError('SOCKET_UNIT')
    if (service.get('ActiveState')!='active' or service.get('SubState')!='running'
            or service.get('TriggeredBy','').split()!=['docker.socket']):raise ProbeError('SERVICE_STATE')


def socket_holders(inode):
    holders=set();target='socket:['+inode+']'
    try:
        for process in PROC_ROOT.iterdir():
            if not process.name.isdigit():continue
            try:tasks=list((process/'task').iterdir())
            except FileNotFoundError:continue
            for task in tasks:
                if not task.name.isdigit():continue
                try:fds=list((task/'fd').iterdir())
                except FileNotFoundError:continue
                for fd in fds:
                    try:link=os.readlink(fd)
                    except FileNotFoundError:continue
                    if link==target:holders.add(int(process.name))
        return holders
    except OSError:raise ProbeError('PROC_VISIBILITY') from None


def main():
    env=os.environ
    if (env.get('GITHUB_ACTIONS')!='true' or env.get('RUNNER_ENVIRONMENT')!='github-hosted'
            or env.get('RUNNER_OS')!='Linux' or env.get('UTER_CI_STRICT_RUNNER')!='true'
            or os.name!='posix' or os.geteuid()!=0):raise ProbeError('GUARD')
    socket_keys=('ActiveState','Accept','Triggers')
    service_keys=('ActiveState','SubState','MainPID','ExecMainPID','TriggeredBy')
    socket_unit=properties('docker.socket',socket_keys)
    service=properties('docker.service',service_keys)
    validate_units(socket_unit,service)
    value=service.get('MainPID','')
    if not re.fullmatch(r'[1-9][0-9]{0,9}',value) or value!=service.get('ExecMainPID') or int(value)<=1:
        raise ProbeError('SERVICE_PID')
    pid=int(value);proc=Path('/proc')/value
    if Path('/proc/1/comm').read_text().strip()!='systemd' or (proc/'comm').read_text().strip()!='dockerd':
        raise ProbeError('PROCESS_NAME')
    for namespace in ('pid','net'):
        stats=[os.stat('/proc/self/ns/'+namespace),os.stat('/proc/1/ns/'+namespace),os.stat(proc/'ns'/namespace)]
        if len({(info.st_dev,info.st_ino) for info in stats})!=1:raise ProbeError('NAMESPACES')
    path=os.path.realpath('/var/run/docker.sock');before=os.stat(path,follow_symlinks=False)
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid!=0:raise ProbeError('SOCKET_FILE')
    peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);pidfd=None
    try:
        peer.settimeout(5);peer.connect('/var/run/docker.sock')
        peerpid,uid,_=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if peerpid!=1 or uid!=0:raise ProbeError('SOCKET_PEER')
        pidfd=os.pidfd_open(pid,0)
        if select.select([pidfd],[],[],0)[0]:raise ProbeError('SERVICE_EXITED')
        inode=listening_inode(Path('/proc/net/unix').read_text(),path)
        if socket_holders(inode)!={1,pid}:raise ProbeError('LISTENER_HOLDERS')
        after=os.stat(path,follow_symlinks=False)
        if (before.st_dev,before.st_ino,before.st_mode,before.st_uid)!=(after.st_dev,after.st_ino,after.st_mode,after.st_uid):
            raise ProbeError('SOCKET_REPLACED')
        if properties('docker.socket',socket_keys)!=socket_unit or properties('docker.service',service_keys)!=service:
            raise ProbeError('UNIT_CHANGED')
        if select.select([pidfd],[],[],0)[0]:raise ProbeError('SERVICE_EXITED')
        readable,_,errors=select.select([peer],[],[peer],0)
        if readable or errors:raise ProbeError('SOCKET_CHANGED')
    finally:
        if pidfd is not None:os.close(pidfd)
        peer.close()


if __name__=='__main__':
    try:main()
    except ProbeError as error:
        allowed={'GUARD','PROPERTIES_MALFORMED','PROPERTIES_MISSING_MULTIPLE','PROPERTIES_TOO_LARGE',
                 'PROPERTY_MISSING_ACTIVESTATE','PROPERTY_MISSING_ACCEPT','PROPERTY_MISSING_SERVICE',
                 'PROPERTY_MISSING_SUBSTATE','PROPERTY_MISSING_MAINPID','PROPERTY_MISSING_EXECMAINPID',
                 'PROPERTY_MISSING_TRIGGERS','PROPERTY_MISSING_TRIGGEREDBY',
                 'SYSTEMCTL_UNAVAILABLE','SYSTEMCTL_TIMEOUT','SYSTEMCTL_FAILED','PROPERTIES_ENCODING','SYSTEMCTL_EXECUTION',
                 'SOCKET_UNIT','SERVICE_STATE','SERVICE_PID','PROCESS_NAME','NAMESPACES',
                 'SOCKET_FILE','SOCKET_PEER','SERVICE_EXITED','LISTENER','LISTENER_HOLDERS','PROC_VISIBILITY',
                 'SOCKET_REPLACED','UNIT_CHANGED','SOCKET_CHANGED'}
        code=str(error) if str(error) in allowed else 'UNVERIFIED'
        print('ACTIVATION_PROBE_'+code);sys.exit(1)
    except Exception:
        print('ACTIVATION_PROBE_UNVERIFIED');sys.exit(1)
    print('ACTIVATION_PROBE_POINT_IN_TIME_PASS')
