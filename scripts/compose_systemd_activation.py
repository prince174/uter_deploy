"""Experimental systemd Docker listener attribution, not a production gate.

Trust host root, systemd and Docker; host procfs must expose all processes and
threads. No concurrent socket passing, daemon restart or host administrators are
permitted. These checks are observations, not an atomic defence against root.
"""
import os
from pathlib import Path
import re
import select
import stat

from scripts import experimental_docker_activation_ci as probe


class SystemdActivationError(ValueError): pass


def daemon_pid():
    """Return verified daemon PID only for a fully observed systemd listener."""
    socket_keys=('ActiveState','Accept','Triggers')
    service_keys=('ActiveState','SubState','MainPID','ExecMainPID','TriggeredBy')
    pidfd=None
    try:
        socket_unit=probe.properties('docker.socket',socket_keys)
        service=probe.properties('docker.service',service_keys)
        probe.validate_units(socket_unit,service)
        value=service['MainPID']
        if not re.fullmatch(r'[1-9][0-9]{0,9}',value) or value!=service['ExecMainPID'] or int(value)<=1:
            raise ValueError
        pid=int(value);proc=Path('/proc')/value
        if Path('/proc/1/comm').read_text().strip()!='systemd' or (proc/'comm').read_text().strip()!='dockerd':
            raise ValueError
        if Path(os.readlink(proc/'exe')).name!='dockerd':raise ValueError
        status=(proc/'status').read_text().splitlines()
        fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in status if ':' in line}
        if fields.get('Pid')!=value or fields.get('Uid','').split()!=['0','0','0','0']:raise ValueError
        pidfd=os.pidfd_open(pid,0)
        if select.select([pidfd],[],[],0)[0]:raise ValueError
        for namespace in ('pid','net'):
            stats=[os.stat('/proc/self/ns/'+namespace),os.stat('/proc/1/ns/'+namespace),os.stat(proc/'ns'/namespace)]
            if len({(item.st_dev,item.st_ino) for item in stats})!=1:raise ValueError
        path=os.path.realpath('/var/run/docker.sock');before=os.stat(path,follow_symlinks=False)
        if not stat.S_ISSOCK(before.st_mode) or before.st_uid!=0:raise ValueError
        inode=probe.listening_inode(Path('/proc/net/unix').read_text(),path)
        if probe.socket_holders(inode)!={1,pid}:raise ValueError
        after=os.stat(path,follow_symlinks=False)
        if (before.st_dev,before.st_ino,before.st_mode,before.st_uid)!=(after.st_dev,after.st_ino,after.st_mode,after.st_uid):
            raise ValueError
        if (probe.properties('docker.socket',socket_keys)!=socket_unit
                or probe.properties('docker.service',service_keys)!=service
                or select.select([pidfd],[],[],0)[0]):raise ValueError
        return pid
    except (ValueError,OSError,UnicodeError,AttributeError,KeyError):
        raise SystemdActivationError('SYSTEMD_ACTIVATION_UNVERIFIED') from None
    finally:
        if pidfd is not None:os.close(pidfd)
