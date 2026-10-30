import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import compose_systemd_activation as activation


@unittest.skipUnless(os.name=='posix' and hasattr(os,'pidfd_open'),'Linux pidfd required')
class SystemdActivationTests(unittest.TestCase):
    def test_only_checked_listener_service_and_process_are_accepted(self):
        socket_unit={'ActiveState':'active','Accept':'no','Triggers':'docker.service'}
        service={'ActiveState':'active','SubState':'running','MainPID':'99','ExecMainPID':'99',
                 'TriggeredBy':'docker.socket'}
        def properties(unit,keys):return dict(socket_unit if unit=='docker.socket' else service)
        def read(path,*args,**kwargs):
            return {'/proc/1/comm':'systemd\n','/proc/99/comm':'dockerd\n',
                    '/proc/99/status':'Pid:\t99\nUid:\t0\t0\t0\t0\n','/proc/net/unix':'fixture'}[str(path)]
        def inspect(path,*args,**kwargs):
            if str(path)=='/run/docker.sock':
                return SimpleNamespace(st_dev=2,st_ino=3,st_mode=stat.S_IFSOCK|0o660,st_uid=0)
            return SimpleNamespace(st_dev=1,st_ino=7)
        with mock.patch.object(activation.probe,'properties',side_effect=properties), \
             mock.patch.object(Path,'read_text',read),mock.patch.object(activation.os,'stat',side_effect=inspect), \
             mock.patch.object(activation.os.path,'realpath',return_value='/run/docker.sock'), \
             mock.patch.object(activation.os,'readlink',return_value='/usr/bin/dockerd'), \
             mock.patch.object(activation.os,'pidfd_open',return_value=42),mock.patch.object(activation.os,'close'), \
             mock.patch.object(activation.select,'select',return_value=([],[],[])), \
             mock.patch.object(activation.probe,'listening_inode',return_value='123'), \
             mock.patch.object(activation.probe,'socket_holders',return_value={1,99}) as holders:
            self.assertEqual(activation.daemon_pid(),99)
            holders.return_value={1,99,101}
            with self.assertRaises(activation.SystemdActivationError):activation.daemon_pid()
            holders.return_value={1,99};socket_unit['Triggers']='other.service'
            with self.assertRaises(activation.SystemdActivationError):activation.daemon_pid()
            socket_unit['Triggers']='docker.service';service['ExecMainPID']='100'
            with self.assertRaises(activation.SystemdActivationError):activation.daemon_pid()

if __name__=='__main__':unittest.main()
