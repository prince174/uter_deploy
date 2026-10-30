import unittest
from scripts import experimental_docker_activation_ci as probe


class ActivationProbeTests(unittest.TestCase):
    def test_properties_reject_missing_duplicate_and_extra(self):
        self.assertEqual(probe.parse_properties('A=x\nB=y\n',('A','B')),
                         {'A':'x','B':'y'})
        for raw in ('A=x\n','A=x\nA=x\nB=y\n','A=x\nB=y\nC=z\n'):
            with self.subTest(raw=raw),self.assertRaises(probe.ProbeError):
                probe.parse_properties(raw,('A','B'))

    def test_listener_requires_exact_unique_stream_listening_socket(self):
        prefix='Num RefCount Protocol Flags Type St Inode Path\n'
        row='000: 00000002 00000000 00010000 0001 01 42 /run/docker.sock\n'
        self.assertEqual(probe.listening_inode(prefix+row,'/run/docker.sock'),'42')
        for bad in (prefix+row+row,prefix+row.replace('00010000','00000000'),prefix+row.replace(' 01 ',' 03 ')):
            with self.subTest(bad=bad),self.assertRaises(probe.ProbeError):
                probe.listening_inode(bad,'/run/docker.sock')

    def test_nonhosted_does_not_inspect_systemd(self):
        from unittest import mock
        with mock.patch.dict(probe.os.environ,{},clear=True),mock.patch.object(probe,'properties') as properties:
            with self.assertRaises(probe.ProbeError):probe.main()
            properties.assert_not_called()

    def test_holders_include_threads_and_inaccessible_proc_fails_closed(self):
        import os
        from pathlib import Path
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for pid,tid,inode in (('1','1','42'),('99','100','42'),('77','77','23')):
                fd=root/pid/'task'/tid/'fd'/'7';fd.parent.mkdir(parents=True)
                try:os.symlink('socket:['+inode+']',fd)
                except OSError:self.skipTest('symlinks unavailable')
            with mock.patch.object(probe,'PROC_ROOT',root):
                self.assertEqual(probe.socket_holders('42'),{1,99})
                with mock.patch.object(Path,'iterdir',side_effect=PermissionError):
                    with self.assertRaises(probe.ProbeError):probe.socket_holders('42')

if __name__=='__main__':unittest.main()
