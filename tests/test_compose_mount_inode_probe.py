import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import ExitStack

from scripts import compose_mount_inode_probe as subject
from scripts import compose_mount_inode_ci as ci


@unittest.skipUnless(os.name=='posix' and hasattr(os,'pidfd_open') and hasattr(os,'O_PATH'),
                     'Linux pidfd and O_PATH required')
class MountInodeProbeTests(unittest.TestCase):
    def context(self, *, mismatch=False, symlink_parent=False, recycled=False, replaced_runtime=False):
        stack=ExitStack()
        file=lambda ino:SimpleNamespace(st_dev=10,st_ino=ino,st_uid=10001,st_gid=10001,st_mode=0o100400,st_nlink=1)
        directory=SimpleNamespace(st_dev=20,st_ino=200)
        proc=SimpleNamespace(st_dev=30,st_ino=300)
        namespace=SimpleNamespace(st_dev=40,st_ino=400)
        fake={10:SimpleNamespace(),11:proc,12:file(101),13:directory,17:file(102 if mismatch else 101),19:directory}
        def open_file(name,flags,*args,**kwargs):
            mapping={'/proc/123':11,'stat':18,'root':14,'run':15,'uter-maintenance':16,'key':17}
            if symlink_parent and name=='uter-maintenance':raise OSError('symlink')
            return mapping[name]
        def stat_file(name,*args,**kwargs):
            if name in ('/proc/self/ns/pid','/proc/1/ns/pid'):return namespace
            if name=='/proc/123':return SimpleNamespace(st_dev=30,st_ino=301 if recycled else 300)
            if name=='/fixture/runtime':return SimpleNamespace(st_dev=20,st_ino=201 if replaced_runtime else 200)
            return file(102 if name=='key' and mismatch else 101)
        procstat=b'123 (test (worker)) S '+b'0 '*18+b'12345 0\n'
        stack.enter_context(patch.object(subject.os,'geteuid',return_value=0))
        stack.enter_context(patch.object(subject.os,'pidfd_open',return_value=10))
        stack.enter_context(patch.object(subject.os,'open',side_effect=open_file))
        stack.enter_context(patch.object(subject.os,'close'))
        stack.enter_context(patch.object(subject.os,'read',return_value=procstat))
        stack.enter_context(patch.object(subject.os,'fstat',side_effect=lambda fd:fake[fd]))
        stack.enter_context(patch.object(subject.os,'stat',side_effect=stat_file))
        stack.enter_context(patch.object(subject.select,'select',return_value=([],[],[])))
        stack.enter_context(patch.object(subject,'_runtime_dir',return_value=19))
        stack.enter_context(patch.object(subject.compose_maintenance_secret,'_open_key',return_value=(12,file(101),13,directory)))
        return stack

    def test_matching_inode_is_only_momentary_init_evidence(self):
        with self.context():result=subject.observe(123,'/fixture/runtime')
        self.assertTrue(result['init_key_inode_match'])
        self.assertFalse(result['host_pid_namespace_verified'])
        self.assertFalse(result['worker_identity_verified'])
        self.assertFalse(result['continuous_fence_verified'])
        self.assertFalse(result['safe_to_update'])

    def test_replacement_symlink_or_pid_recycle_fail_closed(self):
        for kwargs in ({'mismatch':True},{'symlink_parent':True},{'recycled':True},{'replaced_runtime':True}):
            with self.subTest(case=kwargs),self.context(**kwargs):
                with self.assertRaisesRegex(subject.ProbeError,'^COMPOSE_INIT_KEY_INODE_UNVERIFIED$'):
                    subject.observe(123,'/fixture/runtime')

    def test_invalid_pid_is_rejected_before_pidfd(self):
        with patch.object(subject.os,'geteuid',return_value=0),patch.object(subject.os,'pidfd_open') as opened:
            with self.assertRaises(subject.ProbeError):subject.observe(1,'/fixture/runtime')
            opened.assert_not_called()

    def test_ci_refuses_non_hosted_environment_before_docker(self):
        with patch.dict('os.environ',{},clear=True),patch.object(ci,'run') as run:
            with self.assertRaisesRegex(ValueError,'INODE_FIXTURE_ENVIRONMENT_UNVERIFIED'):ci.main()
            run.assert_not_called()

    @unittest.skipUnless(os.geteuid()==0,'requires root-owned private fixture')
    def test_runtime_ancestor_rejects_symlink_and_unsafe_directory(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'runtime';path.mkdir(mode=0o700)
            fd=subject._runtime_dir(path);os.close(fd)
            alias=Path(root)/'link';alias.symlink_to(path,target_is_directory=True)
            with self.assertRaises(OSError):subject._runtime_dir(alias)
            path.chmod(0o777)
            with self.assertRaises(ValueError):subject._runtime_dir(path)
