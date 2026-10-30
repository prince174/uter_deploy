import os
from pathlib import Path
import tempfile
import unittest

from scripts import compose_fence_origin as origin, redis_fence_journal as journal


@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'),'requires POSIX private files')
class FenceOriginTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name);self.key=b'k'*32
        self.record=journal.create(self.home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
        for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','pre_capture_aborting')):
            self.record=journal.advance(self.home,operation=self.record['operation'],expected=old,next_phase=new)

    def test_origin_is_authenticated_bound_and_write_once(self):
        expected=origin.ensure(self.home,self.key,self.record,'pre_capture')
        self.assertEqual(origin.ensure(self.home,self.key,self.record,'pre_capture'),expected)
        self.assertEqual(origin.read(self.home,self.key,self.record),expected)
        for key,record in ((b'x'*32,self.record),(self.key,dict(self.record,operation='0'*32))):
            with self.assertRaisesRegex(origin.OriginError,'^FENCE_ORIGIN_UNVERIFIED$'):
                origin.read(self.home,key,record)
        path=self.home/origin.NAME;raw=path.read_bytes();path.write_bytes(raw.replace(b'pre_capture',b'snapshot'))
        with self.assertRaisesRegex(origin.OriginError,'^FENCE_ORIGIN_UNVERIFIED$'):origin.read(self.home,self.key,self.record)

    def test_phase_and_origin_conflict_never_replace_existing_file(self):
        expected=origin.ensure(self.home,self.key,self.record,'pre_capture')
        before=(self.home/origin.NAME).read_bytes()
        with self.assertRaisesRegex(origin.OriginError,'^FENCE_ORIGIN_PHASE_INVALID$'):
            origin.ensure(self.home,self.key,self.record,'snapshot','1'*64)
        forged=dict(self.record,phase='snapshot_releasing')
        with self.assertRaisesRegex(origin.OriginError,'^FENCE_ORIGIN_CONFLICT$'):
            origin.ensure(self.home,self.key,forged,'snapshot','1'*64)
        self.assertEqual((self.home/origin.NAME).read_bytes(),before)
        self.assertEqual(origin.read(self.home,self.key,self.record),expected)

    def test_dangling_symlink_or_hardlink_are_never_accepted(self):
        target=self.home/origin.NAME;target.symlink_to(self.home/'missing')
        with self.assertRaises(origin.OriginError):origin.ensure(self.home,self.key,self.record,'pre_capture')
        self.assertTrue(target.is_symlink());target.unlink()
        origin.ensure(self.home,self.key,self.record,'pre_capture')
        os.link(target,self.home/'foreign-link')
        with self.assertRaises(origin.OriginError):origin.read(self.home,self.key,self.record)
