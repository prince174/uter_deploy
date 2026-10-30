import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import kubernetes_redis_finalizer_release as release
from tests.test_kubernetes_redis_shutdown import ShutdownObservationTests


@unittest.skipUnless(os.name=='posix','journal requires POSIX')
class RedisReleaseTests(unittest.TestCase):
    def setUp(self):
        ShutdownObservationTests.setUp(self)
        self.key=b'k'*32
        self.session=SimpleNamespace(api=self.api,_scope=lambda:None)

    def invoke(self):
        with patch.object(release.loopback,'classify',return_value={'state':'loopback_spec_observed'}):
            return release.release(self.home,self.session,self.record['operation'],self.key)

    def test_valid_termination_is_one_shot_and_never_authorizes_update(self):
        self.assertEqual(self.invoke(),{'result':'redis_finalizer_release_requested',
                                       'safe_to_backup':False,'safe_to_update':False})
        self.assertEqual(self.api.pod['metadata']['finalizers'],[])
        count=len(self.api.patches)
        with self.assertRaises(release.RedisReleaseError):self.invoke()
        self.assertEqual(len(self.api.patches),count)

    def test_unknown_patch_outcome_is_never_retried(self):
        self.api.failure='after'
        with self.assertRaises(release.RedisReleaseError):self.invoke()
        count=len(self.api.patches);self.api.failure=None
        with self.assertRaises(release.RedisReleaseError):self.invoke()
        self.assertEqual(len(self.api.patches),count)

    def test_nonzero_exit_never_patches(self):
        self.api.pod['status']['containerStatuses'][0]['state']['terminated']['exitCode']=137
        count=len(self.api.patches)
        with self.assertRaises(release.RedisReleaseError):self.invoke()
        self.assertEqual(len(self.api.patches),count)
