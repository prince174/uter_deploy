import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import kubernetes_fence_finalizer as finalizer
from scripts import kubernetes_loopback_intent as intent
from scripts import kubernetes_redis_identity as identity
from scripts import redis_fence_journal as journal
from tests.test_kubernetes_fence_finalizer import FakeAPI


class API(FakeAPI):
    def __init__(self, pod, deployment):
        super().__init__(pod)
        self.deployment = copy.deepcopy(deployment)
        self.patch_failure = None
        self.deployment_patches = []

    def get_deployment(self, name):
        return copy.deepcopy(self.deployment)

    def patch_deployment(self, name, operations):
        self.deployment_patches.append(copy.deepcopy(operations))
        if self.patch_failure == 'before':
            raise TimeoutError
        self.deployment['spec']['template']['spec']['containers'][0]['args'] = [intent.LOOPBACK]
        self.deployment['metadata']['resourceVersion'] = '81'
        if self.patch_failure == 'after':
            raise TimeoutError


@unittest.skipUnless(os.name == 'posix', 'private journal requires POSIX')
class LoopbackIntentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        pod = {'metadata': {'name': 'redis-123', 'namespace': 'test',
                            'uid': '7a1ae129-82a8-490f-86e3-84dfd735d330', 'resourceVersion': '77'},
               'spec': {'containers': [{'name': 'redis'}]},
               'status': {'phase': 'Running', 'containerStatuses': [{'name': 'redis',
                  'containerID': 'containerd://' + 'b' * 64, 'restartCount': 0,
                  'state': {'running': {'startedAt': 'now'}}}]}}
        deployment = {'kind': 'Deployment', 'metadata': {'name': 'test-redis', 'namespace': 'test',
             'uid': '099ae129-82a8-490f-86e3-84dfd735d330', 'resourceVersion': '80'},
             'spec': {'replicas': 1, 'template': {'spec': {'containers': [
                 {'name': 'redis', 'args': [identity.COMMAND]}]}}}}
        self.plan = finalizer.plan_from_pod('kind-test', 'test', 'redis-123', pod)
        finalizer.persist_plan(self.home, self.plan)
        record = journal.create(self.home, backend='kubernetes', site='test', resource=self.plan['uid'],
                                plan_sha256=finalizer.plan_hash(self.plan))
        self.operation = record['operation']
        self.api = API(pod, deployment)
        finalizer.hold(self.home, self.plan, self.operation, self.api)

    def prepare(self):
        return intent.prepare(self.home, self.plan, self.operation, self.api)

    def test_intent_precedes_single_cas_patch_and_never_authorizes_update(self):
        self.prepare()
        self.assertEqual(intent.classify(self.home, self.plan, self.operation, self.api)['state'], 'original_observed')
        result = intent.request(self.home, self.plan, self.operation, self.api)
        self.assertEqual(result, {'state': 'loopback_spec_observed', 'redis_isolated': False, 'safe_to_update': False})
        operations = self.api.deployment_patches[0]
        self.assertEqual(operations[:2], [{'op': 'test', 'path': '/metadata/uid', 'value': self.api.deployment['metadata']['uid']},
                                         {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '80'}])
        self.assertEqual(journal.read(self.home)['phase'], 'isolating')
        with self.assertRaisesRegex(intent.LoopbackIntentError, 'REQUEST_UNCERTAIN'):
            intent.request(self.home, self.plan, self.operation, self.api)
        self.assertEqual(len(self.api.deployment_patches), 1)

    def test_timeout_before_patch_is_read_only_classifiable_and_not_retried(self):
        self.prepare()
        self.api.patch_failure = 'before'
        with self.assertRaisesRegex(intent.LoopbackIntentError, 'REQUEST_UNCERTAIN'):
            intent.request(self.home, self.plan, self.operation, self.api)
        self.assertEqual(intent.classify(self.home, self.plan, self.operation, self.api)['state'], 'original_observed')
        with self.assertRaisesRegex(intent.LoopbackIntentError, 'REQUEST_UNCERTAIN'):
            intent.request(self.home, self.plan, self.operation, self.api)
        self.assertEqual(len(self.api.deployment_patches), 1)
        self.assertEqual(journal.read(self.home)['phase'], 'isolating')

    def test_timeout_after_patch_is_read_only_classifiable(self):
        self.prepare()
        self.api.patch_failure = 'after'
        with self.assertRaisesRegex(intent.LoopbackIntentError, 'REQUEST_UNCERTAIN'):
            intent.request(self.home, self.plan, self.operation, self.api)
        self.assertEqual(intent.classify(self.home, self.plan, self.operation, self.api)['state'], 'loopback_spec_observed')
        self.assertEqual(len(self.api.deployment_patches), 1)
        self.assertEqual(journal.read(self.home)['phase'], 'isolating')

    def test_foreign_uid_spec_rv_or_operation_refuses_reconciliation(self):
        self.prepare()
        original = copy.deepcopy(self.api.deployment)
        for kind in ('uid', 'spec', 'rv', 'operation'):
            self.api.deployment = copy.deepcopy(original)
            operation = self.operation
            if kind == 'uid': self.api.deployment['metadata']['uid'] = 'b99ae129-82a8-490f-86e3-84dfd735d330'
            if kind == 'spec': self.api.deployment['spec']['replicas'] = 2
            if kind == 'rv': self.api.deployment['metadata']['resourceVersion'] = '82'
            if kind == 'operation': operation = 'a' * 32
            with self.subTest(kind=kind), self.assertRaises(intent.LoopbackIntentError):
                intent.classify(self.home, self.plan, operation, self.api)
        self.assertEqual(self.api.deployment_patches, [])

    def test_unsafe_intent_or_missing_finalizer_prevents_patch(self):
        self.prepare()
        self.api.pod['metadata']['finalizers'] = []
        with self.assertRaisesRegex(intent.LoopbackIntentError, 'REQUEST_UNCERTAIN'):
            intent.request(self.home, self.plan, self.operation, self.api)
        (self.home / intent.NAME).unlink()
        (self.home / intent.NAME).symlink_to(self.home / 'missing')
        with self.assertRaises(intent.LoopbackIntentError):
            intent.request(self.home, self.plan, self.operation, self.api)
        self.assertEqual(self.api.deployment_patches, [])

    def test_existing_intent_never_overwritten(self):
        before = self.prepare()
        with self.assertRaisesRegex(intent.LoopbackIntentError, 'WRITE_UNCERTAIN'):
            self.prepare()
        self.assertEqual(intent._read(self.home), before)

    def test_untrusted_attempt_marker_or_fsync_failure_never_reaches_api(self):
        self.prepare()
        marker=self.home/intent.ATTEMPT_NAME
        marker.symlink_to(self.home/'missing')
        with self.assertRaisesRegex(intent.LoopbackIntentError, 'REQUEST_UNCERTAIN'):
            intent.request(self.home, self.plan, self.operation, self.api)
        marker.unlink()
        with patch.object(intent.os,'fsync',side_effect=OSError('disk failure')):
            with self.assertRaisesRegex(intent.LoopbackIntentError, 'REQUEST_UNCERTAIN'):
                intent.request(self.home, self.plan, self.operation, self.api)
        self.assertTrue(marker.exists())
        with self.assertRaisesRegex(intent.LoopbackIntentError, 'REQUEST_UNCERTAIN'):
            intent.request(self.home, self.plan, self.operation, self.api)
        self.assertEqual(self.api.deployment_patches, [])


if __name__ == '__main__':
    unittest.main()
