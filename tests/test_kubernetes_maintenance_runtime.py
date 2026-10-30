import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import kubernetes_maintenance_runtime as runtime, redis_fence_journal


class DurableInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.operation = '1'*32
        self.plan_hash = 'a'*64
        self.key = b'k'*32
        self.plan = {'uid':'11111111-1111-1111-1111-111111111111','namespace':'uter-test'}
        self.session = SimpleNamespace(home=self.home, site='uter-test', manifest={'image':'signed'}, _guard=lambda:None)
        redis_fence_journal.create(self.home, backend='kubernetes', site=self.session.site,
            resource=self.plan['uid'], plan_sha256=self.plan_hash, operation=self.operation)
        self.snapshot = {'writers':{service:{'pod':f'uter-test-{service}-x', 'uid':service,
            'container_id':'containerd://'+'a'*64, 'pod_spec_sha256':'b'*64,
            'deployment_uid':service, 'secret_uid':'secret', 'secret_rv':'42'} for service in ('agent','guardrail')},
            'ingress_fenced':False, 'restart_fenced':False, 'redis_isolated':False,
            'safe_to_start':False, 'safe_to_update':False}
        self.patches = [patch.object(runtime.finalizer,'read_plan',return_value=self.plan),
            patch.object(runtime.finalizer,'_check_journal'), patch.object(runtime.finalizer,'plan_hash',return_value=self.plan_hash),
            patch.object(runtime.preflight,'observe',side_effect=lambda *args, **kwargs:copy.deepcopy(self.snapshot))]
        for item in self.patches:
            item.start(); self.addCleanup(item.stop)

    def test_inventory_durable_and_coordinator_refuses_any_request(self):
        self.assertFalse(runtime.prepare(self.session,self.operation,self.key)['safe_to_backup'])
        with patch.object(runtime.maintenance_transport,'request') as request:
            with self.assertRaisesRegex(runtime.RuntimeError,'KUBE_MAINTENANCE_FENCE_UNVERIFIED'):
                runtime.collect(self.session,self.operation,self.key)
            request.assert_not_called()
        self.assertTrue((self.home/'maintenance-kubernetes-inventory.json').is_file())

    def test_changed_writer_and_tampering_fail_before_requests(self):
        runtime.prepare(self.session,self.operation,self.key)
        self.snapshot['writers']['agent']['container_id']='containerd://'+'c'*64
        with self.assertRaises(runtime.RuntimeError): runtime.collect(self.session,self.operation,self.key)
        self.snapshot['writers']['agent']['container_id']='containerd://'+'a'*64
        (self.home/'maintenance-kubernetes-inventory.json').write_text('{}')
        with self.assertRaises(ValueError): runtime.collect(self.session,self.operation,self.key)

    def test_duplicate_prepare_never_overwrites_inventory(self):
        runtime.prepare(self.session,self.operation,self.key)
        before=(self.home/'maintenance-kubernetes-inventory.json').read_bytes()
        with self.assertRaises(runtime.RuntimeError): runtime.prepare(self.session,self.operation,self.key)
        self.assertEqual(before,(self.home/'maintenance-kubernetes-inventory.json').read_bytes())

    def test_secret_rotation_and_manifest_change_invalidate_inventory(self):
        runtime.prepare(self.session,self.operation,self.key)
        self.snapshot['writers']['agent']['secret_rv']='43'
        with self.assertRaises(runtime.RuntimeError): runtime.collect(self.session,self.operation,self.key)
        self.snapshot['writers']['agent']['secret_rv']='42'
        self.session.manifest={'image':'changed'}
        with self.assertRaises(runtime.RuntimeError): runtime.collect(self.session,self.operation,self.key)


if __name__ == '__main__': unittest.main()
