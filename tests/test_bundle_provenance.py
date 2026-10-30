import base64
import hashlib
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import uterctl
from scripts import bundle


class BundleProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        key = Ed25519PrivateKey.generate()
        self.private = self.root / 'private.pem'
        self.public = self.root / 'public.pem'
        self.private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
        self.public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                               serialization.PublicFormat.SubjectPublicKeyInfo))

    def make_bundle(self, gated=True):
        manifest = {'schema': 1, 'config_schema': 1, 'tooling_schema': 1,
                    'status': 'released', 'version': '0.1.7', 'source_commit': 'a' * 40,
                    'data_epoch': 2 if gated else 1, 'upgrade_from': ['0.1.6'],
                    'images': {name: 'registry.example/' + name + '@sha256:' + 'b' * 64
                               for name in ('guardrail', 'agent', 'redis')}}
        if gated:
            manifest['session_identity_gate'] = {'schema': 1, 'from_epoch': 1, 'to_epoch': 2,
                                                   'policy': 'block_unverified_sessions'}
        source = self.root / 'manifest.json'
        source.write_text(json.dumps(manifest), encoding='utf-8')
        result = self.root / 'bundle'
        bundle.build(source, result, self.private)
        return result

    def test_gated_bundle_signs_exact_placeholder_and_document(self):
        result = self.make_bundle()
        placeholder = result / 'scripts/session_provenance.py'
        doc = result / 'docs/session-provenance-contract.md'
        source = uterctl.ROOT / 'scripts/session_provenance.py'
        self.assertEqual(placeholder.read_bytes(), source.read_bytes())
        self.assertTrue(doc.is_file())
        inventory = json.loads((result / 'checksums.json').read_text(encoding='utf-8'))
        self.assertEqual(inventory['scripts/session_provenance.py'], hashlib.sha256(placeholder.read_bytes()).hexdigest())
        self.assertIn('docs/session-provenance-contract.md', inventory)
        self.assertEqual(uterctl.verify(result, self.public)['session_identity_gate']['policy'],
                         'block_unverified_sessions')

    def test_changed_or_deleted_placeholder_rejected_by_signed_inventory(self):
        result = self.make_bundle()
        placeholder = result / 'scripts/session_provenance.py'
        original = placeholder.read_bytes()
        for mutation in ('change', 'delete'):
            with self.subTest(mutation=mutation):
                if mutation == 'change':
                    placeholder.write_bytes(original + b'\n# modified\n')
                else:
                    placeholder.unlink()
                with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
                    uterctl.verify(result, self.public)
                placeholder.write_bytes(original)
        uterctl.verify(result, self.public)

    def test_non_gated_bundle_keeps_previous_inventory(self):
        result = self.make_bundle(gated=False)
        self.assertFalse((result / 'scripts/session_provenance.py').exists())
        self.assertFalse((result / 'scripts/session_migration_guard.py').exists())
        self.assertEqual((result / 'scripts/redis_fence_journal.py').read_bytes(),
                         (uterctl.ROOT / 'scripts/redis_fence_journal.py').read_bytes())
        for name in ('compose_nsfirewall_adapter.py','compose_nsfirewall_protocol.py',
                     'compose_nsfirewall_checkpoint.py','compose_fence_adapter.py','compose_fence_recovery_plan.py',
                     'compose_redis_diagnostic.py','compose_systemd_activation.py','experimental_docker_activation_ci.py',
                     'compose_snapshot_only.py','snapshot_only_receipts.py','compose_fence_start.py','compose_fence_resume.py',
                     'compose_fence_origin.py','compose_fence_finalize.py','compose_fenced_update.py',
                     'experimental_operation_lock.py','managed_operation_lock.py',
                     'maintenance_receipt.py','maintenance_protocol.py','maintenance_evidence.py','maintenance_transport.py',
                     'kubernetes_sealed_config.py','kubernetes_trusted_kubectl.py','kubernetes_fence_pin.py',
                     'kubernetes_redis_identity.py','compose_maintenance_check.py','compose_maintenance_coordinator.py',
                     'kubernetes_fence_finalizer.py','kubernetes_writer_quiesce.py','kubernetes_writer_finalizer.py',
                     'kubernetes_maintenance_preflight.py','kubernetes_maintenance_runtime.py',
                     'kubernetes_fence_coordinator.py','kubernetes_fence_profile_store.py','kubernetes_pinned_preflight.py',
                     'kubernetes_audit_reader.py','kubernetes_audit_writer_guard.py','kubernetes_backup_coordinator.py',
                     'kubernetes_config_snapshot.py','kubernetes_loopback_auth.py','kubernetes_loopback_intent.py',
                     'kubernetes_loopback_recovery.py','kubernetes_loopback_snapshot.py','kubernetes_redis_finalizer_release.py',
                     'kubernetes_redis_reverse_finalizer.py','kubernetes_redis_shutdown.py','kubernetes_runtime_pin.py'):
            with self.subTest(name=name):
                path=result/'scripts'/name
                self.assertEqual(path.read_bytes(),(uterctl.ROOT/'scripts'/name).read_bytes())
                self.assertIn('scripts/'+name,json.loads((result/'checksums.json').read_text()))
        self.assertEqual(uterctl.verify(result, self.public)['data_epoch'], 1)

    def test_signed_compose_coordinator_rejects_modification(self):
        result=self.make_bundle(gated=False)
        path=result/'scripts'/'compose_maintenance_coordinator.py'
        original=path.read_bytes()
        self.assertEqual(original,(uterctl.ROOT/'scripts'/'compose_maintenance_coordinator.py').read_bytes())
        uterctl.verify(result,self.public)
        path.write_bytes(original+b'\n# tampered\n')
        with self.assertRaisesRegex(ValueError,'inventory mismatch'):
            uterctl.verify(result,self.public)

    def test_signed_compose_maintenance_secret_helper_rejects_modification(self):
        result=self.make_bundle(gated=False)
        path=result/'scripts'/'compose_maintenance_secret.py'
        self.assertEqual(path.read_bytes(),(uterctl.ROOT/'scripts'/'compose_maintenance_secret.py').read_bytes())
        uterctl.verify(result,self.public)
        path.write_bytes(path.read_bytes()+b'\n# tampered\n')
        with self.assertRaisesRegex(ValueError,'inventory mismatch'):
            uterctl.verify(result,self.public)

    def test_legacy_signed_bundle_without_new_helper_still_verifies(self):
        result=self.make_bundle(gated=False)
        (result/'scripts/compose_maintenance_secret.py').unlink()
        raw=json.dumps(uterctl.inventory(result),sort_keys=True,indent=2).encode()
        private=serialization.load_pem_private_key(self.private.read_bytes(),password=None)
        (result/'checksums.json').write_bytes(raw)
        (result/'checksums.sig').write_bytes(base64.b64encode(private.sign(raw)))
        self.assertEqual(uterctl.verify(result,self.public)['data_epoch'],1)

    def test_signed_compose_coordinator_imports_in_isolated_executor_with_gate_closed(self):
        result=self.make_bundle(gated=False)
        code=('import importlib.util,sys; from pathlib import Path; '
              'p=Path(sys.argv[1]); s=importlib.util.spec_from_file_location("executor_entrypoint",p/"uterctl.py"); '
              'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
              'm._load_signed_fence_executor(Path(sys.argv[2])); '
              'from scripts import compose_maintenance_coordinator as c; '
              'exec("try:\\n c._verify_ingress(None,None,None)\\nexcept c.ComposeMaintenanceError:\\n pass\\nelse:\\n raise AssertionError(\'ingress gate opened\')")')
        run=subprocess.run([sys.executable,'-I','-B','-c',code,str(result),str(self.public)],
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=15)
        self.assertEqual(run.returncode,0,run.stderr)

    def test_signed_kubernetes_maintenance_static_script_dependencies_are_present(self):
        result=self.make_bundle(gated=False)
        inventory=json.loads((result/'checksums.json').read_text(encoding='utf-8'))
        pending=['kubernetes_maintenance_preflight','kubernetes_maintenance_runtime','kubernetes_fence_coordinator']
        visited=set()
        while pending:
            name=pending.pop()
            if name in visited:continue
            visited.add(name)
            relative='scripts/'+name+'.py'
            self.assertIn(relative,inventory)
            tree=ast.parse((result/relative).read_text(encoding='utf-8'),filename=relative)
            for node in ast.walk(tree):
                if isinstance(node,ast.ImportFrom) and node.module=='scripts':
                    pending.extend(alias.name for alias in node.names)
                elif isinstance(node,ast.ImportFrom) and node.module and node.module.startswith('scripts.'):
                    pending.append(node.module.split('.')[1])
                elif isinstance(node,ast.Import):
                    pending.extend(alias.name.split('.')[1] for alias in node.names if alias.name.startswith('scripts.'))
                # Catch some obvious dynamic imports for review. This is not a
                # proof against aliases, eval, getattr or arbitrary dynamic code.
                elif isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='__import__':
                    if not (len(node.args)==1 and isinstance(node.args[0],ast.Constant) and node.args[0].value=='sys'):
                        self.fail(relative+' uses unreviewed dynamic __import__')
                elif (isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
                      and isinstance(node.func.value,ast.Name) and node.func.value.id=='importlib'):
                    self.fail(relative+' uses dynamic importlib')
        self.assertTrue({'kubernetes_writer_finalizer','kubernetes_writer_quiesce',
                         'kubernetes_fence_finalizer','maintenance_transport'}.issubset(visited))
        uterctl.verify(result,self.public)

    def test_signed_kubernetes_maintenance_modules_reject_modification(self):
        result=self.make_bundle(gated=False)
        for name in ('kubernetes_fence_finalizer','kubernetes_writer_quiesce','kubernetes_writer_finalizer',
                     'kubernetes_maintenance_preflight','kubernetes_maintenance_runtime',
                     'kubernetes_fence_coordinator','kubernetes_fence_profile_store','kubernetes_pinned_preflight',
                     'kubernetes_audit_reader','kubernetes_audit_writer_guard','kubernetes_backup_coordinator',
                     'kubernetes_config_snapshot','kubernetes_loopback_auth','kubernetes_loopback_intent',
                     'kubernetes_loopback_recovery','kubernetes_loopback_snapshot','kubernetes_redis_finalizer_release',
                     'kubernetes_redis_reverse_finalizer','kubernetes_redis_shutdown','kubernetes_runtime_pin'):
            with self.subTest(name=name):
                path=result/'scripts'/(name+'.py');original=path.read_bytes()
                path.write_bytes(original+b'\n# tampered\n')
                with self.assertRaisesRegex(ValueError,'inventory mismatch'):uterctl.verify(result,self.public)
                path.write_bytes(original)
        uterctl.verify(result,self.public)

    def test_signed_kubernetes_maintenance_imports_isolated_with_gate_closed(self):
        result=self.make_bundle(gated=False)
        code=('import importlib.util,sys; from pathlib import Path; '
              'p=Path(sys.argv[1]); s=importlib.util.spec_from_file_location("executor_entrypoint",p/"uterctl.py"); '
              'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
              'm._load_signed_fence_executor(Path(sys.argv[2])); '
              'from scripts import kubernetes_maintenance_preflight as pflight, kubernetes_maintenance_runtime as r, '
              'kubernetes_fence_finalizer, kubernetes_writer_finalizer, kubernetes_writer_quiesce, '
              'kubernetes_fence_coordinator, kubernetes_fence_profile_store, kubernetes_pinned_preflight; '
              'exec("try:\\n r._require_fences(None,None,None)\\nexcept r.RuntimeError:\\n pass\\nelse:\\n raise AssertionError(\'ingress gate opened\')")')
        run=subprocess.run([sys.executable,'-I','-B','-c',code,str(result),str(self.public)],
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=15)
        self.assertEqual(run.returncode,0,run.stderr)

    @unittest.skipUnless(os.name=='posix','private POSIX installation')
    def test_isolated_signed_kubernetes_cli_refuses_missing_profile_without_operation(self):
        result=self.make_bundle(gated=False)
        home=self.root/'home';home.mkdir(mode=0o700)
        command=[sys.executable,'-I','-B',str(result/'uterctl.py'),'maintenance-check-kubernetes',
                 '--home',str(home),'--bundle',str(result),'--key',str(self.public),
                 '--executor-key',str(self.public),'--backup-key',str(self.root/'missing-backup-key'),
                 '--operator-profile',str(self.root/'missing-profile'),
                 '--kubeconfig',str(self.root/'missing-kubeconfig'),'--kubectl',str(self.root/'missing-kubectl')]
        run=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=15)
        self.assertNotEqual(run.returncode,0)
        self.assertIn('KUBE_OPERATOR_PROFILE_UNVERIFIED',run.stderr)
        self.assertEqual(run.stdout,'')
        self.assertFalse((home/'operation.lock').exists())
        self.assertFalse((home/'redis-fence-operation.json').exists())
