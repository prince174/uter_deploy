import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import uterctl as u


def manifest(version="1.0.0", previous=None):
    return {"schema": 1, "config_schema": 1, "status": "released", "version": version,
            "source_commit": "a" * 40, "data_epoch": 1, "upgrade_from": previous or [],
            "images": {n: f"registry.example/{n}@sha256:" + "a" * 64 for n in ["guardrail", "agent", "redis"]}}


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "installation"
        (self.home / "runtime").mkdir(parents=True)
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.root / "trusted.pem"
        self.pub.write_bytes(self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        u.write(self.home / "runtime/site.json", {"backend": "compose", "name": "uter-test", "namespace": "uter-test", "smoke_command": ["acceptance"]})

    def bundle(self, m=None, name="bundle"):
        p = self.root / name
        p.mkdir()
        u.write(p / "manifest.json", m or manifest())
        for name in ["compose/compose.yaml", "charts/uter/Chart.yaml", "empty.env"]:
            f = p / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("fixture")
        self.sign(p)
        return p

    def sign(self, p):
        raw = json.dumps(u.inventory(p), sort_keys=True).encode()
        (p / "checksums.json").write_bytes(raw)
        (p / "checksums.sig").write_bytes(base64.b64encode(self.key.sign(raw)))

    def call(self, command, b, extra=()):
        u.main([command, "--home", str(self.home), "--bundle", str(b), "--key", str(self.pub), *extra])

    def test_signed_bundle(self):
        self.assertEqual(u.verify(self.bundle(), self.pub)["version"], "1.0.0")

    def test_incomplete_recovery_blocks_controller_mutations(self):
        b=self.bundle()
        u.write(self.home/'recovery-operation.json',{'phase':'starting'})
        with patch.object(u,'deploy') as deploy:
            with self.assertRaisesRegex(ValueError,'Recovery is incomplete'):
                self.call('apply',b)
            deploy.assert_not_called()
        self.assertEqual(u.verify(b,self.pub)['version'],'1.0.0')

    def test_tampering(self):
        b = self.bundle()
        (b / "compose/compose.yaml").write_text("modified")
        with self.assertRaises(ValueError): u.verify(b, self.pub)

    def test_extra_file(self):
        b = self.bundle()
        (b / "source.py").write_text("hidden")
        with self.assertRaises(ValueError): u.verify(b, self.pub)

    def test_nested_checksums_not_exempt(self):
        b = self.bundle()
        (b / "compose/checksums.json").write_text("injected")
        with self.assertRaises(ValueError): u.verify(b, self.pub)

    def test_wrong_key(self):
        b = self.bundle()
        self.pub.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        with self.assertRaises(Exception): u.verify(b, self.pub)

    def test_examples_refused(self):
        m = manifest(); m["status"] = "example"
        with self.assertRaises(ValueError): u.validate(m)

    def test_mutable_images_refused(self):
        m = manifest(); m["images"]["agent"] = "agent:latest"
        with self.assertRaises(ValueError): u.validate(m)

    def test_path_traversal_version_refused(self):
        m = manifest(); m["version"] = "../../etc"
        with self.assertRaises(ValueError): u.validate(m)

    def test_upgrade_compatibility(self):
        with self.assertRaises(ValueError): u.transition(manifest(), manifest("2.0.0"))
        u.transition(manifest(), manifest("1.1.0", ["1.0.0"]))

    def test_data_migration_refused(self):
        m = manifest("1.1.0", ["1.0.0"]); m["data_epoch"] = 2
        with self.assertRaises(ValueError): u.transition(manifest(), m)

    def test_operation_lock(self):
        with u.locked(self.home):
            with self.assertRaises(FileExistsError):
                with u.locked(self.home): pass
        self.assertFalse((self.home / "operation.lock").exists())

    def test_success_commits_state_after_smoke(self):
        b = self.bundle()
        with patch.object(u, "deploy") as deploy, patch.object(u, "run") as run:
            self.call("apply", b)
        state = u.read(self.home / "state.json")
        self.assertEqual(state["current"]["version"], "1.0.0")
        self.assertIsNone(state["pending"])
        run.assert_called_once()
        self.assertEqual(deploy.call_count, 2)

    def test_failed_smoke_does_not_report_success(self):
        b = self.bundle()
        with patch.object(u, "deploy"), patch.object(u, "run", side_effect=RuntimeError("smoke failed")):
            with self.assertRaises(RuntimeError): self.call("apply", b)
        state = u.read(self.home / "state.json")
        self.assertIsNone(state["current"])
        self.assertEqual(state["pending"]["version"], "1.0.0")

    def test_upgrade_requires_backup_receipt(self):
        u.write(self.home / "state.json", {"current": manifest(), "previous": None, "pending": None})
        with self.assertRaisesRegex(ValueError, "backup-receipt"):
            self.call("apply", self.bundle(manifest("1.1.0", ["1.0.0"])))

    def test_resume_requires_pending_version(self):
        with self.assertRaisesRegex(ValueError, "pending release"):
            self.call("resume", self.bundle())

    def test_first_install_failure_can_resume(self):
        b = self.bundle()
        u.write(self.home / "state.json", {"current": None, "previous": None, "pending": manifest()})
        receipt = self.root / "backup.json"
        u.write(receipt, {"version": "1.0.0", "backup_id": "partial-install-snapshot"})
        with patch.object(u, "deploy"), patch.object(u, "run"):
            self.call("resume", b, ["--backup-receipt", str(receipt)])
        self.assertIsNone(u.read(self.home / "state.json")["pending"])

    def test_failed_upgrade_can_rollback(self):
        old = self.bundle()
        with patch.object(u, "deploy"), patch.object(u, "run"):
            self.call("apply", old)
        new = self.bundle(manifest("1.1.0", ["1.0.0"]), "new")
        receipt = self.root / "backup.json"
        u.write(receipt, {"version": "1.0.0", "backup_id": "snapshot-1"})
        with patch.object(u, "deploy"), patch.object(u, "run", side_effect=RuntimeError("bad")):
            with self.assertRaises(RuntimeError): self.call("apply", new, ["--backup-receipt", str(receipt)])
        u.write(receipt, {"version": "1.1.0", "backup_id": "snapshot-after-failure"})
        with patch.object(u, "deploy"), patch.object(u, "run"):
            self.call("rollback", old, ["--backup-receipt", str(receipt)])
        self.assertEqual(u.read(self.home / "state.json")["current"]["version"], "1.0.0")

    def prepare_adopted(self):
        old = self.bundle()
        releases = self.home / 'releases'; releases.mkdir()
        import shutil
        shutil.copytree(old, releases / '1.0.0')
        site = u.site_config(self.home); site['context'] = 'default'
        u.write(self.home / 'runtime/site.json', site)
        u.write(self.home / 'install.json', {'backend':'compose','name':'uter-test','context':'default','images':manifest()['images']})
        u.write(self.home / 'state.json', {'current':manifest(),'previous':None,'pending':None,'adopted_installer':True})
        key = self.root / 'backup-key'; key.write_bytes(b'k'*32)
        if __import__('os').name == 'posix': key.chmod(0o600)
        return key

    def test_adopted_update_requires_actual_backup_not_receipt(self):
        key=self.prepare_adopted();new=self.bundle(manifest('1.1.0',['1.0.0']),'new')
        receipt=self.root/'receipt';u.write(receipt,{'version':'1.0.0','backup_id':'fake'})
        with patch.object(u,'deploy'):
            with self.assertRaisesRegex(ValueError,'receipts alone'):
                self.call('apply',new,['--backup-receipt',str(receipt)])
        self.assertIsNone(u.read(self.home/'state.json')['pending'])

    def test_adopted_backup_failure_never_changes_pending_state(self):
        key=self.prepare_adopted();new=self.bundle(manifest('1.1.0',['1.0.0']),'new')
        with patch.object(u,'deploy'), patch('scripts.backup_snapshot.capture',side_effect=RuntimeError('snapshot failed')):
            with self.assertRaisesRegex(RuntimeError,'snapshot failed'):
                self.call('apply',new,['--backup-dir',str(self.root/'backup'),'--backup-key',str(key)])
        state=u.read(self.home/'state.json')
        self.assertEqual(state['current']['version'],'1.0.0');self.assertIsNone(state['pending'])

    def test_adopted_update_records_backup_and_preserves_marker(self):
        key=self.prepare_adopted();new=self.bundle(manifest('1.1.0',['1.0.0']),'new')
        info={'id':'d'*32,'version':'1.0.0'}
        with patch.object(u,'deploy') as deploy, patch.object(u,'run'), patch('scripts.backup_snapshot.capture',return_value=info) as capture:
            self.call('apply',new,['--backup-dir',str(self.root/'backup'),'--backup-key',str(key)])
        state=u.read(self.home/'state.json')
        self.assertEqual(state['current']['version'],'1.1.0');self.assertTrue(state['adopted_installer'])
        self.assertEqual(state['last_backup']['id'],info['id']);self.assertTrue(capture.call_args.kwargs['leave_stopped'])
        self.assertEqual(deploy.call_count,2)

    def test_adopted_backup_cannot_use_key_inside_installation(self):
        self.prepare_adopted();new=self.bundle(manifest('1.1.0',['1.0.0']),'new')
        key=self.home/'runtime/backup.key';key.write_bytes(b'k'*32)
        with patch.object(u,'deploy'):
            with self.assertRaisesRegex(ValueError,'outside the installation'):
                self.call('apply',new,['--backup-dir',str(self.root/'backup'),'--backup-key',str(key)])

    def test_check_does_not_apply(self):
        with patch.object(u, "deploy") as deploy:
            self.call("check", self.bundle())
        self.assertTrue(deploy.call_args.kwargs["check"])
        self.assertFalse((self.home / "state.json").exists())

    def test_compose_stable_project_and_offline(self):
        runtime = self.home / "runtime"
        for name in ["guardrail.env", "agent.env", "redis.conf", "redis-password", "audit-hmac-key", "policies/runtime.toml", "profiles/model_profiles.toml"]:
            path = runtime / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("configured")
        (runtime / "models").mkdir()
        with patch.object(u, "run") as run:
            u.deploy(self.home, self.bundle(), manifest(), u.site_config(self.home), offline=True)
        commands = [c.args[0] for c in run.call_args_list]
        self.assertTrue(all("uter-test" in cmd for cmd in commands))
        self.assertFalse(any("pull" == cmd[-1] for cmd in commands))
        self.assertIn("--no-build", commands[-1])

    def test_helm_uses_locked_image_values_last(self):
        (self.home / "runtime/values.yaml").write_text("{}")
        site = u.site_config(self.home); site["backend"] = "helm"
        with patch.object(u, "run") as run:
            u.deploy(self.home, self.bundle(), manifest(), site)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[-1], str(self.home / "release-values.json"))
        self.assertIn("--wait", cmd)


if __name__ == "__main__": unittest.main()
