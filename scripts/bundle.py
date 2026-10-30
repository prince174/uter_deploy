"""Assemble and sign an immutable directory; signing keys never enter the bundle."""
import argparse
import base64
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from uterctl import ROOT, inventory, validate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def build(manifest, output, key, *, source_root=ROOT):
    m = validate(json.loads(manifest.read_text(encoding="utf-8")))
    private = load_pem_private_key(key.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("Ed25519 private key required")
    output.mkdir(parents=True, exist_ok=False)
    shutil.copy2(manifest, output / "manifest.json")
    source_root=Path(source_root)
    for name in ["compose", "charts", "docs"]:
        shutil.copytree(source_root / name, output / name)
    if m.get('tooling_schema') == 1:
        shutil.copy2(source_root/'uterctl.py',output/'uterctl.py')
        shutil.copy2(source_root/'requirements.txt',output/'requirements.txt')
        (output/'examples').mkdir()
        shutil.copy2(source_root/'examples/redis.conf.example',output/'examples/redis.conf.example')
        scripts=output/'scripts';scripts.mkdir()
        for name in ('install.py','adopt_installation.py','backup_crypto.py','backup_store.py',
                     'backup_snapshot.py','archive_safety.py','restore_backup.py','recovery_preflight.py',
                     'recovery_volume.py','recovery_aof.py','recover_compose.py','recover_kubernetes.py',
                     'recovery_kube_volumes.py','extract_signed_bundle.py','managed_smoke.py','adopt_managed.py',
                     'update_installation.py','smoke_http.py','extract_release_inputs.py','preflight.py',
                     'fetch_release.py','install_recovery.py','backup_installation.py',
                     'workload_preflight.py','render_backup_systemd.py',
                     'bootstrap_wizard.py','uter_wizard.py','install_wizard.py','update_wizard.py',
                     'redis_fence_journal.py','compose_nsfirewall_adapter.py','compose_nsfirewall_protocol.py',
                     'compose_nsfirewall_checkpoint.py','compose_fence_adapter.py','compose_fence_recovery_plan.py',
                     'compose_redis_diagnostic.py','compose_systemd_activation.py','experimental_docker_activation_ci.py',
                     'compose_snapshot_only.py','snapshot_only_receipts.py','compose_fence_start.py',
                     'compose_fence_resume.py','compose_fence_origin.py'):
            shutil.copy2(source_root/'scripts'/name,scripts/name)
        if m.get('session_identity_gate'):
            shutil.copy2(source_root/'scripts/session_migration_guard.py', scripts/'session_migration_guard.py')
            shutil.copy2(source_root/'scripts/session_provenance.py', scripts/'session_provenance.py')
    (output / "empty.env").write_text("# Deliberately empty; runtime env files are explicit.\n")
    raw = json.dumps(inventory(output), sort_keys=True, indent=2).encode()
    (output / "checksums.json").write_bytes(raw)
    (output / "checksums.sig").write_bytes(base64.b64encode(private.sign(raw)))
    print(f"Signed bundle {m['version']}: {output}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--key", type=Path, required=True)
    a = p.parse_args()
    build(a.manifest, a.output, a.key)
