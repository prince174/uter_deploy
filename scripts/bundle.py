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


def build(manifest, output, key):
    m = validate(json.loads(manifest.read_text(encoding="utf-8")))
    private = load_pem_private_key(key.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("Ed25519 private key required")
    output.mkdir(parents=True, exist_ok=False)
    shutil.copy2(manifest, output / "manifest.json")
    for name in ["compose", "charts", "docs"]:
        shutil.copytree(ROOT / name, output / name)
    (output / "empty.env").write_text("# Deliberately empty; customer env files are explicit.\n")
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
