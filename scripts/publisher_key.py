"""Create an Ed25519 publisher key in an existing private POSIX directory."""
import argparse
import hashlib
import os
from pathlib import Path
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def create(private_path, public_path):
    if os.name != 'posix':
        raise ValueError('Generate publisher keys on a POSIX system with private permissions')
    private_path, public_path = Path(private_path), Path(public_path)
    parent = private_path.parent.resolve(strict=True)
    repository = Path(__file__).resolve().parents[1]
    if parent == repository or parent.is_relative_to(repository):
        raise ValueError('Private signing key must be outside the deployment repository')
    if private_path.is_symlink() or public_path.is_symlink() or private_path.exists() or public_path.exists():
        raise ValueError('Key paths must be new files')
    if parent.stat().st_uid != os.geteuid() or stat.S_IMODE(parent.stat().st_mode) & 0o077:
        raise ValueError('Private key directory must be owned by the current user and inaccessible to group/others')
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        with public_path.open('xb') as f:
            f.write(public); f.flush(); os.fsync(f.fileno())
    except BaseException:
        private_path.unlink(missing_ok=True)
        raise
    return hashlib.sha256(public).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--private', type=Path, required=True)
    p.add_argument('--public', type=Path, required=True)
    a = p.parse_args()
    print('Publisher public key SHA256:', create(a.private, a.public))
    print('Keep the private key offline and make a secure backup. Verify the public fingerprint independently.')


if __name__ == '__main__':
    main()
