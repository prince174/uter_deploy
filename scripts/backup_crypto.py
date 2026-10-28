"""Authenticated streaming encryption for backups; never print keys or plaintext."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b'UTERBK1\0'
CHUNK = 1024 * 1024


def derive_key(key, purpose):
    if len(key) != 32: raise ValueError('Backup key must contain 32 bytes')
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'uter-backup-v1:' + purpose).derive(key)


def read_key(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink(): raise ValueError('Backup key must be a regular file')
    if os.name == 'posix' and path.stat().st_mode & 0o077:
        raise ValueError('Backup key must be accessible only to its owner (0600)')
    key = path.read_bytes()
    if len(key) != 32: raise ValueError('Backup key must contain exactly 32 random bytes')
    return key


def create_key(path):
    path = Path(path)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream: stream.write(secrets.token_bytes(32))
    except BaseException:
        path.unlink(missing_ok=True); raise


def encrypt_stream(source, target, key, aad):
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(derive_key(key, b'encryption')), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(aad)
    digest = hashlib.sha256(); plaintext_digest = hashlib.sha256(); size = 0
    def put(data): target.write(data); digest.update(data)
    put(MAGIC + nonce)
    while True:
        chunk = source.read(CHUNK)
        if not chunk: break
        size += len(chunk); plaintext_digest.update(chunk); put(cipher.update(chunk))
    put(cipher.finalize()); put(cipher.tag)
    return {'sha256': digest.hexdigest(), 'plaintext_sha256': plaintext_digest.hexdigest(), 'plaintext_bytes': size}


def decrypt_verify(path, key, aad, expected, sink=None):
    path = Path(path); size = path.stat().st_size
    if size < len(MAGIC) + 12 + 16: raise ValueError('Truncated encrypted backup')
    ciphertext_digest = hashlib.sha256(); plaintext_digest = hashlib.sha256(); plaintext_size = 0
    with path.open('rb') as stream:
        header = stream.read(len(MAGIC)+12);ciphertext_digest.update(header)
        if not header.startswith(MAGIC): raise ValueError('Invalid backup header')
        stream.seek(-16, os.SEEK_END); tag = stream.read(16)
        stream.seek(len(header)); remaining = size-len(header)-len(tag)
        cipher = Cipher(algorithms.AES(derive_key(key, b'encryption')), modes.GCM(header[len(MAGIC):], tag)).decryptor()
        cipher.authenticate_additional_data(aad)
        while remaining:
            data=stream.read(min(CHUNK, remaining))
            if not data: raise ValueError('Truncated backup')
            remaining -= len(data);ciphertext_digest.update(data)
            plain=cipher.update(data);plaintext_size += len(plain);plaintext_digest.update(plain)
            if sink is not None: sink.write(plain)
        ciphertext_digest.update(tag)
        cipher.finalize()
    actual={'sha256':ciphertext_digest.hexdigest(),'plaintext_sha256':plaintext_digest.hexdigest(),'plaintext_bytes':plaintext_size}
    if actual != expected: raise ValueError('Backup content or metadata mismatch')
    return actual


def sign_manifest(manifest, key):
    data=json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    return hmac.new(derive_key(key, b'manifest'), data, hashlib.sha256).hexdigest()


def verify_manifest(manifest, signature, key):
    if not isinstance(signature, str) or not hmac.compare_digest(sign_manifest(manifest, key), signature):
        raise ValueError('Backup manifest authentication failed')


def decrypt_to_new_file(path, destination, key, aad, expected):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink(): raise ValueError('Restore destination already exists')
    fd, temporary = tempfile.mkstemp(prefix='.uter-restore-', dir=destination.parent)
    try:
        with os.fdopen(fd,'wb') as out:
            decrypt_verify(path,key,aad,expected,out)
            out.flush();os.fsync(out.fileno())
        # Refuse overwrite even if another process creates the path during verification.
        os.link(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
