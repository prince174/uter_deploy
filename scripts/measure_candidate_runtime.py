"""Measure SQLite and OpenSSL actually loaded in a candidate image."""
import hashlib
import json
from pathlib import Path
import sqlite3
import ssl


def paths_matching(name):
    paths = {line.split()[-1] for line in Path('/proc/self/maps').read_text().splitlines() if name in line}
    if len(paths) != 1:
        raise ValueError('RUNTIME_LIBRARY_IDENTITY_UNVERIFIED')
    return Path(paths.pop())


db = sqlite3.connect(':memory:')
db.execute('create virtual table docs using fts5(content)')
db.execute('insert into docs values (?)', ('security update',))
if db.execute('select count(*) from docs where docs match ?', ('security',)).fetchone()[0] != 1:
    raise ValueError('RUNTIME_SQLITE_FTS_UNVERIFIED')
sqlite_path = paths_matching('libsqlite3.so')
libraries = {}
for name in ('libssl.so.3', 'libcrypto.so.3'):
    path = paths_matching(name)
    if not str(path).startswith('/usr/local/lib/'):
        raise ValueError('RUNTIME_OPENSSL_LOCATION_UNVERIFIED')
    libraries[name] = hashlib.sha256(path.read_bytes()).hexdigest()
expected = json.loads(Path('/usr/local/share/uter-openssl-package/library-hashes.json').read_text())
if libraries != expected:
    raise ValueError('RUNTIME_OPENSSL_HASH_UNVERIFIED')
print(json.dumps({'sqlite': {'sqlite_version':sqlite3.sqlite_version,
                             'library_sha256':hashlib.sha256(sqlite_path.read_bytes()).hexdigest(),
                             'fts5':'pass'},
                  'openssl': {'version':ssl.OPENSSL_VERSION, 'libraries':libraries}}))
