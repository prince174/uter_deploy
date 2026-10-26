"""Inspect every Docker-save layer without extraction or printing file contents."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import zipfile

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
PYTHON_ROOTS = ('usr/local/lib/python3.12/', 'usr/lib/python3/', 'usr/lib/python3.12/',
                'usr/share/gcc/python/libstdcxx/', 'usr/share/gdb/auto-load/')
SOURCE_SUFFIXES = {'.py', '.pyc', '.pyo', '.pyi', '.pyx'}
ARCHIVE_SUFFIXES = ('.zip', '.whl', '.egg', '.pyz', '.tar', '.tar.gz', '.tgz')


def fingerprints(root):
    result = {}
    if root:
        for service in ('agent', 'guardrail'):
            for p in (Path(root) / service).rglob('*.py'):
                data = p.read_bytes()
                result.setdefault(len(data), set()).add(hashlib.sha256(data).hexdigest())
        if not result:
            raise ValueError('No product source fingerprints found')
    return result


def audit(path, source_root=None):
    hashes = fingerprints(source_root)
    report = {'schema': 2, 'layers': 0, 'files': 0, 'nested_archives': 0,
              'allowed_python_files': 0, 'source_fingerprints': sum(map(len, hashes.values())),
              'violations': [], 'scope': 'all layers; paths, exact source hashes, bounded archives; not full DLP'}
    failures = report['violations']

    def check(name, size, reader, location, depth=0, dependency_archive=False):
        raw = name
        while name.startswith('./'):
            name = name[2:]
        p = PurePosixPath(name)
        if p.is_absolute() or '..' in p.parts or '\\' in name:
            failures.append(f'{location}: unsafe archive path')
            return
        if p.name.startswith('.wh.'):
            return
        forbidden = ('.git' in p.parts or p.name == '.env' or p.name.startswith('.env.')
                     or p.name in {'id_rsa', 'id_ed25519', '.netrc', '.pypirc'}
                     or p.suffix in {'.pdb', '.debug'} or '.dSYM' in p.parts)
        is_source = p.suffix in SOURCE_SUFFIXES
        allowed = (name.startswith(PYTHON_ROOTS) and depth == 0) or dependency_archive
        if forbidden or (is_source and not allowed):
            failures.append(f'{location}: {raw} (forbidden file)')
        if is_source and allowed:
            report['allowed_python_files'] += 1
        nested = size >= 0 and name.lower().endswith(ARCHIVE_SUFFIXES)
        if nested and (size > MAX_ARCHIVE or depth >= 3):
            failures.append(f'{location}: {raw} (archive inspection limit)')
            return
        if size in hashes or nested:
            data = reader()
            if size in hashes and hashlib.sha256(data).hexdigest() in hashes[size]:
                failures.append(f'{location}: {raw} (exact product source copy)')
            if nested:
                report['nested_archives'] += 1
                try:
                    if zipfile.is_zipfile(io.BytesIO(data)):
                        with zipfile.ZipFile(io.BytesIO(data)) as z:
                            if sum(x.file_size for x in z.infolist()) > MAX_EXPANDED:
                                raise ValueError('expanded archive limit')
                            for x in z.infolist():
                                if not x.is_dir():
                                    check(x.filename, x.file_size, lambda x=x: z.read(x), location + ':' + raw, depth + 1,
                                          dependency_archive or (depth == 0 and name.startswith('usr/local/lib/python3.12/ensurepip/_bundled/pip-') and name.endswith('.whl')))
                    else:
                        with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as t:
                            total = 0
                            for x in t:
                                total += x.size
                                if total > MAX_EXPANDED:
                                    raise ValueError('expanded archive limit')
                                if x.isfile():
                                    check(x.name, x.size, lambda x=x: t.extractfile(x).read(), location + ':' + raw, depth + 1,
                                          dependency_archive or (depth == 0 and name.startswith('usr/local/lib/python3.12/ensurepip/_bundled/pip-') and name.endswith('.whl')))
                except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile, RuntimeError):
                    failures.append(f'{location}: {raw} (uninspectable archive)')

    with tarfile.open(path) as outer:
        manifests = json.load(outer.extractfile('manifest.json'))
        for m in manifests:
            if m.get('Config'):
                config = json.load(outer.extractfile(m['Config']))
                if b'PRIVATE KEY-----' in json.dumps(config).encode():
                    failures.append('image config/history: private key marker')
                for entry in config.get('config', {}).get('Env', []):
                    key, _, value = entry.partition('=')
                    if value and any(word in key.upper() for word in ('PASSWORD', 'TOKEN', 'SECRET', 'API_KEY')):
                        failures.append('image config: nonempty credential-like environment variable')
        for layer in sorted({x for m in manifests for x in m['Layers']}):
            report['layers'] += 1
            with tarfile.open(fileobj=outer.extractfile(layer), mode='r|*') as contents:
                for member in contents:
                    if member.isfile():
                        report['files'] += 1
                        check(member.name, member.size, lambda: contents.extractfile(member).read(), layer)
                    elif member.issym() or member.islnk():
                        check(member.name, -1, lambda: b'', layer)
    return report


def scan(path):
    return audit(path)['violations']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    result = audit(args.archive, args.source_root)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2), encoding='utf-8')
    if result['violations']:
        raise SystemExit('Forbidden image contents:\n' + '\n'.join(result['violations'][:30]) + f"\nTotal: {len(result['violations'])}; see --report for all findings")
    print(f"All {result['layers']} layers inspected; {result['files']} files; "
          f"{result['source_fingerprints']} source fingerprints; not a full secret scan")
