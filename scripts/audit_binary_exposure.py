"""Bounded static exposure assessment; reports counts, never extracted product strings."""
import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import tarfile


def sections(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Expected ELF64 little-endian')
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, names_index = struct.unpack_from('<HHH', data, 58)
    if size != 64 or not count or names_index >= count or offset + size * count > len(data):
        raise ValueError('Invalid or unsupported ELF sections')
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size) for i in range(count)]
    names = headers[names_index]
    table = data[names[4]:names[4] + names[5]]
    return [table[h[0]:].split(b'\0', 1)[0].decode('ascii', errors='replace') for h in headers]


def source_literals(root):
    literals = set()
    if root:
        for service in ('guardrail', 'agent'):
            for p in (Path(root) / service).glob('*.py'):
                tree = ast.parse(p.read_text(encoding='utf-8-sig'))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str) and 24 <= len(node.value) <= 4096:
                        literals.add(node.value.encode())
    return literals


def audit(path, source_root=None):
    literals = source_literals(source_root)
    result = {'schema': 1, 'method': 'ELF sections and exact plaintext literal search; not full decompilation',
              'source_assisted': bool(source_root), 'tested_unique_literals': len(literals), 'modules': [],
              'limitations': 'Zero plaintext hits do not prove secrecy; runtime introspection and semantic reconstruction remain possible.'}
    with tarfile.open(path) as outer:
        manifests = json.load(outer.extractfile('manifest.json'))
        for layer in sorted({x for m in manifests for x in m['Layers']}):
            with tarfile.open(fileobj=outer.extractfile(layer), mode='r|*') as t:
                for m in t:
                    name = m.name.removeprefix('./')
                    if m.isfile() and name.startswith('app/') and name.endswith('.so'):
                        if m.size > 128 * 1024 * 1024:
                            raise ValueError('Module inspection size limit')
                        data = t.extractfile(m).read()
                        names = sections(data)
                        result['modules'].append({'name': PurePosixPath(name).name, 'sha256': hashlib.sha256(data).hexdigest(),
                            'bytes': len(data), 'debug_sections': [s for s in names if s.startswith(('.debug', '.zdebug')) or s == '.symtab'],
                            'plaintext_source_literals_found': sum(s in data for s in literals),
                            'python_init_export_present': b'PyInit_' in data,
                            'diagnostic_py_path_present': b'.py\0' in data})
    if not result['modules']:
        raise ValueError('No product ELF modules found')
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('archive'); p.add_argument('--source-root', type=Path); p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    result = audit(args.archive, args.source_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'modules': len(result['modules']), 'modules_with_debug': sum(bool(x['debug_sections']) for x in result['modules']),
                      'plaintext_literal_hits': sum(x['plaintext_source_literals_found'] for x in result['modules'])}))

    if any(x['debug_sections'] for x in result['modules']):
        raise SystemExit('Product ELF debug sections remain; see exposure report')
