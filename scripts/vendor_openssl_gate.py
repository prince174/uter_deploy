"""Audit the independently sourced Debian OpenSSL package without hiding its provenance."""
import json
from pathlib import Path
import re
import sys

VERSION = '3.0.22-1~deb12u2'
PACKAGE_SHA256 = 'cb4784740daa9b3b0eaea2b444bbefa686794afbbf3d678d238c1fd9875f2efd'


def prepare(measurement, control, root):
    data = json.loads(Path(measurement).read_text())
    fields = dict(line.split(': ', 1) for line in Path(control).read_text().splitlines()
                  if ': ' in line and not line.startswith((' ', '\t')))
    if (data.get('package') != 'libssl3' or data.get('package_version') != VERSION
            or data.get('package_sha256') != PACKAGE_SHA256
            or not str(data.get('version', '')).startswith('OpenSSL 3.0.22 ')
            or fields.get('Package') != 'libssl3' or fields.get('Version') != VERSION
            or fields.get('Source', '').split(' ')[0] != 'openssl'
            or set(data.get('libraries', {})) != {'libssl.so.3', 'libcrypto.so.3'}
            or not all(re.fullmatch('[0-9a-f]{64}', x) for x in data['libraries'].values())):
        raise ValueError('OPENSSL_VENDOR_IDENTITY_UNVERIFIED')
    for name, version in (('actual', VERSION), ('negative', '3.0.0-1')):
        base = Path(root) / name
        (base/'etc').mkdir(parents=True)
        (base/'var/lib/dpkg').mkdir(parents=True)
        (base/'etc/os-release').write_text('ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n')
        (base/'etc/debian_version').write_text('12.0\n')
        (base/'var/lib/dpkg/status').write_text(
            'Package: libssl3\nStatus: install ok installed\nSource: openssl\n'
            'Architecture: amd64\nVersion: '+version+'\n\n')


def validate_report(data, version):
    osinfo = data.get('Metadata', {}).get('OS', {})
    if osinfo.get('Family') != 'debian' or not str(osinfo.get('Name', '')).startswith('12'):
        raise ValueError('OPENSSL_VENDOR_SCANNER_OS_UNVERIFIED')
    results = [r for r in data.get('Results', []) if r.get('Class') == 'os-pkgs']
    packages = [p for r in results for p in r.get('Packages', []) if p.get('Name') == 'libssl3']
    if len(packages) != 1:
        raise ValueError('OPENSSL_VENDOR_SCANNER_PACKAGE_UNVERIFIED')
    package = packages[0]
    actual = package.get('Version', '')
    if package.get('Release'):
        actual += '-' + package['Release']
    if actual != version or package.get('SrcName', 'openssl') != 'openssl':
        raise ValueError('OPENSSL_VENDOR_SCANNER_PACKAGE_UNVERIFIED')
    return [v for r in results for v in r.get('Vulnerabilities', []) or []
            if v.get('Severity') in ('HIGH', 'CRITICAL')]


def verify(actual, negative):
    current = validate_report(json.loads(Path(actual).read_text()), VERSION)
    control = validate_report(json.loads(Path(negative).read_text()), '3.0.0-1')
    if not control:
        raise ValueError('OPENSSL_VENDOR_SCANNER_NEGATIVE_CONTROL_FAILED')
    if current:
        raise ValueError('OPENSSL_VENDOR_HIGH_OR_CRITICAL')
    return {'package': 'libssl3', 'version': VERSION, 'high_critical': 0,
            'negative_control_high_critical': len(control), 'status': 'pass'}


if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        prepare(*sys.argv[2:])
    elif sys.argv[1] == 'verify':
        result = verify(*sys.argv[2:4])
        Path(sys.argv[4]).write_text(json.dumps(result, indent=2)+'\n')
    else:
        raise SystemExit('Invalid action')
