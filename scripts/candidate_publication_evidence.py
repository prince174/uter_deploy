"""Recheck raw scanner, SQLite and vendor evidence before any registry write."""
import json
from pathlib import Path
import tempfile

from scripts import security_gate, sqlite_vex_gate, vendor_openssl_gate


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def verify(folder, service, image_id, runtime=None):
    evidence = Path(folder)/'evidence'
    raw = read(evidence/'trivy-vuln-report.json')
    gate = read(evidence/'security-summary.json')
    if (raw.get('Metadata', {}).get('ImageID') != image_id
            or security_gate.summary(raw) != gate or gate.get('secrets') != 0):
        raise ValueError('PUBLICATION_RAW_EVIDENCE_UNVERIFIED')
    if service == 'redis':
        if gate.get('critical_high') != 0:
            raise ValueError('PUBLICATION_REDIS_SECURITY_UNVERIFIED')
        return {'security':gate}
    if service not in ('agent', 'guardrail') or runtime is None:
        raise ValueError('PUBLICATION_RUNTIME_UNVERIFIED')
    sqlite = read(evidence/'sqlite-measurement.json')
    openssl = read(evidence/'openssl-measurement.json')
    if (runtime.get('sqlite') != sqlite
            or runtime.get('openssl') != {'version':openssl.get('version'), 'libraries':openssl.get('libraries')}):
        raise ValueError('PUBLICATION_RUNTIME_MEASUREMENT_MISMATCH')
    _, vex = sqlite_vex_gate.assess_evidence(raw, image_id, sqlite)
    if read(evidence/'sqlite-vex-summary.json') != vex or gate.get('critical_high') != 3:
        raise ValueError('PUBLICATION_SQLITE_VEX_UNVERIFIED')
    with tempfile.TemporaryDirectory(prefix='uter-openssl-evidence-') as temporary:
        vendor_openssl_gate.prepare(evidence/'openssl-measurement.json', evidence/'openssl-control.txt',
                                    Path(temporary)/'inventory')
    vendor = vendor_openssl_gate.verify(evidence/'vendor-openssl-report.json',
                                        evidence/'vendor-openssl-control-report.json')
    if read(evidence/'vendor-openssl-summary.json') != vendor:
        raise ValueError('PUBLICATION_OPENSSL_SCAN_UNVERIFIED')
    tls = read(evidence/'openssl-tls-check.json')
    if (tls.get('valid_tls') != 'pass' or tls.get('hostname_rejection') != 'pass'
            or tls.get('untrusted_ca_rejection') != 'pass' or tls.get('openssl') != openssl['version']):
        raise ValueError('PUBLICATION_TLS_UNVERIFIED')
    return {'security':gate, 'sqlite_vex':vex, 'vendor_openssl':vendor, 'openssl_measurement':openssl}
