"""Record the independently audited OpenSSL package in a CycloneDX image SBOM."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import vendor_openssl_gate


def combine(sbom, measurement, vendor_summary):
    if (not isinstance(sbom, dict) or sbom.get('bomFormat') != 'CycloneDX'
            or not isinstance(sbom.get('components'), list)
            or vendor_summary.get('status') != 'pass'
            or vendor_summary.get('version') != vendor_openssl_gate.VERSION
            or vendor_summary.get('high_critical') != 0
            or measurement.get('package_sha256') != vendor_openssl_gate.PACKAGE_SHA256
            or measurement.get('package_version') != vendor_openssl_gate.VERSION):
        raise ValueError('OPENSSL_SBOM_EVIDENCE_UNVERIFIED')
    components = sbom['components']
    if any(c.get('name') in ('libssl3', 'libssl3t64') for c in components if isinstance(c, dict)):
        raise ValueError('OPENSSL_SBOM_EXISTING_COMPONENT_REQUIRES_REVIEW')
    components.append({'type':'library', 'name':'libssl3', 'version':vendor_openssl_gate.VERSION,
                       'purl':'pkg:deb/debian/libssl3@3.0.22-1~deb12u2?arch=amd64&distro=debian-12',
                       'hashes':[{'alg':'SHA-256', 'content':vendor_openssl_gate.PACKAGE_SHA256}],
                       'properties':[{'name':'uter:vendor-distribution','value':'debian-12-bookworm'},
                                     {'name':'uter:runtime-libssl-sha256','value':measurement['libraries']['libssl.so.3']},
                                     {'name':'uter:runtime-libcrypto-sha256','value':measurement['libraries']['libcrypto.so.3']},
                                     {'name':'uter:security-scan','value':'separate-debian-12-vendor-package-scan'}]})
    return sbom


if __name__ == '__main__':
    result=combine(*(json.loads(Path(path).read_text(encoding='utf-8')) for path in sys.argv[1:4]))
    Path(sys.argv[4]).write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
