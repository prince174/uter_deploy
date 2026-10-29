"""Exercise the configured trust-bundle semantics without a network or container."""
import datetime
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def certificate(name, key, issuer, signing_key, *, ca, hostname=None, expired=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now - datetime.timedelta(days=2 if expired else 1)
    valid_until = now - datetime.timedelta(days=1) if expired else now + datetime.timedelta(days=1)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(valid_from)
               .not_valid_after(valid_until)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                              key_encipherment=False, data_encipherment=False, key_agreement=False,
                              key_cert_sign=ca, crl_sign=ca, encipher_only=None, decipher_only=None), critical=True))
    if hostname:
        builder = (builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    return builder.sign(signing_key, hashes.SHA256())


def handshake(client_context, server_context, hostname):
    """Pump SSL in memory, preserving certificate and hostname verification."""
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(client_in, client_out, server_side=False, server_hostname=hostname)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client_done = server_done = False
    for _ in range(30):
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        pending = client_out.read()
        if pending:
            server_in.write(pending)
        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
        pending = server_out.read()
        if pending:
            client_in.write(pending)
        if client_done and server_done:
            return
    raise RuntimeError('TLS handshake did not complete')


class CABundleTLSTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        root_key = ec.generate_private_key(ec.SECP256R1())
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Temporary test CA')])
        root = certificate(root_name, root_key, root_name, root_key, ca=True)
        other_key = ec.generate_private_key(ec.SECP256R1())
        other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Untrusted test CA')])
        other = certificate(other_name, other_key, other_name, other_key, ca=True)
        server_key = ec.generate_private_key(ec.SECP256R1())
        server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'llm.example')])
        leaf = certificate(server_name, server_key, root_name, root_key, ca=False, hostname='llm.example')
        expired = certificate(server_name, server_key, root_name, root_key, ca=False,
                              hostname='llm.example', expired=True)
        self.ca = self.root / 'trusted.pem'
        self.other_ca = self.root / 'untrusted.pem'
        self.ca.write_bytes(root.public_bytes(serialization.Encoding.PEM))
        self.other_ca.write_bytes(other.public_bytes(serialization.Encoding.PEM))
        certfile = self.root / 'server.pem'
        keyfile = self.root / 'server.key'
        certfile.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        keyfile.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server.load_cert_chain(certfile, keyfile)
        expiredfile = self.root / 'expired-server.pem'
        expiredfile.write_bytes(expired.public_bytes(serialization.Encoding.PEM))
        self.expired_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.expired_server.load_cert_chain(expiredfile, keyfile)

    def client(self, bundle):
        # No hashed CA entries are present in this controlled policy directory.
        with patch.dict(os.environ, {'SSL_CERT_FILE': str(bundle), 'SSL_CERT_DIR': str(self.root)}):
            return ssl.create_default_context()

    def test_custom_ca_allows_matching_hostname(self):
        handshake(self.client(self.ca), self.server, 'llm.example')

    def test_untrusted_ca_remains_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            handshake(self.client(self.other_ca), self.server, 'llm.example')

    def test_wrong_hostname_remains_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            handshake(self.client(self.ca), self.server, 'other.example')

    def test_expired_server_certificate_remains_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            handshake(self.client(self.ca), self.expired_server, 'llm.example')
