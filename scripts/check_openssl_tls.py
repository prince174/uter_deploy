"""Exercise real local TLS handshakes and trust failures, without network egress."""
import json
import socket
import ssl
import sys
import threading


def handshake(cert, key, hostname, trust):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if trust:
        client.load_verify_locations(cafile=cert)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(10)
    result = []
    def serve():
        try:
            with listener.accept()[0] as peer:
                with server.wrap_socket(peer, server_side=True) as secured:
                    result.append(secured.recv(4))
        except ssl.SSLError:
            result.append(b'rejected')
        finally:
            listener.close()
    thread = threading.Thread(target=serve)
    thread.start()
    accepted = False
    try:
        with socket.create_connection(listener.getsockname(), timeout=10) as raw:
            with client.wrap_socket(raw, server_hostname=hostname) as secured:
                secured.sendall(b'test')
                accepted = True
    except ssl.SSLCertVerificationError:
        accepted = False
    finally:
        thread.join(timeout=15)
    if thread.is_alive() or len(result) != 1:
        raise RuntimeError('TLS_SERVER_UNVERIFIED')
    return accepted


def main(cert, key):
    if not handshake(cert, key, 'localhost', True):
        raise RuntimeError('TLS_VALID_CERTIFICATE_REJECTED')
    if handshake(cert, key, 'wrong-host.invalid', True):
        raise RuntimeError('TLS_WRONG_HOST_ACCEPTED')
    if handshake(cert, key, 'localhost', False):
        raise RuntimeError('TLS_UNTRUSTED_CERTIFICATE_ACCEPTED')
    print(json.dumps({'valid_tls':'pass', 'hostname_rejection':'pass',
                      'untrusted_ca_rejection':'pass', 'openssl':ssl.OPENSSL_VERSION}))


if __name__ == '__main__':
    main(*sys.argv[1:])
