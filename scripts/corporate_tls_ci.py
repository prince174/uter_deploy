"""Test candidate CA deployment against published images on disposable CI only.

The HTTPS upstream is a deterministic protocol fixture, not a real LLM. This
does not test corporate proxies, mTLS, a real corporate CA, or production CNI.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from urllib import error, request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import uterctl
from scripts.extract_release_inputs import extract as extract_inputs
from scripts.smoke_http import check as smoke


PUBLISHER_FINGERPRINT = '65be6fd9613fa7e879735fe5b453bfcb8c0e38911cd7429c9aac9c9afba676a2'
NODE_IMAGE = 'kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0'
UTER_PORT = 18083


class StageError(Exception):
    pass


def ci_only():
    if (os.name != 'posix' or os.geteuid() != 0 or
            os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or
            not re.fullmatch(r'[0-9]+', os.environ.get('GITHUB_RUN_ID', '')) or
            os.environ.get('DOCKER_HOST')):
        raise StageError('DISPOSABLE_GITHUB_HOSTED_RUNNER_REQUIRED')


def call(argv, stage, *, env=None, input_data=None, timeout=360):
    try:
        result = subprocess.run([str(value) for value in argv], input=input_data,
                                env=env, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise StageError(stage) from None
    if result.returncode:
        raise StageError(stage)
    return result.stdout


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def create_certificates(directory, gateway):
    """Create an ephemeral trusted CA, a distinct untrusted CA, and TLS leaves."""
    address = ipaddress.ip_address(gateway)
    if address.version != 4 or not address.is_private:
        raise ValueError('A private IPv4 gateway is required')
    now = datetime.now(timezone.utc)
    def ca(common_name):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
            .sign(key, hashes.SHA256()))
        return key, certificate
    trusted_key, trusted_ca = ca('Uter CI trusted CA')
    other_key, other_ca = ca('Uter CI untrusted CA')
    trust_path = directory / 'trusted-ca.pem'
    write_private(trust_path, trusted_ca.public_bytes(serialization.Encoding.PEM))
    result = {'ca': trust_path}
    for variant, signing_key, issuer, san in (
            ('trusted', trusted_key, trusted_ca, x509.IPAddress(address)),
            ('untrusted', other_key, other_ca, x509.IPAddress(address)),
            ('hostname', trusted_key, trusted_ca, x509.DNSName('wrong.invalid'))):
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Uter CI fixture')]))
            .issuer_name(issuer.subject).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(signing_key, hashes.SHA256()))
        cert_path, key_path = directory / (variant + '.pem'), directory / (variant + '.key')
        write_private(cert_path, leaf.public_bytes(serialization.Encoding.PEM))
        write_private(key_path, leaf_key.private_bytes(serialization.Encoding.PEM,
                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        result[variant] = (cert_path, key_path)
    return result


def gateway_address(backend, cluster, env):
    if backend == 'compose':
        info = json.loads(call(['docker', 'network', 'inspect', 'bridge'], 'BRIDGE_INSPECT_FAILED', env=env))
        value = info[0]['IPAM']['Config'][0]['Gateway']
    else:
        info = json.loads(call(['docker', 'inspect', cluster + '-control-plane'], 'KIND_INSPECT_FAILED', env=env))
        value = info[0]['NetworkSettings']['Networks']['kind']['Gateway']
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_private:
        raise StageError('PRIVATE_GATEWAY_REQUIRED')
    return str(address)


def free_port(address):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((address, 0))
        return listener.getsockname()[1]


def verify_published_inputs(work, destination):
    key = work / 'download/publisher-public.pem'
    if hashlib.sha256(key.read_bytes()).hexdigest() != PUBLISHER_FINGERPRINT:
        raise StageError('PUBLISHER_FINGERPRINT_MISMATCH')
    bundle = work / 'signed'
    manifest = uterctl.verify(bundle, key)
    archive = work / 'download/installation-inputs.tar.gz'
    extract_inputs(archive, work / 'download/installation-inputs.tar.gz.sha256',
                   destination, bundle=bundle, key=key)
    if json.loads((destination / 'images.json').read_text(encoding='utf-8')) != manifest['images']:
        raise StageError('SIGNED_IMAGE_MISMATCH')
    return manifest


def wait_fixture(base, ca, key, process):
    context = ssl.create_default_context(cafile=str(ca))
    opener = request.build_opener(request.ProxyHandler({}), request.HTTPSHandler(context=context))
    for _ in range(60):
        if process.poll() is not None:
            raise StageError('FIXTURE_EXITED')
        try:
            req = request.Request(base + '/health', headers={'Authorization': 'Bearer ' + key})
            with opener.open(req, timeout=3) as response:
                if response.status == 200:
                    return
        except error.HTTPError as exc:
            exc.close()
            time.sleep(1)
        except (error.URLError, TimeoutError, OSError):
            time.sleep(1)
    raise StageError('FIXTURE_NOT_READY')


def wait_uter(expected):
    opener = request.build_opener(request.ProxyHandler({}))
    for _ in range(90):
        try:
            with opener.open('http://127.0.0.1:' + str(UTER_PORT) + '/ready', timeout=5) as response:
                record = json.load(response)
                if expected and response.status == 200 and record.get('ready') is True and record.get('upstream') is True:
                    return
        except error.HTTPError as exc:
            try:
                record = json.load(exc)
            except (ValueError, OSError):
                record = {}
            finally:
                exc.close()
            if not expected and exc.code == 503 and record.get('ready') is False and record.get('upstream') is False:
                return
        except (error.URLError, TimeoutError, OSError, ValueError):
            pass
        time.sleep(2)
    raise StageError('UTER_READY_EXPECTATION_FAILED' if expected else 'UTER_DID_NOT_FAIL_CLOSED')


def tls_probe(backend, name, cluster, address, port, env):
    # The CA path is read from the actual Guardrail environment. No credentials
    # or raw TLS exception text are printed by this in-container probe.
    source = '''import os,socket,ssl\naddress={address!r};port={port!r}\ntry:\n context=ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])\n with socket.create_connection((address,port),timeout=8) as raw:\n  with context.wrap_socket(raw,server_hostname=address): pass\n print("TRUSTED")\nexcept ssl.SSLCertVerificationError as exc:\n print("HOSTNAME" if exc.verify_code in (62,64) else "UNTRUSTED" if exc.verify_code in (18,19,20,21) else "OTHER_CERTIFICATE")\nexcept Exception:\n print("PROBE_FAILED")\n'''.format(address=address, port=port).encode()
    if backend == 'compose':
        argv = ['docker', 'exec', '-i', name + '-guardrail-1', 'python', '-']
    else:
        argv = ['kubectl', '--context', 'kind-' + cluster, '-n', name, 'exec', '-i',
                'deployment/' + name + '-guardrail', '--', 'python', '-']
    return call(argv, 'GUARDRAIL_TLS_PROBE_FAILED', env=env, input_data=source, timeout=30).decode().strip()


def terminate(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def cleanup(argv, env):
    try:
        result = subprocess.run(argv, env=env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=120)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def main():
    ci_only()
    backend = os.environ.get('BACKEND')
    if backend not in ('compose', 'kubernetes'):
        raise StageError('BACKEND_INVALID')
    work = Path(os.environ['TEST_WORKSPACE']).resolve(strict=True)
    python = work / 'venv/bin/python'
    suffix = secrets.token_hex(6)
    name = 'uter-tls-' + suffix
    cluster = name + '-kind'
    fixture = forward = None
    cluster_attempted = install_attempted = False
    # The probe requires root-owned private ancestors; GitHub's workspace is
    # owned by the runner account, while /tmp protects private children via sticky bit.
    with tempfile.TemporaryDirectory(prefix='uter-corporate-tls-', dir='/tmp') as temp:
        temp = Path(temp)
        inputs = temp / 'inputs'
        manifest = verify_published_inputs(work, inputs)
        home = temp / 'home'
        probe_dir = temp / 'workload-preflight'
        docker_config = temp / 'docker-config'
        docker_config.mkdir(mode=0o700)
        env = os.environ.copy()
        for key in list(env):
            if key.startswith('COMPOSE_') or key in ('DOCKER_HOST', 'DOCKER_CONTEXT') or key.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'):
                del env[key]
        env['DOCKER_CONFIG'] = str(docker_config)
        env['KUBECONFIG'] = str(temp / 'kubeconfig')
        compose = ['docker', '--context', 'default', 'compose', '--project-name', name,
                   '--env-file', str(home / 'empty.env'), '-f', str(home / 'compose/compose.yaml')]
        try:
            if backend == 'kubernetes':
                existing = call(['kind', 'get', 'clusters'], 'KIND_DISCOVERY_FAILED', env=env).decode().splitlines()
                if cluster in existing:
                    raise StageError('CLUSTER_NAME_ALREADY_EXISTS')
                cluster_attempted = True
                call(['kind', 'create', 'cluster', '--name', cluster, '--image', NODE_IMAGE,
                      '--kubeconfig', env['KUBECONFIG'], '--wait', '180s'], 'KIND_CREATE_FAILED', env=env)
            gateway = gateway_address(backend, cluster, env)
            port = free_port(gateway)
            certs = create_certificates(temp, gateway)
            fixture_token = 'sk-' + secrets.token_hex(32)
            token_file = temp / 'fixture-token'
            write_private(token_file, fixture_token.encode())
            base = 'https://' + gateway + ':' + str(port)

            def start_fixture(variant):
                cert, key = certs[variant]
                return subprocess.Popen([str(python), str(ROOT/'tests/fixtures/corporate_tls_upstream.py'),
                    '--host', gateway, '--port', str(port), '--certificate', str(cert), '--key', str(key),
                    '--token-file', str(token_file)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            fixture = start_fixture('trusted')
            wait_fixture(base, certs['ca'], fixture_token, fixture)
            print('Stage: deterministic HTTPS fixture ready (not a real LLM)', flush=True)
            if backend == 'compose':
                # Probe a disposable network using the exact signed Guardrail image.
                # This is urllib inside that image, not the application or its future network.
                call(['docker', '--context', 'default', 'pull', manifest['images']['guardrail']],
                     'PREFLIGHT_IMAGE_PULL_FAILED', env=env)
                probe_dir.mkdir(mode=0o700)
                probe = call([python, ROOT/'scripts/workload_preflight.py', 'probe',
                              '--bundle', work/'signed', '--publisher-key', work/'download/publisher-public.pem',
                              '--fingerprint', PUBLISHER_FINGERPRINT, '--state-dir', probe_dir,
                              '--llm-url', base+'/v1', '--llm-model', 'fixture-model',
                              '--llm-key-file', token_file, '--llm-ca-bundle', certs['ca']],
                             'WORKLOAD_PREFLIGHT_FAILED', env=env)
                try:
                    probe_result = json.loads(probe)
                except (ValueError, UnicodeError):
                    raise StageError('WORKLOAD_PREFLIGHT_OUTPUT_INVALID') from None
                if (probe_result.get('result') != 'pass' or
                        probe_result.get('actual_uter_application') != 'not_checked' or
                        probe_result.get('actual_compose_network') != 'not_checked' or
                        any(probe_dir.iterdir())):
                    raise StageError('WORKLOAD_PREFLIGHT_RESULT_INVALID')
                print('Stage: disposable image network probe passed and cleaned up', flush=True)
            installer = ROOT / 'scripts/install.py'
            prepare = [python, installer, 'prepare', '--home', home, '--backend', backend, '--name', name,
                       '--inputs', inputs, '--llm-url', base + '/v1', '--llm-model', 'fixture-model',
                       '--llm-key-file', token_file, '--llm-ca-bundle', certs['ca'],
                       '--port', str(UTER_PORT), '--guardrail-cpus', '2']
            if backend == 'kubernetes':
                prepare += ['--context', 'kind-' + cluster]
            call(prepare, 'PREPARE_FAILED', env=env)
            cfg = json.loads((home / 'install.json').read_text())
            env.update({key.upper() + '_IMAGE': value for key, value in cfg['images'].items()})
            env.update(RUNTIME_DIR=str(home / 'runtime'), GUARDRAIL_PORT=str(UTER_PORT), GUARDRAIL_CPUS='2')
            call([python, installer, 'check', '--home', home], 'CHECK_FAILED', env=env)
            install_attempted = True
            call([python, installer, 'install', '--home', home], 'INSTALL_FAILED', env=env)
            if backend == 'kubernetes':
                forward = subprocess.Popen(['kubectl', '--context', 'kind-' + cluster, '-n', name,
                    'port-forward', 'service/' + name + '-guardrail', str(UTER_PORT) + ':8000',
                    '--address', '127.0.0.1'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_uter(True)
            if tls_probe(backend, name, cluster, gateway, port, env) != 'TRUSTED':
                raise StageError('TRUSTED_TLS_PROBE_FAILED')
            credentials = json.loads((home / 'credentials.json').read_text())
            smoke('http://127.0.0.1:' + str(UTER_PORT), 'admin', credentials['admin'])
            print('Stage: trusted CA, Uter readiness and fixture chat passed', flush=True)

            for variant, expected in (('untrusted', 'UNTRUSTED'), ('hostname', 'HOSTNAME')):
                terminate(fixture)
                fixture = start_fixture(variant)
                # Probe the actual Guardrail certificate store and distinguish name
                # mismatch from untrusted CA before asserting readiness fails closed.
                for attempt in range(30):
                    observed = tls_probe(backend, name, cluster, gateway, port, env)
                    if observed != 'PROBE_FAILED':
                        break
                    if fixture.poll() is not None:
                        raise StageError('FIXTURE_EXITED')
                    time.sleep(1)
                if observed != expected:
                    raise StageError('EXPECTED_TLS_FAILURE_NOT_OBSERVED')
                wait_uter(False)
                print('Stage: ' + variant + ' certificate rejected; readiness failed closed', flush=True)
                terminate(fixture)
                fixture = start_fixture('trusted')
                wait_fixture(base, certs['ca'], fixture_token, fixture)
                wait_uter(True)
            smoke('http://127.0.0.1:' + str(UTER_PORT), 'admin', credentials['admin'])
            print(json.dumps({'backend': backend, 'trusted_ca': 'pass', 'untrusted_ca': 'pass',
                              'hostname_mismatch': 'pass', 'tls_readiness_recovery': 'pass',
                              'fixture': 'deterministic HTTPS; not a real LLM'}))
        finally:
            cleanup_failed = False
            try:
                terminate(forward)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_failed = True
            if probe_dir.exists():
                for operation in probe_dir.iterdir():
                    if not operation.is_dir() or operation.is_symlink():
                        cleanup_failed = True
                    else:
                        cleanup_failed |= not cleanup([str(python), str(ROOT/'scripts/workload_preflight.py'),
                                                       'cleanup', '--operation-dir', str(operation)], env)
            if install_attempted and backend == 'compose':
                cleanup_failed |= not cleanup(compose + ['down', '--volumes', '--remove-orphans'], env)
            if cluster_attempted:
                cleanup_failed |= not cleanup(['kind', 'delete', 'cluster', '--name', cluster,
                                               '--kubeconfig', env['KUBECONFIG']], env)
            try:
                terminate(fixture)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_failed = True
            if cleanup_failed:
                raise StageError('CI_CLEANUP_FAILED')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        category = str(exc) if isinstance(exc, StageError) else 'CORPORATE_TLS_VALIDATION_FAILED'
        print('Isolated TLS test failed: ' + category + '; raw details withheld', file=sys.stderr)
        sys.exit(1)
