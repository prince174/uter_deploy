"""Download and verify one public Uter deployment release into a new directory.

The publisher fingerprint must come from a separate trusted channel. This bootstrap
itself, Python and its dependencies must already be trusted by the operator. On
POSIX, the output parent must be owned by the operator and not writable by other
users. On Windows, the operator must separately verify the parent directory ACL;
this program cannot establish that ACL is private. Other users of the same account
and administrators are within the trust boundary.
"""
import argparse
from contextlib import nullcontext
import ctypes
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from urllib import parse, request

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uterctl
from scripts import extract_release_inputs, extract_signed_bundle


RELEASE_BASE = 'https://github.com/prince174/uter_deploy/releases/download/'
TRUSTED_HOSTS = frozenset({'github.com', 'release-assets.githubusercontent.com',
                           'objects.githubusercontent.com'})
TAG = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
FINGERPRINT = re.compile(r'[a-fA-F0-9]{64}\Z')
ASSETS = (
    ('publisher-public.pem', 32 * 1024),
    ('signed-bundle.tar.gz', 128 * 1024 * 1024),
    ('installation-inputs.tar.gz', 16 * 1024 * 1024),
    ('installation-inputs.tar.gz.sha256', 2048),
)
DEFAULT_DEADLINE = 600


def trusted_url(url):
    parsed = parse.urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError('Invalid HTTPS port') from None
    if (parsed.scheme != 'https' or parsed.hostname not in TRUSTED_HOSTS or
            parsed.username is not None or parsed.password is not None or
            port not in (None, 443) or parsed.fragment):
        raise ValueError('Release download URL is not trusted HTTPS')
    return url


class TrustedRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        trusted_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, destination, limit):
    """Download a bounded asset; validate HTTPS before and after redirects."""
    trusted_url(url)
    opener = request.build_opener(TrustedRedirect())
    req = request.Request(url, headers={'User-Agent': 'uter-deploy-release-fetch/1'})
    with opener.open(req, timeout=30) as source:
        trusted_url(source.geturl())
        length = source.headers.get('Content-Length')
        if length is not None:
            try:
                length = int(length)
            except ValueError:
                raise ValueError('Invalid asset length') from None
            if length < 0 or length > limit:
                raise ValueError('Release asset exceeds download limit')
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as out:
            total = 0
            while True:
                chunk = source.read(min(1024 * 1024, limit + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ValueError('Release asset exceeds download limit')
                out.write(chunk)
            if length is not None and total != length:
                raise ValueError('Release asset length mismatch')


def destination_path(output):
    output = Path(output).absolute()
    parent = output.parent.resolve(strict=True)
    info = parent.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('Output parent must be a directory')
    if os.name == 'posix' and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
        raise ValueError('Output parent must be owned by the operator and not writable by others')
    if os.name == 'posix':
        # An attacker who can rename an ancestor can replace an otherwise private
        # parent. Root and the operator are trusted; sticky shared parents such as
        # /tmp protect a child owned by the operator from other users' renames.
        for ancestor in parent.parents:
            attrs = ancestor.stat()
            if (attrs.st_uid not in (0, os.geteuid()) or
                    (attrs.st_mode & 0o022 and not attrs.st_mode & stat.S_ISVTX)):
                raise ValueError('Output has an untrusted writable ancestor')
    output = parent / output.name
    if output.exists() or output.is_symlink():
        raise ValueError('Output already exists')
    return output


def publish_no_replace(stage, output):
    """Atomically publish a marked directory without replacing any existing path."""
    if os.name == 'nt':
        # On Windows os.rename rejects an existing destination.
        os.rename(stage, output)
    elif sys.platform.startswith('linux'):
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, 'renameat2', None)
        if rename is None:
            raise RuntimeError('Atomic no-replace rename is unavailable')
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(stage), -100, os.fsencode(output), 1) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
    else:
        raise RuntimeError('Atomic no-replace rename is unsupported on this platform')


def check_regular_tree(root):
    root = Path(root)
    def unsafe_link(path):
        attrs = path.lstat()
        return stat.S_ISLNK(attrs.st_mode) or bool(getattr(attrs, 'st_file_attributes', 0) & 0x400)
    if unsafe_link(root) or not root.is_dir():
        raise ValueError('Release root must be a real directory')
    for item in root.rglob('*'):
        if unsafe_link(item) or not (item.is_dir() or item.is_file()):
            raise ValueError('Release tree contains a link or special file')


def fetch(tag, fingerprint, expected_version, output, *, _staging_root=None):
    if not TAG.fullmatch(tag):
        raise ValueError('Invalid release tag')
    if not FINGERPRINT.fullmatch(fingerprint):
        raise ValueError('Publisher fingerprint must be a SHA-256 hex digest')
    if not uterctl.VERSION.fullmatch(expected_version):
        raise ValueError('Expected version must be a valid release version')
    output = destination_path(output)
    parent = output.parent

    context = (tempfile.TemporaryDirectory(prefix='.uter-release-fetch-', dir=parent)
               if _staging_root is None else nullcontext(str(_staging_root)))
    with context as tmp:
        stage = Path(tmp) / 'release'
        stage.mkdir(mode=0o700)
        assets = stage / 'downloads'
        assets.mkdir(mode=0o700)
        for name, limit in ASSETS:
            download(RELEASE_BASE + tag + '/' + name, assets / name, limit)

        key = assets / 'publisher-public.pem'
        if hashlib.sha256(key.read_bytes()).hexdigest() != fingerprint.lower():
            raise ValueError('Publisher fingerprint mismatch')
        bundle = stage / 'bundle'
        manifest = extract_signed_bundle.extract(assets / 'signed-bundle.tar.gz', key, bundle)
        if manifest['version'] != expected_version:
            raise ValueError('Release version differs from expected version')
        archive = assets / 'installation-inputs.tar.gz'
        extract_release_inputs.extract(archive, assets / 'installation-inputs.tar.gz.sha256',
                                       stage / 'inputs', bundle=bundle, key=key)
        images = json.loads((stage / 'inputs/images.json').read_text(encoding='utf-8'))
        if images != manifest['images']:
            raise ValueError('Installation images differ from signed manifest')

        # The marker is present *before* atomic publication. Interruption before the
        # rename leaves no destination; interruption after it leaves INCOMPLETE.
        marker = stage / 'INCOMPLETE'
        marker.write_text('Release verification or publication is incomplete.\n', encoding='utf-8')
        if os.name == 'posix':
            marker.chmod(0o600)
        publish_no_replace(stage, output)
        check_regular_tree(output)
        final_key = output / 'downloads/publisher-public.pem'
        if hashlib.sha256(final_key.read_bytes()).hexdigest() != fingerprint.lower():
            raise ValueError('Published publisher fingerprint mismatch')
        final_manifest = uterctl.verify(output / 'bundle', final_key)
        if final_manifest != manifest or hashlib.sha256(
                (output / 'downloads/installation-inputs.tar.gz').read_bytes()).hexdigest() != manifest['installation_archive_sha256']:
            raise ValueError('Published release failed final verification')
        checked_inputs = Path(tmp) / 'checked-inputs'
        extract_release_inputs.extract(output / 'downloads/installation-inputs.tar.gz',
            output / 'downloads/installation-inputs.tar.gz.sha256', checked_inputs,
            bundle=output / 'bundle', key=final_key)
        expected = {item.name for item in checked_inputs.iterdir()}
        actual = {item.name for item in (output / 'inputs').iterdir()}
        if expected != actual or any((checked_inputs / name).read_bytes() !=
                                     (output / 'inputs' / name).read_bytes() for name in expected):
            raise ValueError('Published installation inputs failed final verification')
        check_regular_tree(output)
        if hashlib.sha256(final_key.read_bytes()).hexdigest() != fingerprint.lower():
            raise ValueError('Published publisher fingerprint mismatch')
        (output / 'INCOMPLETE').unlink()
    return {'version': manifest['version'], 'release': tag, 'output': str(output)}


def _worker(connection, tag, fingerprint, expected_version, output, staging_root):
    try:
        result = fetch(tag, fingerprint, expected_version, output, _staging_root=staging_root)
        connection.send(('ok', result))
    except Exception as exc:
        # Class only: messages may include signed asset URLs or other sensitive text.
        connection.send(('error', type(exc).__name__))
    finally:
        connection.close()


def supervise(target, args, deadline):
    """Hard bound for a child process, including drip-fed responses and extraction."""
    if not 0 < deadline <= 3600:
        raise ValueError('Deadline must be in (0, 3600] seconds')
    context = multiprocessing.get_context('spawn')
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=target, args=(sender, *args))
    started = False
    try:
        process.start()
        started = True
        sender.close()
        if not receiver.poll(deadline):
            raise TimeoutError('Release download deadline exceeded')
        try:
            status, value = receiver.recv()
        except EOFError:
            raise RuntimeError('Release worker stopped without a result') from None
        process.join(timeout=5)
        if process.is_alive() or process.exitcode != 0 or status != 'ok':
            raise RuntimeError('Release worker failed')
        return value
    finally:
        sender.close()
        receiver.close()
        if started and process.is_alive():
            process.terminate()
            process.join(timeout=5)
            if process.is_alive():
                process.kill()
                process.join(timeout=5)


def fetch_with_deadline(tag, fingerprint, expected_version, output, deadline=DEFAULT_DEADLINE):
    output = destination_path(output)
    # The parent owns this directory so it is removed even if a timed-out worker
    # is terminated. A published INCOMPLETE destination is deliberately preserved.
    with tempfile.TemporaryDirectory(prefix='.uter-release-fetch-', dir=output.parent) as tmp:
        return supervise(_worker, (tag, fingerprint, expected_version, output, Path(tmp)), deadline)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True, help='Public deployment release tag')
    parser.add_argument('--version', required=True, help='Expected signed product version')
    parser.add_argument('--fingerprint', required=True, help='Independently verified SHA-256 of publisher PEM')
    parser.add_argument('--output', required=True, type=Path, help='New output directory')
    parser.add_argument('--deadline', type=float, default=DEFAULT_DEADLINE,
                        help='Total download and verification deadline in seconds (default 600)')
    args = parser.parse_args()
    result = fetch_with_deadline(args.release, args.fingerprint, args.version, args.output, args.deadline)
    if os.name == 'nt':
        print('Windows: verify the output parent ACL separately; this tool does not check it.')
    print('Verified release:', result['version'])
    print('Bundle:', str(Path(result['output']) / 'bundle'))
    print('Inputs:', str(Path(result['output']) / 'inputs'))
    print('Publisher key:', str(Path(result['output']) / 'downloads/publisher-public.pem'))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Network exception text can contain signed redirect URLs or other sensitive data.
        print('Release download/verification failed:', type(exc).__name__, file=sys.stderr)
        sys.exit(1)
