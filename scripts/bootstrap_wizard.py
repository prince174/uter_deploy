#!/usr/bin/env python3
"""Prepare a private Python environment and launch the Uter assistant on Linux.

Run only from a trusted checkout. This bootstrap cannot authenticate itself,
the operating system, Python, pip or its package index.
"""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import subprocess
import sys
import venv


ROOT = Path(__file__).absolute().parent.parent


class BootstrapError(Exception):
    pass


def trusted_directory(path, *, private=False):
    path = Path(path)
    if '..' in path.parts:
        raise BootstrapError('DIRECTORY_INVALID')
    path = path.absolute()
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        sticky_root = item != path and info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
                (info.st_mode & 0o022 and not sticky_root)):
            raise BootstrapError('DIRECTORY_UNTRUSTED')
        if item == path and private and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise BootstrapError('PRIVATE_ENVIRONMENT_REQUIRED')
    return path


def trusted_file(path):
    path = Path(path).absolute()
    trusted_directory(path.parent)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022):
        raise BootstrapError('FILE_UNTRUSTED')
    return path


def trusted_tree(path, *, allow_internal_links=False):
    """Reject writable, foreign or linked code before executing it as operator."""
    path = trusted_directory(path)
    count = 0
    def walk_error(error):
        raise error
    for parent, dirs, files in os.walk(path, followlinks=False, onerror=walk_error):
        for name in dirs + files:
            count += 1
            if count > 100000:
                raise BootstrapError('TREE_TOO_LARGE')
            item = Path(parent) / name
            info = item.lstat()
            if info.st_uid not in (0, os.geteuid()):
                raise BootstrapError('TREE_UNTRUSTED')
            if stat.S_ISLNK(info.st_mode):
                if not allow_internal_links or not item.resolve(strict=True).is_relative_to(path):
                    raise BootstrapError('TREE_LINK_UNTRUSTED')
                continue
            if info.st_mode & 0o022:
                raise BootstrapError('TREE_UNTRUSTED')
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise BootstrapError('TREE_LINK_UNTRUSTED')
            elif not stat.S_ISDIR(info.st_mode):
                raise BootstrapError('TREE_UNTRUSTED')
    return path


def reject_signed_ancestor(path):
    """Never add a venv inside a signed bundle, even when launched elsewhere."""
    for ancestor in (path, *path.parents):
        if os.path.lexists(ancestor / 'checksums.sig'):
            raise BootstrapError('ENVIRONMENT_INSIDE_SIGNED_BUNDLE')


def protect_generated_activators(environment):
    """Remove unsafe write bits from venv's own freshly copied templates only.

    CPython may explicitly restore mode 0777 on activation templates regardless
    of umask. This runs only for a new private venv; never follow links, mutate
    hardlinks, or relax the checks for an existing environment.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    bin_fd = None
    try:
        bin_fd = os.open(Path(environment)/'bin', flags)
        directory = os.fstat(bin_fd)
        if directory.st_uid != os.geteuid() or directory.st_mode & 0o022:
            raise BootstrapError('GENERATED_ENVIRONMENT_UNTRUSTED')
        for name in ('activate', 'activate.csh', 'activate.fish', 'Activate.ps1'):
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=bin_fd)
            except FileNotFoundError:
                continue
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_nlink != 1):
                    raise BootstrapError('GENERATED_ENVIRONMENT_UNTRUSTED')
                os.fchmod(fd, stat.S_IMODE(info.st_mode) & ~0o022)
            finally:
                os.close(fd)
    except OSError:
        raise BootstrapError('GENERATED_ENVIRONMENT_UNTRUSTED') from None
    finally:
        if bin_fd is not None:
            os.close(bin_fd)


@contextmanager
def private_umask():
    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


def bootstrap(root, environment):
    if sys.platform != 'linux' or os.name != 'posix':
        raise BootstrapError('LINUX_REQUIRED')
    if sys.version_info < (3, 11):
        raise BootstrapError('PYTHON_3_11_REQUIRED')
    root = trusted_directory(root)
    if (root / 'checksums.sig').exists():
        raise BootstrapError('RUN_FROM_TRUSTED_CHECKOUT_NOT_SIGNED_BUNDLE')
    requirements = trusted_file(root / 'requirements.txt')
    trusted_file(root / 'uterctl.py')
    scripts = trusted_tree(root / 'scripts')
    for name in ('uter_wizard.py', 'install_wizard.py', 'update_wizard.py'):
        trusted_file(scripts / name)
    environment = Path(environment).absolute()
    trusted_directory(environment.parent)
    reject_signed_ancestor(environment)
    with private_umask():
        if not os.path.lexists(environment):
            os.mkdir(environment, 0o700)
            try:
                venv.EnvBuilder(with_pip=True, symlinks=False).create(environment)
            except Exception:
                raise BootstrapError('ENVIRONMENT_CREATION_FAILED_INSPECT_DIRECTORY') from None
            protect_generated_activators(environment)
        trusted_directory(environment, private=True)
        trusted_tree(environment, allow_internal_links=True)
        python = trusted_file(environment / 'bin/python3')
        if not python.stat().st_mode & 0o100:
            raise BootstrapError('ENVIRONMENT_PYTHON_NOT_EXECUTABLE')
        print('Preparing Python dependencies; the package index and this checkout must be trusted.',
              file=sys.stderr, flush=True)
        try:
            result = subprocess.run([str(python), '-I', '-m', 'pip', 'install', '--disable-pip-version-check',
                                     '-r', str(requirements)], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
        except (OSError, subprocess.TimeoutExpired):
            raise BootstrapError('DEPENDENCY_INSTALL_FAILED') from None
        if result.returncode:
            raise BootstrapError('DEPENDENCY_INSTALL_FAILED')
        # Package installation can add files: enforce the same protections again
        # before executing any of them. The package index itself remains trusted.
        trusted_tree(environment, allow_internal_links=True)
        trusted_file(python)
    return python, scripts / 'uter_wizard.py'


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--venv-dir', type=Path, default=ROOT / '.uter-wizard-venv',
                        help='Private environment owned by the executing user')
    # Once an action is selected, all remaining options belong to the assistant.
    action_at = next((i for i, item in enumerate(argv) if item in ('install', 'update')), len(argv))
    args = parser.parse_args(argv[:action_at])
    rest = argv[action_at:]
    if rest and any(item in ('-h', '--help') for item in rest[1:]):
        print('Uter ' + rest[0] + ': start without --help for guided prompts.')
        print('For all automation options run scripts/' + rest[0] + '_wizard.py --help')
        print('with the prepared Python environment; see README.md. No packages were installed.')
        return 0
    try:
        python, wizard = bootstrap(ROOT, args.venv_dir)
        return subprocess.call([str(python), '-I', '-B', str(wizard), *rest])
    except (BootstrapError, OSError) as exc:
        code = str(exc) if isinstance(exc, BootstrapError) else 'PATH_OR_PERMISSIONS_INVALID'
        print('Bootstrap stopped: ' + code, file=sys.stderr)
        print('Check trusted paths, Python venv/pip and package-index access; do not share credentials.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
