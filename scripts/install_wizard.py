#!/usr/bin/env python3
"""Download a signed release and perform a first installation on Linux.

This tool assumes its own checkout, Python and dependencies are trusted. The
publisher fingerprint must be obtained independently. It never updates an
existing installation and never removes resources when installation fails.
"""
import argparse
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError
import warnings

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import uterctl
from scripts import extract_release_inputs, fetch_release, preflight, workload_preflight

DEFAULT_TAG = 'deploy-2026.10.29-signed-4'
DEFAULT_VERSION = '0.1.6'
FINGERPRINT = re.compile(r'[0-9a-fA-F]{64}\Z')
NAME = re.compile(r'[a-z][a-z0-9-]{0,38}[a-z0-9]\Z')


class WizardError(Exception):
    """An allowlisted code safe to report without user data or credentials."""


def ask(label, default=None):
    suffix = f' [{default}]' if default is not None else ''
    value = input(label + suffix + ': ').strip()
    return value or default or ''


def default_workspace():
    """Create one private directory only beneath a verified private home."""
    user_home = workload_preflight.secure_directory(Path.home())
    root = user_home/'.uter-install-wizard'
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    return workload_preflight.secure_directory(root)


def trusted_home_parent(path):
    """Allow protected 0755 parents such as /srv, never writable or symlinked ones."""
    path = Path(path)
    if '..' in path.parts:
        raise WizardError('INSTALLATION_PARENT_UNTRUSTED')
    path = path.absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = None
    try:
        descriptor = os.open('/', flags)
        root = os.fstat(descriptor)
        if root.st_uid != 0 or root.st_mode & 0o022:
            raise WizardError('INSTALLATION_PARENT_UNTRUSTED')
        paths = path.parts[1:]
        for index, part in enumerate(paths):
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            final = index == len(paths)-1
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
                    (info.st_mode & 0o022 and (final or not sticky_root))):
                raise WizardError('INSTALLATION_PARENT_UNTRUSTED')
        return path
    except OSError:
        raise WizardError('INSTALLATION_PARENT_UNTRUSTED') from None
    finally:
        if descriptor is not None: os.close(descriptor)


def collect(args):
    """Use explicit CLI values first; never prompt for or print credential bytes."""
    if not args.non_interactive and not sys.stdin.isatty():
        raise WizardError('INTERACTIVE_TERMINAL_REQUIRED')
    def choose(field, label, default=None):
        value = getattr(args, field)
        if value is None and not args.non_interactive:
            value = ask(label, default)
        setattr(args, field, value if value is not None else default)
    choose('release', 'Тег опубликованного релиза', DEFAULT_TAG)
    choose('version', 'Ожидаемая версия подписанного релиза', DEFAULT_VERSION)
    choose('fingerprint', 'SHA-256 публичного ключа издателя из независимого доверенного источника')
    choose('backend', 'Способ развёртывания: compose или kubernetes', 'compose')
    choose('name', 'Имя установки и проекта', 'uter-instance')
    workspace = None
    if not args.non_interactive and (args.home is None or args.release_dir is None):
        try:
            workspace = default_workspace()
        except (OSError, workload_preflight.ProbeError):
            print('Не удалось подготовить приватный каталог по умолчанию; укажите доверенные пути.', flush=True)
    release_default = str(workspace/('release-'+args.version)) if workspace else None
    home_default = str(workspace/args.name) if workspace else None
    choose('release_dir', 'Приватный каталог релиза (новый, если не указан --reuse-release)', release_default)
    choose('home', 'Новый каталог установки', home_default)
    if args.backend == 'kubernetes':
        choose('context', 'Точный context Kubernetes')
    if not args.non_interactive:
        try:
            args.port = int(ask('Свободный локальный порт Uter для проверки', str(args.port)))
        except ValueError:
            raise WizardError('PORT_OR_CPU_INVALID') from None
    choose('llm_url', 'Базовый URL LiteLLM, совместимый с OpenAI API')
    choose('llm_model', 'Имя модели в LiteLLM')
    if not args.non_interactive and args.llm_max_tokens is None:
        token_value = ask('Параметр max_tokens для запросов к LLM (1–65536, не общий предел); Enter — не задавать')
        if token_value:
            if not token_value.isascii() or not token_value.isdecimal():
                raise WizardError('LLM_MAX_TOKENS_INVALID')
            try:
                args.llm_max_tokens = int(token_value)
            except ValueError:
                raise WizardError('LLM_MAX_TOKENS_INVALID') from None
    args._interactive_key = None
    if not args.non_interactive and args.llm_key_file is None:
        method = ask('Ключ LLM: файл (file), скрытый ввод (enter) или нет ключа (none)', 'file').casefold()
        if method in ('file', 'файл'):
            args.llm_key_file = ask('Путь к защищённому файлу ключа LLM (может быть пустым)')
        elif method in ('enter', 'ввести'):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter('error', getpass.GetPassWarning)
                    args._interactive_key = getpass.getpass('Ключ API LLM (скрытый ввод): ')
            except getpass.GetPassWarning:
                raise WizardError('HIDDEN_INPUT_UNAVAILABLE_USE_KEY_FILE') from None
            if not args._interactive_key:
                raise WizardError('EMPTY_KEY_REQUIRES_EXPLICIT_NONE')
        elif method in ('none', 'нет'):
            args._interactive_key = ''
        else:
            raise WizardError('LLM_KEY_MODE_INVALID')
    if not args.non_interactive:
        if args.llm_ca_bundle is None:
            args.llm_ca_bundle = ask('Путь к полному набору сертификатов CA; Enter — стандартный набор') or None
        if args.health_url is None:
            args.health_url = ask('URL проверки LLM на том же сервере; Enter — /health') or None
        if not args.allow_http_llm and str(args.llm_url).startswith('http://'):
            args.allow_http_llm = ask('HTTP не шифруется. Разрешить для доверенной тестовой сети? Введите да').casefold() in ('да', 'yes')
        if not args.skip_llm_preflight:
            args.skip_llm_preflight = ask('Пропустить проверку LLM с хоста, если она доступна только из кластера? Введите да').casefold() in ('да', 'yes')
    return args


def validate(args):
    if os.name != 'posix' or sys.platform != 'linux':
        raise WizardError('LINUX_REQUIRED')
    required = (args.release, args.version, args.fingerprint, args.release_dir, args.home,
                args.name, args.llm_url, args.llm_model)
    if not all(required):
        raise WizardError('MISSING_REQUIRED_INPUT')
    if not args.llm_key_file and getattr(args, '_interactive_key', None) is None:
        raise WizardError('MISSING_REQUIRED_INPUT')
    if args.backend not in ('compose', 'kubernetes') or (args.backend == 'kubernetes' and not args.context):
        raise WizardError('BACKEND_OR_CONTEXT_INVALID')
    if args.context and (args.context.startswith('-') or any(ord(c) < 32 or ord(c) == 127 for c in args.context)):
        raise WizardError('BACKEND_OR_CONTEXT_INVALID')
    if not fetch_release.TAG.fullmatch(args.release) or not uterctl.VERSION.fullmatch(args.version):
        raise WizardError('RELEASE_OR_VERSION_INVALID')
    if not NAME.fullmatch(args.name) or not FINGERPRINT.fullmatch(args.fingerprint):
        raise WizardError('NAME_OR_FINGERPRINT_INVALID')
    if not 1024 <= args.port <= 65535 or not 1 <= args.guardrail_cpus <= 64:
        raise WizardError('PORT_OR_CPU_INVALID')
    if args.llm_max_tokens is not None and (type(args.llm_max_tokens) is not int or not 1 <= args.llm_max_tokens <= 65536):
        raise WizardError('LLM_MAX_TOKENS_INVALID')
    if args.offline and args.backend != 'compose':
        raise WizardError('OFFLINE_COMPOSE_ONLY')
    try:
        preflight.check_url(args.llm_url, args.allow_http_llm)
        if args.health_url and not preflight.same_origin(preflight.check_url(args.llm_url, args.allow_http_llm),
                                                         preflight.check_url(args.health_url, args.allow_http_llm)):
            raise WizardError('HEALTH_ORIGIN_MISMATCH')
        if args.llm_ca_bundle:
            workload_preflight.read_trusted_ca(Path(args.llm_ca_bundle))
        # Validate owner, ancestors, mode, type and bounded content before downloads.
        if args.llm_key_file:
            workload_preflight.read_trusted_key(Path(args.llm_key_file))
        else:
            value = args._interactive_key
            if len(value.encode('utf-8')) > preflight.MAX_KEY or any(not 32 <= ord(c) <= 126 for c in value):
                raise WizardError('LLM_KEY_INVALID')
        release = Path(args.release_dir).absolute()
        home = Path(args.home).absolute()
        if '..' in Path(args.release_dir).parts or '..' in Path(args.home).parts:
            raise WizardError('PATH_INVALID')
        trusted_home_parent(home.parent)
        if args.reuse_release:
            release = workload_preflight.secure_directory(release)
        else:
            release = fetch_release.destination_path(release)
        if home.exists() or home.is_symlink():
            raise WizardError('INSTALLATION_EXISTS')
        if home == release or home.is_relative_to(release) or release.is_relative_to(home):
            raise WizardError('INSTALLATION_AND_RELEASE_MUST_BE_SEPARATE')
    except (OSError, ValueError, preflight.CheckFailure, workload_preflight.ProbeError):
        raise WizardError('INPUT_OR_PATH_INVALID') from None
    return release, home


def verify_release(release, fingerprint, expected_version):
    """Authenticate the selected bundle and publisher independently on each use."""
    try:
        if (release / 'INCOMPLETE').exists():
            raise ValueError('incomplete')
        protected_release_tree(release)
        fetch_release.check_regular_tree(release)
        key = release / 'downloads/publisher-public.pem'
        public_key = workload_preflight.read_trusted_file(key, 32768, secret=False, error='KEY_INVALID')
        if hashlib.sha256(public_key).hexdigest() != fingerprint.lower():
            raise ValueError('fingerprint')
        bundle = release / 'bundle'
        manifest = uterctl.verify(bundle, key)
        if manifest['version'] != expected_version or not manifest.get('installation_archive_sha256'):
            raise ValueError('version or archive')
        return bundle, key, manifest
    except Exception:
        raise WizardError('RELEASE_VERIFICATION_FAILED') from None


def protected_release_tree(release):
    """Prevent other users from replacing a checked installer or signed input."""
    root = workload_preflight.secure_directory(release)
    seen, total = 0, 0
    def reject_walk(error):
        raise error
    for current, directories, files in os.walk(root, followlinks=False, onerror=reject_walk):
        for path in (Path(current), *(Path(current)/name for name in directories+files)):
            info = path.lstat()
            seen += 1
            if (seen > 10000 or info.st_uid not in (0, os.geteuid()) or
                    info.st_mode & 0o022 or
                    not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) or
                    (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
                raise WizardError('RELEASE_TREE_UNTRUSTED')
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
                if info.st_size > 128*1024*1024 or total > 256*1024*1024:
                    raise WizardError('RELEASE_TREE_UNTRUSTED')


def authenticated_inputs(release, bundle, key, manifest, destination):
    try:
        extract_release_inputs.extract(release / 'downloads/installation-inputs.tar.gz',
                                       release / 'downloads/installation-inputs.tar.gz.sha256',
                                       destination, bundle=bundle, key=key)
        if json.loads((destination/'images.json').read_text(encoding='utf-8')) != manifest['images']:
            raise ValueError('images')
    except Exception:
        raise WizardError('SIGNED_INPUTS_INVALID') from None


def port_is_free(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', port))
        return True
    except OSError:
        return False


def run_install(bundle, stage, home, args, inputs=None, key_file=None):
    script = bundle / 'scripts/install.py'
    # Isolate signed installer imports from caller PYTHONPATH/PYTHONHOME and
    # prevent bytecode writes inside the immutable signed bundle.
    command = [sys.executable, '-I', '-B', str(script), stage, '--home', str(home)]
    if stage == 'prepare':
        command += ['--backend', args.backend, '--name', args.name, '--inputs', str(inputs),
                    '--llm-url', args.llm_url, '--llm-model', args.llm_model,
                    '--llm-key-file', str(key_file), '--port', str(args.port),
                    '--guardrail-cpus', str(args.guardrail_cpus)]
        if args.context: command += ['--context', args.context]
        if args.llm_max_tokens is not None: command += ['--llm-max-tokens', str(args.llm_max_tokens)]
        if args.allow_http_llm: command += ['--allow-http-llm']
        if args.llm_ca_bundle: command += ['--llm-ca-bundle', str(args.llm_ca_bundle)]
        if args.storage_class: command += ['--storage-class', args.storage_class]
    if stage == 'install' and args.offline: command += ['--offline']
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=900, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise WizardError(stage.upper() + '_FAILED_OR_TIMED_OUT') from None
    if result.returncode:
        raise WizardError(stage.upper() + '_FAILED')


def start_forward(context, name, port):
    """Only accept readiness printed by our own kubectl, never an occupied port."""
    command = ['kubectl', '--context', context, '-n', name, 'port-forward',
               '--address', '127.0.0.1', 'svc/'+name+'-guardrail', f'{port}:8000']
    try:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, bufsize=0)
    except OSError:
        raise WizardError('KUBERNETES_FORWARD_FAILED') from None
    expected = f'Forwarding from 127.0.0.1:{port} -> 8000'.encode()
    deadline = time.monotonic() + 45
    data = b''
    try:
        while time.monotonic() < deadline and proc.poll() is None and len(data) < 8192:
            available, _, _ = select.select([proc.stdout], [], [], min(1, max(0, deadline-time.monotonic())))
            if available:
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk: break
                data += chunk
                if expected in data and proc.poll() is None:
                    return proc
        raise WizardError('KUBERNETES_FORWARD_FAILED')
    except BaseException:
        stop_forward(proc)
        raise


def stop_forward(proc):
    if proc is None: return
    try:
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=5)
    finally:
        if proc.stdout: proc.stdout.close()


def smoke(bundle, home, port):
    """Run authenticated acceptance without putting passwords in arguments or logs."""
    def diagnostic(stage, category):
        stages = {'READY', 'AUTH', 'HEALTH', 'CHAT'}
        categories = {'TIMEOUT', 'NETWORK_FAILED', 'INVALID_RESPONSE', 'NOT_READY',
                      'BLOCKED_OR_INVALID', 'FAILED', 'HTTP_OTHER'} | {
            'HTTP_' + str(code) for code in (400, 401, 403, 404, 408, 409, 422, 429, 500, 502, 503, 504)}
        if stage in stages and category in categories:
            print('ACCEPTANCE_DIAGNOSTIC=' + stage + '_' + category, file=sys.stderr, flush=True)

    try:
        raw = workload_preflight.read_trusted_file(home/'credentials.json', 65536,
                                                   secret=True, error='CREDENTIALS_INVALID')
        credentials = json.loads(raw)
        password = credentials['admin']
        if not isinstance(password, str) or not password: raise ValueError('admin')
        module_spec = importlib.util.spec_from_file_location('_uter_signed_smoke', bundle/'scripts/smoke_http.py')
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        # Loopback credentials must never be forwarded through an ambient proxy.
        # ProxyHandler({}) is installed only for this call and restored afterwards.
        import urllib.request
        original = urllib.request._opener
        urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                                  preflight.NoRedirect()))
        try:
            result = module.check(f'http://127.0.0.1:{port}', 'admin', password, diagnostic=diagnostic)
        finally:
            urllib.request._opener = original
        if not isinstance(result, dict) or result.get('chat') != 'pass':
            raise ValueError('smoke')
    except HTTPError as error:
        error.close()
        raise WizardError('ACCEPTANCE_FAILED') from None
    except Exception:
        raise WizardError('ACCEPTANCE_FAILED') from None


def mark_acceptance(home):
    """Record success only after authenticated smoke; never alter a pending install."""
    try:
        workload_preflight.secure_directory(home)
        state_path = home/'install-state.json'
        raw = workload_preflight.read_trusted_file(state_path, 65536, secret=True, error='STATE_INVALID')
        state = json.loads(raw)
        if state != {'status': 'ready', 'acceptance': 'not-run'}:
            raise ValueError('Unexpected state')
        fd, temporary = tempfile.mkstemp(prefix='.acceptance-', dir=home)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump({'status': 'ready', 'acceptance': 'passed'}, stream)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, state_path)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
    except (OSError, ValueError, TypeError, workload_preflight.ProbeError):
        raise WizardError('ACCEPTANCE_STATE_WRITE_FAILED') from None


def accept_with_operation_lock(bundle, home, port):
    """Serialize acceptance with managed adoption/update/backup, not arbitrary admins."""
    try:
        workload_preflight.secure_directory(home)
        with uterctl.locked(home):
            # An adoption or update that completed after install but before this
            # lock makes the earlier install identity unsuitable for acceptance.
            if os.path.lexists(home/'state.json'):
                raise WizardError('INSTALLATION_STATE_CHANGED')
            raw = workload_preflight.read_trusted_file(home/'install-state.json', 65536,
                                                       secret=True, error='STATE_INVALID')
            if json.loads(raw) != {'status': 'ready', 'acceptance': 'not-run'}:
                raise WizardError('INSTALLATION_STATE_CHANGED')
            smoke(bundle, home, port)
            if os.path.lexists(home/'state.json'):
                raise WizardError('INSTALLATION_STATE_CHANGED')
            mark_acceptance(home)
    except FileExistsError:
        raise WizardError('INSTALLATION_OPERATION_LOCKED') from None
    except (OSError, ValueError, TypeError, RecursionError, workload_preflight.ProbeError):
        raise WizardError('ACCEPTANCE_LOCK_OR_STATE_FAILED') from None


def execute(args):
    release, home = validate(args)
    if not port_is_free(args.port):
        raise WizardError('LOCAL_PORT_UNAVAILABLE')
    if args.reuse_release:
        print('Этап: проверка ранее загруженного подписанного релиза', flush=True)
    else:
        print('Этап: загрузка и проверка подписанного релиза', flush=True)
        try:
            fetch_release.fetch_with_deadline(args.release, args.fingerprint, args.version, release)
        except Exception:
            raise WizardError('RELEASE_DOWNLOAD_OR_VERIFICATION_FAILED') from None
    bundle, key, manifest = verify_release(release, args.fingerprint, args.version)
    with tempfile.TemporaryDirectory(prefix='.uter-install-wizard-', dir=release.parent) as tmp:
        stage = Path(tmp)
        authenticated_inputs(release, bundle, key, manifest, stage/'inputs')
        # Use a private bounded snapshot; credentials never appear in argv or logs.
        try:
            if args.llm_key_file:
                secret = workload_preflight.read_trusted_key(Path(args.llm_key_file)).encode()
            else:
                secret = args._interactive_key.encode()
                args._interactive_key = None
            fd = os.open(stage/'llm-key', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream: stream.write(secret)
        except (OSError, workload_preflight.ProbeError):
            raise WizardError('LLM_KEY_UNAVAILABLE') from None
        del secret
        if args.skip_llm_preflight:
            print('Проверка LLM с хоста пропущена; доступ проверится после установки.', flush=True)
            print('Этап: проверка инструментов хоста; registry, CNI, CSI и RBAC не проверяются.', flush=True)
            checks = preflight.runtime_checks(args.backend, args.context)
            for check in checks:
                print('  '+str(check.get('name', 'check'))+': '+str(check.get('status', 'unknown'))+
                      ' ('+str(check.get('code', 'UNKNOWN'))+')', flush=True)
            if any(check.get('status') == 'fail' for check in checks):
                raise WizardError('HOST_PREFLIGHT_FAILED')
        else:
            print('Этап: проверка хоста; сеть контейнеров/Pod, registry, CNI, CSI и RBAC не проверяются.', flush=True)
            params = argparse.Namespace(backend=args.backend, context=args.context, llm_url=args.llm_url,
                llm_model=args.llm_model, llm_key_file=stage/'llm-key', health_url=args.health_url,
                ca_file=Path(args.llm_ca_bundle) if args.llm_ca_bundle else None,
                allow_http_llm=args.allow_http_llm, use_env_proxy=args.use_env_proxy, workdir=home.parent, timeout=30)
            try: report = preflight.preflight(params)
            except preflight.CheckFailure: raise WizardError('HOST_PREFLIGHT_FAILED') from None
            for check in report['checks']:
                print('  '+str(check.get('name', 'check'))+': '+str(check.get('status', 'unknown'))+
                      ' ('+str(check.get('code', 'UNKNOWN'))+')', flush=True)
            if report['result'] == 'fail': raise WizardError('HOST_PREFLIGHT_FAILED')
        for name in ('prepare', 'check', 'install'):
            verify_release(release, args.fingerprint, args.version)
            print('Этап: '+{'prepare':'подготовка','check':'проверка конфигурации','install':'установка'}[name], flush=True)
            run_install(bundle, name, home, args, stage/'inputs', stage/'llm-key')
        verify_release(release, args.fingerprint, args.version)
        print('Этап: авторизованная проверка работающего сервиса', flush=True)
        forward = None
        try:
            if args.backend == 'kubernetes':
                forward = start_forward(args.context, args.name, args.port)
            accept_with_operation_lock(bundle, home, args.port)
        finally:
            stop_forward(forward)
    print('Установка и авторизованная проверка сервиса прошли успешно.', flush=True)
    print('Сохраните приватный каталог установки и учётные данные; внешний доступ настройте отдельно.', flush=True)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--non-interactive', action='store_true', help='Require explicit values; never prompt')
    for flag in ('release', 'version', 'fingerprint', 'release-dir', 'backend', 'home', 'name',
                 'context', 'llm-url', 'llm-model', 'llm-key-file', 'llm-ca-bundle', 'health-url', 'storage-class'):
        p.add_argument('--'+flag)
    p.add_argument('--port', type=int, default=18000)
    p.add_argument('--llm-max-tokens', type=int, help='Optional upstream generation token setting, 1..65536')
    p.add_argument('--guardrail-cpus', type=float, default=4)
    p.add_argument('--allow-http-llm', action='store_true')
    p.add_argument('--skip-llm-preflight', action='store_true')
    p.add_argument('--use-env-proxy', action='store_true', help='Use environment proxy for host LLM preflight')
    p.add_argument('--reuse-release', action='store_true', help='Verify and use an existing private release without downloading')
    p.add_argument('--offline', action='store_true', help='Compose only: do not pull images; use --reuse-release to avoid release downloads')
    args = collect(p.parse_args(argv))
    return execute(args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (WizardError, KeyboardInterrupt, EOFError) as exc:
        code = str(exc) if isinstance(exc, WizardError) else 'INTERRUPTED'
        print('Мастер установки остановлен: '+code+'. Сохраните каталог установки для диагностики.', file=sys.stderr)
        sys.exit(1)
