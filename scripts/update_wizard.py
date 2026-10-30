#!/usr/bin/env python3
"""Guide a signed, backed-up Uter update without printing credentials.

Run only from a trusted, protected checkout or verified signed bundle. The
publisher fingerprint must be obtained through an independent trusted channel.
No installation data or workloads change before confirmation. Selecting --release
downloads a verified release into a new directory, including with --check-only.
--offline applies to image pulls during Compose update, not to release downloads,
the LLM or other external dependencies.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import backup_installation as security, backup_store, fetch_release

FINGERPRINT = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[a-z][a-z0-9-]{0,38}[a-z0-9]\Z')
MESSAGES = {
    'LINUX_REQUIRED': 'Обновление поддерживается на Linux.',
    'PUBLISHER_FINGERPRINT_INVALID': 'Введите SHA-256 публичного ключа: 64 шестнадцатеричных символа.',
    'PUBLISHER_FINGERPRINT_MISMATCH': 'Отпечаток публичного ключа не совпадает с независимо полученным.',
    'BUNDLE_NOT_PROTECTED': 'Каталог подписанного комплекта доступен для записи посторонним или имеет недоверенного владельца.',
    'BUNDLE_TOO_LARGE': 'Размер подписанного комплекта превышает допустимый предел.',
    'DIRECTORY_PARENT_NOT_PROTECTED': 'Родитель каталога резервирования должен существовать и быть защищён от записи посторонними.',
    'INSTALLATION_NOT_READY': 'Установка не завершена: сначала разберите состояние install-state.',
    'INSTALLATION_IDENTITY_INVALID': 'Параметры установки или context некорректны.',
    'OFFLINE_REQUIRES_COMPOSE': 'Режим offline доступен только для Compose.',
    'RECOVERY_INCOMPLETE': 'Восстановление не завершено; сначала проверьте его журнал.',
    'BACKUP_REQUIRES_INSPECTION': 'Предыдущее резервирование не завершено; сначала проверьте его журнал.',
    'CURRENT_SIGNED_BUNDLE_REQUIRED': 'Для первого обновления нужен подписанный комплект текущей версии.',
    'CURRENT_BUNDLE_STATE_MISMATCH': 'Комплект текущей версии не совпадает с управляемым состоянием установки.',
    'INSTALLED_BUNDLE_STATE_MISMATCH': 'Сохранённый комплект установки не совпадает с её состоянием.',
    'CURRENT_BUNDLE_IMAGES_MISMATCH': 'Образы установки не совпадают с текущим подписанным комплектом.',
    'RELEASE_VERSION_UNCHANGED': 'Текущая и новая версия совпадают.',
    'SIGNED_UPDATER_MISSING': 'В целевом подписанном комплекте отсутствует программа обновления.',
    'BACKUP_PATHS_NOT_SEPARATE': 'Разместите установку, копии и ключ в отдельных каталогах.',
    'BACKUP_KEY_INVALID': 'Существующий ключ копии некорректен; он не будет заменён.',
    'PLAN_CHANGED': 'План изменился после проверки. Запустите мастер заново и повторно проверьте его.',
    'PUBLISHER_CHANGED': 'Публичный ключ изменился после проверки.',
    'SIGNED_BUNDLE_CHANGED': 'Подписанный комплект изменился после проверки.',
    'BACKUP_KEY_STATE_CHANGED': 'Состояние файла ключа изменилось; обновление остановлено.',
    'SIGNED_UPDATE_FAILED_INSPECT_STATE': 'Обновление не завершилось. Проверьте состояние и журналы; автоматический откат не выполнялся.',
    'SESSION_MIGRATION_AMBIGUOUS': 'Обновление остановлено: найдены сессии, владельца которых нельзя надёжно определить.',
    'SESSION_MIGRATION_SCAN_FAILED': 'Обновление остановлено: не удалось безопасно проверить старые сессии.',
    'SESSION_MIGRATION_FENCE_UNVERIFIED': 'Обновление остановлено: нельзя подтвердить отсутствие внешних записей в хранилище сессий.',
    'REDIS_FENCE_REQUIRES_INSPECTION': 'Обновление остановлено: необходимо проверить незавершённую операцию изоляции Redis.',
    'UPDATER_TIMEOUT_INSPECT_STATE': 'Прервано ожидание обновления. Проверьте состояние и журналы перед любыми действиями; операции Docker/Kubernetes могут продолжаться.',
    'UPDATER_OUTPUT_LIMIT_INSPECT_STATE': 'Обновление завершилось, но его вывод превысил предел. Проверьте состояние и журналы; не запускайте обновление повторно без проверки.',
    'UPDATER_OUTPUT_UNAVAILABLE_INSPECT_STATE': 'Не удалось безопасно получить результат обновления. Проверьте состояние и журналы.',
    'INTERRUPTED_INSPECT_STATE': 'Операция прервана. Если обновление уже началось, проверьте состояние и журналы перед повтором.',
    'INPUT_OR_VERIFICATION_FAILED': 'Не удалось проверить пути, подпись или совместимость. Проверьте состояние установки.',
    'RELEASE_FETCH_OR_VERIFICATION_FAILED': 'Не удалось получить или проверить выпуск. Проверьте сеть, тег, версию и доверенный отпечаток.',
    'UPDATE_RESULT_INVALID_INSPECT_STATE': 'Не удалось подтвердить результат обновления. Проверьте состояние и журналы.',
    'REQUIRED_ARGUMENT_MISSING': 'Укажите обязательные параметры или запустите интерактивный мастер.',
    'JSON_REQUIRES_CONFIRM_OR_CHECK_ONLY': 'Для JSON-режима укажите --confirm или --check-only.',
    'TARGET_SELECTION_REQUIRED': 'Выберите локальный комплект или тег выпуска.',
    'EXPECTED_VERSION_REQUIRED': 'Для загрузки укажите ожидаемую версию.',
    'EXPECTED_VERSION_MISMATCH': 'Подписанная версия не совпадает с указанной.',
    'DOWNLOAD_DIRECTORY_REQUIRES_RELEASE': '--download-to используется только с --release.',
    'PUBLISHER_KEY_REQUIRED': 'Укажите публичный ключ издателя.',
}


class WizardError(Exception):
    """Fixed categories avoid exposing external outputs or credentials."""


class SessionMigrationBlocked(WizardError):
    """A protected marker describes a block and separately verified backup status."""

    def __init__(self, reason, old_version, new_version, backup, backup_id, backup_verified=False):
        super().__init__(reason)
        self.old_version = old_version
        self.new_version = new_version
        self.backup = backup
        self.backup_id = backup_id
        self.backup_verified = backup_verified


def fresh_session_block(plan, *, absent_before):
    """Accept only a newly-created, protected marker for this signed transition.

    The marker is a local report. Backup verification is performed separately.
    Never include arbitrary error text, key values, or record contents in output.
    """
    expected_gate = {'schema': 1, 'from_epoch': 1, 'to_epoch': 2,
                     'policy': 'block_unverified_sessions'}
    if (not absent_before or plan['new'].get('session_identity_gate') != expected_gate
            or plan['old'].get('data_epoch') != 1 or plan['new'].get('data_epoch') != 2):
        return None
    marker = plan['home'] / 'session-migration-block.json'
    try:
        report = security.safe_json(marker, private=True)
        if set(report) != {'schema', 'reason', 'old_version', 'new_version', 'backup_id', 'backup_path'}:
            return None
        reason = report['reason']
        if (type(report['schema']) is not int or report['schema'] != 1
                or reason not in ('SESSION_MIGRATION_AMBIGUOUS', 'SESSION_MIGRATION_SCAN_FAILED',
                                  'SESSION_MIGRATION_FENCE_UNVERIFIED')
                or report['old_version'] != plan['old']['version']
                or report['new_version'] != plan['new']['version']
                or not isinstance(report['backup_id'], str)
                or not re.fullmatch(r'[0-9a-f]{32}', report['backup_id'])
                or not isinstance(report['backup_path'], str)
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in report['backup_path'])):
            return None
        backup = Path(report['backup_path'])
        root = security.private_directory(plan['backup_root'])
        if not backup.is_absolute() or backup.parent != root or backup == root:
            return None
        backup = security.private_directory(backup)
        # Historical controller state is often 0644 inside an owner-only home;
        # it is not a secret, but must still be owner-controlled and immutable
        # to other users. The marker and backup manifest remain private.
        state = security.safe_json(plan['home'] / 'state.json')
        if (state.get('adopted_installer') is not True or state.get('pending') is not None
                or state.get('current') != plan['old']
                or security.present(plan['home'] / 'backup-operation.json')):
            return None
        # Check only basic identity here. Cryptographic backup verification and
        # a trial restore are separate steps and are never claimed by the UI.
        envelope = security.safe_json(backup / 'manifest.json', private=True)
        manifest = envelope.get('manifest')
        if (not isinstance(manifest, dict) or manifest.get('id') != report['backup_id']
                or manifest.get('version') != plan['old']['version']):
            return None
        verified = False
        try:
            key = security.safe_file(plan['backup_key'], private=True, limit=32)
            if len(key) != 32:
                raise ValueError
            _, site, current = security.installation_metadata(plan['home'])
            if current != plan['old']:
                raise ValueError
            authenticated = backup_store.verify_set(backup, key, home=plan['home'], site=site,
                                                    version=plan['old']['version'])
            verified = authenticated['id'] == report['backup_id']
        except Exception:
            # Never claim success if key, identity, MAC or any component failed.
            verified = False
        return SessionMigrationBlocked(reason, report['old_version'], report['new_version'],
                                       str(backup), report['backup_id'], verified)
    except Exception:
        return None


def secure_bundle(path):
    """Forbid links and writes by third parties throughout a release tree."""
    path = security.checked_existing_path(path)
    security.verify_tree(path)
    total = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        for item in [Path(root), *(Path(root) / name for name in dirs + files)]:
            info = item.lstat()
            if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                raise WizardError('BUNDLE_NOT_PROTECTED')
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
                if info.st_size > 128 * 1024 * 1024 or total > 256 * 1024 * 1024:
                    raise WizardError('BUNDLE_TOO_LARGE')
                if item == path / 'checksums.json' and info.st_size > 4 * 1024 * 1024:
                    raise WizardError('BUNDLE_TOO_LARGE')
    return path


def checked_parent(path):
    parent = security.checked_existing_path(Path(path).absolute().parent)
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o022):
        raise WizardError('DIRECTORY_PARENT_NOT_PROTECTED')
    return parent


def private_dir_or_new(path):
    path = Path(path).absolute()
    checked_parent(path)
    if security.present(path):
        return security.private_directory(path), False
    return path, True


def verify_publisher(path, fingerprint):
    if not FINGERPRINT.fullmatch(fingerprint):
        raise WizardError('PUBLISHER_FINGERPRINT_INVALID')
    key = security.checked_existing_path(path)
    if hashlib.sha256(security.safe_file(key, limit=32768)).hexdigest() != fingerprint:
        raise WizardError('PUBLISHER_FINGERPRINT_MISMATCH')
    return key


def prepare_plan(home, bundle, publisher_key, fingerprint, *, current_bundle=None,
                 backup_root=None, backup_key=None, offline=False):
    if os.name != 'posix' or not sys.platform.startswith('linux'):
        raise WizardError('LINUX_REQUIRED')
    home = security.private_directory(home)
    key = verify_publisher(publisher_key, fingerprint)
    bundle = secure_bundle(bundle)
    new = uterctl.verify(bundle, key)
    config = security.safe_json(home / 'install.json')
    initial = security.safe_json(home / 'install-state.json')
    if initial.get('status') != 'ready':
        raise WizardError('INSTALLATION_NOT_READY')
    backend, name, context = (config.get(item) for item in ('backend', 'name', 'context'))
    if (backend not in ('compose', 'kubernetes') or not isinstance(name, str)
            or not NAME.fullmatch(name) or not isinstance(context, str) or not context
            or context.startswith('-') or any(ord(ch) < 32 or ord(ch) == 127 for ch in context)
            or (backend == 'compose' and context != 'default')):
        raise WizardError('INSTALLATION_IDENTITY_INVALID')
    if offline and backend != 'compose':
        raise WizardError('OFFLINE_REQUIRES_COMPOSE')
    recovery = home / 'recovery-operation.json'
    if security.present(recovery) and security.safe_json(recovery).get('phase') != 'complete':
        raise WizardError('RECOVERY_INCOMPLETE')
    if security.present(home / 'backup-operation.json'):
        raise WizardError('BACKUP_REQUIRES_INSPECTION')
    if security.present(home / 'redis-fence-operation.json'):
        raise WizardError('REDIS_FENCE_REQUIRES_INSPECTION')
    state_file = home / 'state.json'
    adopted = security.present(state_file)
    if adopted:
        _, site, state_old = security.installation_metadata(home)
        security.expected_identity(config, site, backend, name, context)
        if current_bundle is None:
            current_bundle = home / 'releases' / state_old['version']
    elif current_bundle is None:
        raise WizardError('CURRENT_SIGNED_BUNDLE_REQUIRED')
    current_bundle = secure_bundle(current_bundle)
    old = uterctl.verify(current_bundle, key)
    if adopted:
        if old != state_old:
            raise WizardError('CURRENT_BUNDLE_STATE_MISMATCH')
        # The existing managed controller independently uses this exact path.
        installed = secure_bundle(home / 'releases' / old['version'])
        if uterctl.verify(installed, key) != old:
            raise WizardError('INSTALLED_BUNDLE_STATE_MISMATCH')
    elif config.get('images') != old['images']:
        raise WizardError('CURRENT_BUNDLE_IMAGES_MISMATCH')
    if old['version'] == new['version']:
        raise WizardError('RELEASE_VERSION_UNCHANGED')
    uterctl.transition(old, new)
    tool = bundle / 'scripts' / 'update_installation.py'
    if not tool.is_file() or tool.is_symlink():
        raise WizardError('SIGNED_UPDATER_MISSING')
    backup_root = Path(backup_root or home.parent / (home.name + '-backups')).absolute()
    backup_key = Path(backup_key or home.parent / (home.name + '-backup-key') / 'backup.key').absolute()
    backups, make_backups = private_dir_or_new(backup_root)
    keydir, make_keydir = private_dir_or_new(backup_key.parent)
    backup_key = keydir / backup_key.name
    if (not backup_key.name or backup_key.name in ('.', '..') or backups == home
            or backups.is_relative_to(home) or home.is_relative_to(backups)
            or backup_key.is_relative_to(home) or backup_key.is_relative_to(backups)
            or keydir == home or keydir.is_relative_to(home)
            or keydir == backups or keydir.is_relative_to(backups)):
        raise WizardError('BACKUP_PATHS_NOT_SEPARATE')
    exists = security.present(backup_key) if not make_keydir else False
    key_digest = None
    if exists:
        key_bytes = security.safe_file(backup_key, private=True, limit=32)
        if len(key_bytes) != 32:
            raise WizardError('BACKUP_KEY_INVALID')
        # Compared in memory only; never expose the key or its fingerprint.
        key_digest = hashlib.sha256(key_bytes).digest()
    return {'home': home, 'bundle': bundle, 'publisher_key': key, 'fingerprint': fingerprint,
            'current_bundle': current_bundle, 'backup_root': backups, 'backup_key': backup_key,
            'make_backups': make_backups, 'make_keydir': make_keydir, 'create_key': not exists,
            'key_digest': key_digest,
            'backend': backend, 'name': name, 'context': context, 'offline': offline,
            'adopted': adopted, 'old': old, 'new': new, 'tool': tool}


def ensure_new_private_dir(path, create):
    if create:
        # Refuse replacement, including a directory created after confirmation.
        os.mkdir(path, 0o700)
    security.private_directory(path)


def interrupt_updater_group(process):
    """Forward interruption to the dedicated process group, allowing cleanup."""
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        pass
    # No forced kill: writers/backup need an opportunity to unwind. A further
    # interruption may leave daemon-side work running; the operator must inspect.
    process.wait()


def run_updater(argv, *, timeout=None, max_output=8 * 1024 * 1024):
    """Drain both streams, retain bounded stdout, and discard stderr in memory.

    There is no automatic timeout by default. Truncation does not interrupt the
    updater: after it finishes the result is reported as inconclusive. A manual
    interrupt is forwarded to its process group without SIGKILL; daemon-side
    operations may continue, so callers must inspect the installation and journals.
    An explicit timeout requests a graceful interrupt after that duration, then
    waits for process cleanup without imposing a further timeout.
    """
    if (timeout is not None and timeout <= 0) or max_output <= 0:
        raise ValueError('Invalid updater limits')
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
    except OSError:
        raise WizardError('UPDATER_OUTPUT_UNAVAILABLE_INSPECT_STATE') from None
    output = bytearray()
    truncated = False
    deadline = time.monotonic() + timeout if timeout is not None else None
    finished = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                remaining = deadline - time.monotonic() if deadline is not None else None
                if remaining is not None and remaining <= 0:
                    raise WizardError('UPDATER_TIMEOUT_INSPECT_STATE')
                for event, _ in selector.select(min(remaining, 1) if remaining is not None else 1):
                    chunk = os.read(event.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(event.fileobj)
                        event.fileobj.close()
                        continue
                    if event.data == 'stdout':
                        room = max_output - len(output)
                        output.extend(chunk[:max(room, 0)])
                        if len(chunk) > room:
                            truncated = True
                    # Discard stderr immediately; it may contain credentials.
        remaining = deadline - time.monotonic() if deadline is not None else None
        if remaining is not None and remaining <= 0:
            raise WizardError('UPDATER_TIMEOUT_INSPECT_STATE')
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise WizardError('UPDATER_TIMEOUT_INSPECT_STATE') from None
        finished = True
        if returncode:
            raise WizardError('SIGNED_UPDATE_FAILED_INSPECT_STATE')
        if truncated:
            raise WizardError('UPDATER_OUTPUT_LIMIT_INSPECT_STATE')
        try:
            decoded = output.decode('utf-8')
        except UnicodeError:
            raise WizardError('UPDATER_OUTPUT_UNAVAILABLE_INSPECT_STATE') from None
        return decoded
    finally:
        if not finished:
            interrupt_updater_group(process)
        for pipe in (process.stdout, process.stderr):
            if pipe is not None and not pipe.closed:
                pipe.close()


def execute(plan):
    """Revalidate protected signed content immediately before invoking its updater."""
    refreshed = prepare_plan(plan['home'], plan['bundle'], plan['publisher_key'], plan['fingerprint'],
                             current_bundle=plan['current_bundle'], backup_root=plan['backup_root'],
                             backup_key=plan['backup_key'], offline=plan['offline'])
    if refreshed != plan:
        raise WizardError('PLAN_CHANGED')
    # Recheck the two signatures after the user has reviewed the plan.
    if verify_publisher(plan['publisher_key'], plan['fingerprint']) != plan['publisher_key']:
        raise WizardError('PUBLISHER_CHANGED')
    for folder, manifest in ((plan['current_bundle'], plan['old']), (plan['bundle'], plan['new'])):
        if uterctl.verify(secure_bundle(folder), plan['publisher_key']) != manifest:
            raise WizardError('SIGNED_BUNDLE_CHANGED')
    ensure_new_private_dir(plan['backup_root'], plan['make_backups'])
    ensure_new_private_dir(plan['backup_key'].parent, plan['make_keydir'])
    if security.present(plan['backup_key']) == plan['create_key']:
        raise WizardError('BACKUP_KEY_STATE_CHANGED')
    argv = [sys.executable, '-I', '-B', str(plan['tool']), '--home', str(plan['home']),
            '--bundle', str(plan['bundle']), '--publisher-key', str(plan['publisher_key']),
            '--backup-root', str(plan['backup_root']), '--backup-key', str(plan['backup_key'])]
    if not plan['adopted']:
        argv += ['--current-bundle', str(plan['current_bundle'])]
    if plan['create_key']:
        argv.append('--create-backup-key')
    if plan['offline']:
        argv.append('--offline')
    marker_absent = not security.present(plan['home'] / 'session-migration-block.json')
    try:
        output = run_updater(argv)
    except WizardError as error:
        # Timeouts and interruptions are inconclusive: a live updater may still
        # be changing state, so never interpret any marker for those outcomes.
        if str(error) == 'SIGNED_UPDATE_FAILED_INSPECT_STATE':
            blocked = fresh_session_block(plan, absent_before=marker_absent)
            if blocked is not None:
                raise blocked from None
        raise
    try:
        if len(output) > 8 * 1024 * 1024 or output.count('{') > 4096:
            raise ValueError
        decoder = json.JSONDecoder()
        matches = []
        for index, char in enumerate(output):
            if char != '{':
                continue
            try:
                candidate, _ = decoder.raw_decode(output, index)
            except ValueError:
                continue
            if isinstance(candidate, dict) and set(candidate) == {'version', 'backup', 'backup_id', 'backup_key'}:
                matches.append(candidate)
        if len(matches) != 1:
            raise ValueError
        result = matches[0]
        if (result['version'] != plan['new']['version']
                or not isinstance(result['backup_id'], str)
                or not re.fullmatch(r'[0-9a-f]{32}', result['backup_id'])
                or not isinstance(result['backup'], str)
                or result['backup_key'] != str(plan['backup_key'])
                or not Path(result['backup']).resolve().is_relative_to(plan['backup_root'].resolve())):
            raise ValueError
    except (ValueError, TypeError, RecursionError):
        raise WizardError('UPDATE_RESULT_INVALID_INSPECT_STATE') from None
    return result


def display_plan(plan):
    print('Установка: ' + plan['name'] + ' (' + plan['backend'] + ', context: ' + plan['context'] + ')')
    print('Переход: ' + plan['old']['version'] + ' → ' + plan['new']['version'])
    print('Каталог копий: ' + str(plan['backup_root']))
    print('Файл ключа копии: ' + str(plan['backup_key']) + (' (будет создан)' if plan['create_key'] else ' (существующий)'))
    print('Компоненты будут временно остановлены. Внешние записи в Redis и аудит остановите заранее.')
    if plan['new'].get('session_identity_gate'):
        print('Проверка истории сессий выполняется во время обновления, после резервного копирования; проверка плана её не проводит.')
        print('При неоднозначной истории, ошибке проверки или неподтверждённой остановке внешних записей обновление будет заблокировано.')
    if plan['offline']:
        print('Offline запрещает скачивание образов при обновлении; LLM и другие зависимости могут использовать сеть.')
    print('Копию и её ключ необходимо сохранить отдельно. Восстановление и переключение трафика выполняются отдельно.')


def check_only_result(plan):
    result = {'result': 'checked', 'old_version': plan['old']['version'],
              'new_version': plan['new']['version']}
    if plan['new'].get('session_identity_gate'):
        result.update(session_runtime_check='not_run', external_writer_fence='not_verified')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Обновление Uter из подписанного комплекта с резервным копированием.')
    parser.add_argument('--home', type=Path, help='Каталог существующей установки')
    target = parser.add_mutually_exclusive_group()
    target.add_argument('--bundle', type=Path, help='Локальный подписанный комплект целевой версии')
    target.add_argument('--release', help='Тег публичного выпуска для загрузки и проверки')
    parser.add_argument('--version', help='Ожидаемая версия; обязательна при загрузке')
    parser.add_argument('--download-to', type=Path, help='Новый защищённый каталог для скачанного выпуска')
    parser.add_argument('--current-bundle', type=Path, help='Подписанный комплект текущей версии для первого принятия под управление')
    parser.add_argument('--publisher-key', type=Path, help='Публичный ключ издателя')
    parser.add_argument('--fingerprint', help='SHA-256 ключа издателя, полученный по независимому каналу')
    parser.add_argument('--backup-root', type=Path, help='Отдельный каталог резервных копий')
    parser.add_argument('--backup-key', type=Path, help='Путь к ключу резервной копии')
    parser.add_argument('--offline', action='store_true', help='Только Compose: не загружать образы при обновлении; загрузка выпуска и LLM могут использовать сеть')
    parser.add_argument('--confirm', action='store_true', help='Явно запустить обновление без интерактивного подтверждения')
    parser.add_argument('--check-only', action='store_true', help='Проверить план без изменения установки; --release всё равно скачивает выпуск')
    parser.add_argument('--json', action='store_true', help='Машинный JSON-вывод; необходим --confirm или --check-only')
    args = parser.parse_args(argv)
    if args.json and not (args.confirm or args.check_only):
        raise WizardError('JSON_REQUIRES_CONFIRM_OR_CHECK_ONLY')
    for field, question in (('home', 'Каталог установки'),
                            ('fingerprint', 'Независимо полученный SHA-256 ключа')):
        if getattr(args, field) is None:
            if not sys.stdin.isatty():
                raise WizardError('REQUIRED_ARGUMENT_MISSING')
            value = input(question + ': ').strip()
            if not value:
                raise WizardError('REQUIRED_ARGUMENT_MISSING')
            setattr(args, field, value if field == 'fingerprint' else Path(value))
    args.fingerprint = args.fingerprint.lower()
    if not FINGERPRINT.fullmatch(args.fingerprint):
        raise WizardError('PUBLISHER_FINGERPRINT_INVALID')
    if args.bundle is None and args.release is None:
        if not sys.stdin.isatty():
            raise WizardError('TARGET_SELECTION_REQUIRED')
        choice = input('Новый выпуск: 1 — локальный комплект, 2 — загрузить из GitHub: ').strip()
        if choice == '1':
            args.bundle = Path(input('Каталог нового подписанного комплекта: ').strip())
        elif choice == '2':
            args.release = input('Тег опубликованного выпуска: ').strip()
            args.version = input('Ожидаемая версия выпуска: ').strip()
        else:
            raise WizardError('TARGET_SELECTION_REQUIRED')
    if args.release is not None:
        if not args.version or not uterctl.VERSION.fullmatch(args.version):
            raise WizardError('EXPECTED_VERSION_REQUIRED')
        # Refuse invalid installation paths before using the network or writing a release.
        checked_home = security.private_directory(args.home)
        destination = args.download_to or checked_home.parent / (checked_home.name + '-release-' + args.version)
        if not args.json:
            print('Загрузка и проверка подписанного выпуска в ' + str(destination))
        try:
            fetch_release.fetch_with_deadline(args.release, args.fingerprint, args.version, destination)
        except Exception:
            raise WizardError('RELEASE_FETCH_OR_VERIFICATION_FAILED') from None
        args.bundle = Path(destination) / 'bundle'
        if args.publisher_key is None:
            args.publisher_key = Path(destination) / 'downloads' / 'publisher-public.pem'
    elif args.download_to is not None:
        raise WizardError('DOWNLOAD_DIRECTORY_REQUIRES_RELEASE')
    if args.publisher_key is None:
        if not sys.stdin.isatty():
            raise WizardError('PUBLISHER_KEY_REQUIRED')
        value = input('Путь к доверенному публичному ключу: ').strip()
        if not value:
            raise WizardError('PUBLISHER_KEY_REQUIRED')
        args.publisher_key = Path(value)
    if args.current_bundle is None and not security.present(Path(args.home) / 'state.json'):
        if not sys.stdin.isatty():
            raise WizardError('CURRENT_SIGNED_BUNDLE_REQUIRED')
        value = input('Каталог подписанного комплекта текущей версии: ').strip()
        if not value:
            raise WizardError('CURRENT_SIGNED_BUNDLE_REQUIRED')
        args.current_bundle = Path(value)
    plan = prepare_plan(args.home, args.bundle, args.publisher_key, args.fingerprint,
                        current_bundle=args.current_bundle, backup_root=args.backup_root,
                        backup_key=args.backup_key, offline=args.offline)
    if args.version and plan['new']['version'] != args.version:
        raise WizardError('EXPECTED_VERSION_MISMATCH')
    if not args.json:
        display_plan(plan)
    if args.check_only:
        if args.json:
            print(json.dumps(check_only_result(plan)))
        else:
            print('Проверка плана завершена; установка не изменена.')
        return 0
    if not args.confirm:
        if not sys.stdin.isatty() or input('Для запуска введите UPDATE: ').strip() != 'UPDATE':
            print('Обновление не запущено.')
            return 2
    result = execute(plan)
    if args.json:
        print(json.dumps(result))
    else:
        print('Обновлено до версии ' + result['version'] + '; копия: ' + result['backup'])
        print('Ключ копии: ' + str(plan['backup_key']) + '. Сохраните его отдельно от копии.')
    return 0


def report_error(error, *, machine=False):
    # Only allowlisted codes are disclosed; external exceptions are never printed.
    if isinstance(error, KeyboardInterrupt):
        code = 'INTERRUPTED_INSPECT_STATE'
    elif isinstance(error, WizardError) and str(error) in MESSAGES:
        code = str(error)
    else:
        code = 'INPUT_OR_VERIFICATION_FAILED'
    if isinstance(error, SessionMigrationBlocked) and code in (
            'SESSION_MIGRATION_AMBIGUOUS', 'SESSION_MIGRATION_SCAN_FAILED',
            'SESSION_MIGRATION_FENCE_UNVERIFIED'):
        if machine:
            print(json.dumps({'result': 'blocked', 'code': code, 'old_version': error.old_version,
                              'new_version': error.new_version, 'backup': error.backup,
                              'backup_id': error.backup_id, 'backup_independently_verified': error.backup_verified}))
        else:
            print(MESSAGES[code], file=sys.stderr)
            print('В отчёте обновления указан каталог копии: ' + error.backup, file=sys.stderr)
            if error.backup_verified:
                print('Целостность и принадлежность зашифрованной копии проверены; восстановление отдельно не проверялось.', file=sys.stderr)
            else:
                print('Не удалось независимо проверить целостность и принадлежность копии; проверьте её отдельно.', file=sys.stderr)
            print('Проверьте состояние сервиса перед дальнейшими действиями.', file=sys.stderr)
    elif machine:
        print(json.dumps({'result': 'error', 'code': code}))
    else:
        print(MESSAGES[code], file=sys.stderr)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as exc:
        report_error(exc, machine='--json' in sys.argv[1:])
        raise SystemExit(1)
