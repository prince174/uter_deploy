"""Conservative, read-only session compatibility guard for quiesced Redis.

The caller owns the controller lock and must have stopped all Uter writers.
Redis key names and values never leave the Redis process or appear in logs.
Without a proven external-writer fence this guard always refuses rollout.
"""
import os
import re
import select
import shlex
import subprocess
import time
from pathlib import Path

from scripts import install

AMBIGUOUS = 'SESSION_MIGRATION_AMBIGUOUS'
SCAN_FAILED = 'SESSION_MIGRATION_SCAN_FAILED'
FENCE_UNVERIFIED = 'SESSION_MIGRATION_FENCE_UNVERIFIED'
REASONS = frozenset((AMBIGUOUS, SCAN_FAILED, FENCE_UNVERIFIED))

# A single bounded Redis SCAN page per script: Redis executes Lua atomically,
# so looping inside Lua could block unrelated clients for an excessive time.
# The script returns only cursor and 0/1, never key names.
_SCRIPT = ("local r=redis.call('SCAN',ARGV[1],'MATCH','sess:*','COUNT',128); "
           "return {r[1],#r[2]>0 and 1 or 0}")


class SessionMigrationBlocked(ValueError):
    """A fixed diagnostic reason, without user or Redis data."""


def _redis_command(home, cfg, site, current, redis_args):
    if cfg.get('context') != site.get('context') or cfg.get('name') != site.get('name'):
        raise SessionMigrationBlocked(SCAN_FAILED)
    # Arguments consist exclusively of checked integers and constant commands.
    cli = ' '.join(shlex.quote(str(arg)) for arg in ['redis-cli', '--raw', *redis_args])
    if site.get('backend') == 'compose' and cfg.get('backend') == 'compose':
        if cfg.get('context') != 'default':
            raise SessionMigrationBlocked(SCAN_FAILED)
        command, env = install.commands(home, dict(cfg, images=current['images']))
        command[command.index('-f')+1] = str(Path(home)/'releases'/current['version']/'compose/compose.yaml')
        shell = 'export REDISCLI_AUTH="$(cat /run/secrets/redis_password)"; exec '+cli
        return command+['exec', '-T', 'redis', 'sh', '-ec', shell], env
    if site.get('backend') == 'helm' and cfg.get('backend') == 'kubernetes':
        if cfg.get('name') != site.get('namespace'):
            raise SessionMigrationBlocked(SCAN_FAILED)
        shell = 'export REDISCLI_AUTH="$REDIS_PASSWORD"; exec '+cli
        command = ['kubectl', '--context', cfg['context'], '-n', site['namespace'], 'exec',
                   'deployment/'+site['name']+'-redis', '-c', 'redis', '--', 'sh', '-ec', shell]
        return command, None
    raise SessionMigrationBlocked(SCAN_FAILED)


def _query(home, cfg, site, current, args, timeout):
    process = None
    try:
        command, env = _redis_command(home, cfg, site, current, args)
        process = subprocess.Popen([str(value) for value in command], env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        deadline = time.monotonic()+timeout
        output = bytearray()
        while True:
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise SessionMigrationBlocked(SCAN_FAILED)
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if not ready:
                raise SessionMigrationBlocked(SCAN_FAILED)
            chunk = os.read(process.stdout.fileno(), 4097-len(output))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > 4096:
                raise SessionMigrationBlocked(SCAN_FAILED)
        if process.wait(timeout=max(0.01, deadline-time.monotonic())):
            raise SessionMigrationBlocked(SCAN_FAILED)
        return bytes(output)
    except SessionMigrationBlocked:
        raise
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SessionMigrationBlocked(SCAN_FAILED) from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait()
            if process.stdout is not None:
                process.stdout.close()


def _scan_for_legacy_sessions(home, cfg, site, current, *, timeout=180):
    """Observe all DBs without authorizing an update or proving isolation.

    No session at the instant of these reads does not rule out a new writer.
    An eligible caller must independently hold and verify a continuous fence
    before and after the complete scan; this helper never verifies that fence.
    """
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise SessionMigrationBlocked(SCAN_FAILED)
    deadline = time.monotonic()+timeout
    try:
        raw = _query(home, cfg, site, current, ['CONFIG', 'GET', 'databases'], min(30, timeout))
        match = re.fullmatch(rb'databases\r?\n([0-9]{1,3})\r?\n', raw)
        if not match or not 1 <= int(match.group(1)) <= 256:
            raise SessionMigrationBlocked(SCAN_FAILED)
        for database in range(int(match.group(1))):
            cursor = '0'
            seen = set()
            for _ in range(4096):
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise SessionMigrationBlocked(SCAN_FAILED)
                raw = _query(home, cfg, site, current,
                             ['-n', str(database), 'EVAL_RO', _SCRIPT, '0', cursor], min(30, remaining))
                page = re.fullmatch(rb'([0-9]{1,20})\r?\n([01])\r?\n', raw)
                if not page:
                    raise SessionMigrationBlocked(SCAN_FAILED)
                if page.group(2) == b'1':
                    raise SessionMigrationBlocked(AMBIGUOUS)
                cursor = page.group(1).decode('ascii')
                if cursor == '0':
                    break
                if cursor in seen:
                    raise SessionMigrationBlocked(SCAN_FAILED)
                seen.add(cursor)
            else:
                raise SessionMigrationBlocked(SCAN_FAILED)
    except SessionMigrationBlocked:
        raise
    except (OSError, ValueError, TypeError, OverflowError):
        raise SessionMigrationBlocked(SCAN_FAILED) from None


def classify(home, cfg, site, current, *, timeout=180):
    """Preserve the public fail-closed gate, including for empty databases."""
    _scan_for_legacy_sessions(home, cfg, site, current, timeout=timeout)
    raise SessionMigrationBlocked(FENCE_UNVERIFIED)
