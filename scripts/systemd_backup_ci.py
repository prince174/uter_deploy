"""Exercise a published signed Compose backup unit on a disposable hosted runner."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import shutil
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import backup_crypto, backup_store, offline_compose_ci as isolated, scheduled_backup_ci as scheduled
from scripts.corporate_tls_ci import StageError, call, cleanup, free_port, gateway_address, terminate


def runner_guard():
    isolated.ci_only()
    if (os.environ.get('RUNNER_OS') != 'Linux' or
            Path('/proc/1/comm').read_text().strip() != 'systemd'):
        raise StageError('GITHUB_HOSTED_SYSTEMD_REQUIRED')
    work = Path(os.environ['TEST_WORKSPACE']).resolve(strict=True)
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    if work == workspace or not work.is_relative_to(workspace):
        raise StageError('TEST_WORKSPACE_INVALID')
    call(['systemctl', 'show', '--property=Version', '--value'], 'SYSTEMD_UNAVAILABLE', timeout=15)
    return work


class TestUnit:
    """Install exactly one unique unit under /run; verify ownership before cleanup."""
    def __init__(self, name, source):
        if not re.fullmatch(r'uter-backup-uter-offline-ci-[0-9a-f]{12}\.service', name):
            raise StageError('UNIT_NAME_INVALID')
        self.name, self.source = name, Path(source)
        self.fd = None
        self.identity = None
        self.started = False

    def install(self):
        try:
            query = subprocess.run(['systemctl','show',self.name,'--property=LoadState','--value'],
                                   capture_output=True,timeout=15)
        except (OSError,subprocess.TimeoutExpired):
            raise StageError('UNIT_QUERY_FAILED') from None
        if query.returncode not in (0,4) or query.stdout.strip() != b'not-found':
            raise StageError('UNIT_ALREADY_EXISTS')
        self.fd = os.open('/run/systemd/system', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(self.fd)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise StageError('SYSTEMD_DIRECTORY_UNSAFE')
        content = self.source.read_bytes()
        if len(content) > 16384:
            raise StageError('UNIT_CONTENT_INVALID')
        fd = os.open(self.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=self.fd)
        info = os.fstat(fd)
        self.identity = (info.st_dev, info.st_ino, hashlib.sha256(content).digest())
        with os.fdopen(fd, 'wb') as target:
            os.fchmod(target.fileno(), 0o644)
            target.write(content); target.flush(); os.fsync(target.fileno())
        call(['systemctl','daemon-reload'], 'SYSTEMD_RELOAD_FAILED', timeout=60)

    def owned(self):
        if self.fd is None or self.identity is None:
            return False
        try:
            fd = os.open(self.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
            with os.fdopen(fd, 'rb') as source:
                info = os.fstat(source.fileno())
                return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                        and (info.st_dev,info.st_ino) == self.identity[:2]
                        and hashlib.sha256(source.read(16385)).digest() == self.identity[2])
        except OSError:
            return False

    def start(self):
        if not self.owned():
            raise StageError('UNIT_IDENTITY_CHANGED')
        self.started = True
        call(['systemctl','start',self.name], 'BACKUP_UNIT_FAILED', timeout=1200)
        value = call(['systemctl','show',self.name,'--property=Result','--property=ExecMainStatus'],
                     'UNIT_STATUS_FAILED', timeout=15).decode('ascii').splitlines()
        if set(value) != {'Result=success','ExecMainStatus=0'}:
            raise StageError('UNIT_STATUS_INVALID')

    def close(self):
        failed = False
        if self.identity is not None:
            if not self.owned():
                failed = True
            else:
                if self.started:
                    failed |= not cleanup(['systemctl','stop',self.name], os.environ.copy())
                if self.owned():
                    try:
                        os.unlink(self.name, dir_fd=self.fd)
                    except OSError:
                        failed = True
                else:
                    failed = True
                failed |= not cleanup(['systemctl','daemon-reload'], os.environ.copy())
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if failed:
            raise StageError('UNIT_CLEANUP_FAILED')


def run():
    work = runner_guard()
    name = 'uter-offline-ci-' + secrets.token_hex(6)
    fixture = None
    unit = None
    env = os.environ.copy()
    for variable in list(env):
        if variable.startswith('COMPOSE_') or variable in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_AUTH_CONFIG') or variable.lower() in ('http_proxy','https_proxy','all_proxy','no_proxy'):
            del env[variable]
    docker = shutil.which('docker')
    if not docker:
        raise StageError('DOCKER_UNAVAILABLE')
    with tempfile.TemporaryDirectory(prefix='uter-systemd-ci-', dir='/tmp') as directory:
        root = Path(directory)
        bundle, public, inputs, manifest = scheduled.copy_verified_release(work, root)
        if manifest['version'] != '0.1.5':
            raise StageError('PUBLISHED_VERSION_MISMATCH')
        if not (bundle/'scripts/render_backup_systemd.py').is_file() or not (bundle/'scripts/backup_installation.py').is_file():
            raise StageError('PUBLISHED_TOOL_MISSING')
        venv = root/'venv'
        call([sys.executable,'-m','venv','--copies',venv], 'VENV_CREATE_FAILED', env=env, timeout=120)
        python = venv/'bin/python3'
        if python.is_symlink():
            raise StageError('VENV_EXECUTABLE_SYMLINK')
        call([python,'-m','pip','install','-r',bundle/'requirements.txt'], 'VENV_DEPENDENCY_FAILED', env=env, timeout=360)
        home, backups, keys, identities = root/'home', root/'backups', root/'keys', root/'identities'
        for folder in (backups,keys,identities):
            folder.mkdir(mode=0o700)
        docker_config = root/'docker-config'; docker_config.mkdir(mode=0o700)
        env['DOCKER_CONFIG'] = str(docker_config)
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        if any(isolated.owned_resources(docker, name, env).values()):
            raise StageError('TEST_PROJECT_ALREADY_EXISTS')
        try:
            gateway = gateway_address('compose', '', env)
            port = free_port(gateway)
            fixture = subprocess.Popen([str(python),str(ROOT/'tests/fixtures/scheduled_backup_upstream.py'),
                                        '--host',gateway,'--port',str(port)], env=env,
                                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            base = 'http://'+gateway+':'+str(port)
            scheduled.wait_fixture(base,fixture)
            llm_key = root/'empty-key'; llm_key.write_bytes(b''); llm_key.chmod(0o600)
            installer = bundle/'scripts/install.py'
            call([python,installer,'prepare','--home',home,'--backend','compose','--name',name,
                  '--inputs',inputs,'--llm-url',base+'/v1','--llm-model','test-model','--llm-key-file',llm_key,
                  '--allow-http-llm','--port',str(scheduled.SOURCE_PORT),'--guardrail-cpus','2'],
                 'PREPARE_FAILED',env=env)
            cfg = json.loads((home/'install.json').read_text())
            if cfg['images'] != manifest['images']:
                raise StageError('INSTALLED_IMAGE_MISMATCH')
            call([python,installer,'check','--home',home],'INSTALL_CHECK_FAILED',env=env)
            call([python,installer,'install','--home',home],'INSTALL_FAILED',env=env,timeout=600)
            scheduled.source_smoke('compose','',name,scheduled.SOURCE_PORT,home,env)
            before = scheduled.check_data('compose',name,'',env,'write')
            call([python,bundle/'scripts/adopt_managed.py','--home',home,'--bundle',bundle,
                  '--publisher-key',public],'ADOPTION_FAILED',env=env,timeout=600)
            backup_key=keys/'backup.key'; identity=identities/'identity.json'
            cli = bundle/'scripts/backup_installation.py'
            call([python,cli,'create-key','--home',home,'--backup-root',backups,'--backup-key',backup_key],
                 'BACKUP_KEY_CREATE_FAILED',env=env)
            common=['--home',home,'--publisher-key',public,'--expected-backend','compose',
                    '--expected-name',name,'--expected-context','default']
            call([python,cli,'register',*common,'--identity-file',identity],'REGISTRATION_FAILED',env=env,timeout=600)
            out=root/'generated'
            call([python,bundle/'scripts/render_backup_systemd.py','--home',home,'--backup-root',backups,
                  '--backup-key',backup_key,'--identity-file',identity,'--publisher-key',public,
                  '--publisher-sha256',scheduled.PUBLISHER_FINGERPRINT,'--bundle',bundle,'--python',python,
                  '--name',name,'--schedule','02:00','--output',out],'UNIT_RENDER_FAILED',env=env,timeout=600)
            service = out/('uter-backup-'+name+'.service')
            timer = out/('uter-backup-'+name+'.timer')
            call(['systemd-analyze','verify',service,timer],'UNIT_VERIFY_FAILED',env=env,timeout=60)
            previous=(home/'state.json').read_bytes()
            unit=TestUnit(service.name,service)
            unit.install()
            unit.start()
            entries=list(backups.iterdir())
            if len(entries)!=1 or not entries[0].is_dir() or not entries[0].name.startswith('uter-'):
                raise StageError('BACKUP_OUTPUT_INVALID')
            secret=backup_crypto.read_key(backup_key)
            metadata=backup_store.verify_set(entries[0],secret)
            if metadata['version'] != manifest['version']:
                raise StageError('BACKUP_VERSION_MISMATCH')
            wrong=bytes([secret[0]^1])+secret[1:]
            try:
                backup_store.verify_set(entries[0],wrong)
            except ValueError:
                pass
            else:
                raise StageError('INCORRECT_KEY_ACCEPTED')
            for label in ('runtime','redis','audit'):
                if b'synthetic-value' in (entries[0]/(label+'.enc')).read_bytes():
                    raise StageError('BACKUP_CONTAINS_PLAINTEXT')
            if (home/'state.json').read_bytes()!=previous:
                raise StageError('BACKUP_CHANGED_CONTROLLER_STATE')
            scheduled.source_smoke('compose','',name,scheduled.SOURCE_PORT,home,env)
            scheduled.check_audit_continuity(before,scheduled.check_data('compose',name,'',env,'verify'))
            print(json.dumps({'published_version':'0.1.5','service':'started once; timer not enabled',
                              'encrypted_backup':'verified; wrong key rejected','workload_resume':'verified',
                              'redis_and_audit':'verified','upstream':'deterministic fixture; not a real LLM'}))
        finally:
            try:
                if unit is not None:
                    unit.close()
            finally:
                try:
                    isolated.cleanup(docker,name,env)
                finally:
                    terminate(fixture)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        run()
    except (Exception,KeyboardInterrupt) as exc:
        print('Systemd backup CI failed:', str(exc) if isinstance(exc,StageError) else type(exc).__name__,file=sys.stderr)
        sys.exit(1)
