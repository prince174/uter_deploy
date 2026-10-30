"""Exercise the Redis ACL experiment on a disposable GitHub-hosted runner."""
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import redis_acl_experiment

IMAGE = 'ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc'
PHASE = 'INITIAL'


class Client:
    def __init__(self, port):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.file = self.sock.makefile('rb')
    def close(self):
        self.file.close(); self.sock.close()
    def read(self):
        line = self.file.readline(262145)
        if not line.endswith(b'\r\n'): raise ValueError
        value = line[1:-2]
        if line[:1] == b'+': return value.decode()
        if line[:1] == b'-': raise ValueError('REDIS_ERROR')
        if line[:1] == b':': return int(value)
        if line[:1] == b'$':
            size = int(value)
            if size == -1: return None
            if not 0 <= size <= 262144: raise ValueError
            raw = self.file.read(size+2)
            if len(raw) != size+2 or raw[-2:] != b'\r\n': raise ValueError
            return raw[:-2].decode()
        if line[:1] == b'*':
            size = int(value)
            if not 0 <= size <= 1024: raise ValueError
            return [self.read() for _ in range(size)]
        raise ValueError
    def call(self, *parts):
        values = [str(p).encode() for p in parts]
        wire = b'*'+str(len(values)).encode()+b'\r\n'
        wire += b''.join(b'$'+str(len(v)).encode()+b'\r\n'+v+b'\r\n' for v in values)
        self.sock.sendall(wire)
        value = self.read()
        if parts[:2] == ('ACL','GETUSER'):
            if not isinstance(value, list) or len(value)%2: raise ValueError
            return dict(zip(value[::2], value[1::2]))
        return value


def docker(*args):
    return subprocess.run(['docker','--context','default',*args],check=True,stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL,timeout=120).stdout.decode().strip()


def cleanup_container(name, nonce, container_id):
    """Remove only a labelled fixture and treat uncertain confirmed cleanup as failure."""
    try:
        target=container_id if container_id else name
        label=docker('inspect','--format','{{index .Config.Labels "uter.acl.ci"}}',target)
    except subprocess.CalledProcessError:
        if container_id: raise
        return
    if label != nonce: raise ValueError
    docker('rm','-f','-v',target)
    if container_id and docker('ps','-aq','--no-trunc','--filter','id='+container_id): raise ValueError


def main():
    global PHASE
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('RUNNER_OS') != 'Linux'
            or os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT')):
        raise ValueError
    if docker('context','inspect','default','--format','{{.Endpoints.docker.Host}}') != 'unix:///var/run/docker.sock':
        raise ValueError
    nonce=secrets.token_hex(16); name='uter-acl-ci-'+nonce; attempted=False; container_id=None; clients=[]
    with tempfile.TemporaryDirectory(prefix='uter-acl-ci-') as directory:
        try:
            default_password=secrets.token_hex(32); admin_password=secrets.token_hex(32)
            config=Path(directory)/'redis.conf'
            config.write_text('bind 0.0.0.0\nprotected-mode yes\nappendonly yes\nrequirepass '+default_password+'\n')
            config.chmod(0o644)
            PHASE='CONTAINER_START'
            attempted=True
            container_id=docker('run','-d','--name',name,'--label','uter.acl.ci='+nonce,'--publish','127.0.0.1::6379','--mount',
                   'type=bind,src='+str(config)+',dst=/etc/uter-redis.conf,readonly',
                   '--entrypoint','redis-server',IMAGE,'/etc/uter-redis.conf')
            if not re.fullmatch(r'[0-9a-f]{64}', container_id): raise ValueError
            port=int(docker('port',name,'6379/tcp').rsplit(':',1)[1])
            deadline=time.monotonic()+30
            while True:
                try:
                    writer=Client(port); clients.append(writer); break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.25)
            PHASE='INITIAL_AUTH'
            writer.call('AUTH',default_password)
            writer.call('ACL','SETUSER','uter-maint-test','on','>'+admin_password,'~*','&*','+@all')
            writer.call('SET','ci-before','ok')
            admin=Client(port); clients.append(admin); admin.call('AUTH','uter-maint-test',admin_password)
            run_id=next(line.split(':',1)[1] for line in admin.call('INFO','SERVER').splitlines() if line.startswith('run_id:'))
            admin_id=str(admin.call('CLIENT','ID')); intents=set()
            def intent(value):
                if value in intents: return False
                intents.add(value); return True
            PHASE='REJECT_PRIVILEGED_DEFAULT'
            try:
                redis_acl_experiment.run(admin.call,admin_user='uter-maint-test',expected_run_id=run_id,
                    expected_client_id=admin_id,record_intent=intent)
            except redis_acl_experiment.ACLExperimentError: pass
            else: raise ValueError
            if intents: raise ValueError
            admin.call('ACL','SETUSER','default','-@all','+ping','+get','+set')
            def execute(*args):
                value=admin.call(*args)
                if args == ('ACL','SETUSER','default','off'):
                    # Disabling AUTH alone must not be mistaken for eviction.
                    if writer.call('SET','ci-after-disable','still-connected') != 'OK': raise ValueError
                return value
            PHASE='ACL_EXPERIMENT'
            result=redis_acl_experiment.run(execute,admin_user='uter-maint-test',expected_run_id=run_id,
                expected_client_id=admin_id,record_intent=intent)
            PHASE='VERIFY_OLD_CLIENT'
            if (result['default_clients_killed'] != 1 or result['safe_to_backup'] is not False
                    or result['safe_to_update'] is not False): raise ValueError
            try: writer.call('SET','ci-after','unexpected')
            except (OSError, ValueError): pass
            else: raise ValueError
            PHASE='VERIFY_NEW_AUTH'
            fresh=Client(port); clients.append(fresh)
            try: fresh.call('AUTH',default_password)
            except ValueError: pass
            else: raise ValueError
            if admin.call('GET','ci-after-disable') != 'still-connected' or admin.call('GET','ci-after') is not None:
                raise ValueError
            if admin.call('PING') != 'PONG': raise ValueError
            fresh.close(); clients.remove(fresh)
            for stage in ('disable', 'kill'):
                PHASE='UNCERTAIN_'+stage.upper()
                admin.call('ACL','SETUSER','default','on')
                uncertain_writer=Client(port); clients.append(uncertain_writer)
                uncertain_writer.call('AUTH',default_password)
                sent=[]; recorded=set()
                def uncertain_intent(value):
                    if value in recorded: return False
                    recorded.add(value); return True
                def uncertain_execute(*args):
                    value=admin.call(*args)
                    if args in (('ACL','SETUSER','default','off'), ('CLIENT','KILL','USER','default','SKIPME','yes')):
                        sent.append(args)
                        if (stage == 'disable' and args[0] == 'ACL') or (stage == 'kill' and args[0] == 'CLIENT'):
                            raise TimeoutError
                    return value
                try:
                    redis_acl_experiment.run(uncertain_execute,admin_user='uter-maint-test',expected_run_id=run_id,
                        expected_client_id=admin_id,record_intent=uncertain_intent)
                except redis_acl_experiment.ACLExperimentError: pass
                else: raise ValueError
                if sent.count(('ACL','SETUSER','default','off')) != 1 or \
                        sent.count(('CLIENT','KILL','USER','default','SKIPME','yes')) != (stage == 'kill'):
                    raise ValueError
                if 'off' not in admin.call('ACL','GETUSER','default')['flags']: raise ValueError
                if stage == 'disable':
                    if uncertain_writer.call('SET','ci-uncertain','still-connected') != 'OK': raise ValueError
                    admin.call('CLIENT','KILL','USER','default','SKIPME','yes')
                else:
                    try: uncertain_writer.call('SET','ci-uncertain','unexpected')
                    except (OSError, ValueError): pass
                    else: raise ValueError
            print('Redis ACL experiment observed a writer after disable, then disconnection and denied new AUTH.')
            print('Unknown command outcomes refused completion without retry; recovery was not tested.')
            print('Fixture-only in-memory intents; isolation, persistence, backup and recovery not proven.')
        finally:
            for client in clients: client.close()
            if attempted:
                cleanup_container(name, nonce, container_id)


if __name__ == '__main__':
    try: main()
    except Exception:
        print('REDIS_ACL_EXPERIMENT_CI_'+PHASE+'_FAILED',file=sys.stderr)
        raise SystemExit(1)
