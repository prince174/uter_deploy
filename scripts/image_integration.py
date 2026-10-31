"""Disposable CI-only Compose acceptance. Refuses to run outside GitHub Actions."""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(argv, **kw):
    return subprocess.run([str(x) for x in argv], check=True, **kw)


def ensure_unused_project(project):
    """Fail before CI start when its generated namespace already has resources."""
    for kind, args in (('containers',['ps','-aq','--filter','label=com.docker.compose.project='+project]),
                       ('volumes',['volume','ls','-q','--filter','label=com.docker.compose.project='+project]),
                       ('networks',['network','ls','-q','--filter','label=com.docker.compose.project='+project])):
        if subprocess.check_output(['docker','--context','default',*args]).strip(): raise ValueError(kind)
    for kind, names, args in (
        ('volumes',{project+'_redis-data',project+'_audit-data'},['volume','ls','--format','{{.Name}}']),
        ('networks',{project+'_backend',project+'_outbound'},['network','ls','--format','{{.Name}}']),
        ('containers',{project+'-'+s+'-1' for s in ('redis','agent','guardrail','fixture')},
         ['ps','-a','--format','{{.Names}}'])):
        observed=subprocess.check_output(['docker','--context','default',*args]).decode().splitlines()
        if names.intersection(observed): raise ValueError(kind)


def ensure_owned_project(project):
    """Before destructive CI cleanup, reject unexpected project resources."""
    for allowed, args in (
        ({project+'-'+s+'-1' for s in ('redis','agent','guardrail','fixture')},
         ['ps','-a','--filter','label=com.docker.compose.project='+project,'--format','{{.Names}}']),
        ({project+'_redis-data',project+'_audit-data'},
         ['volume','ls','--filter','label=com.docker.compose.project='+project,'--format','{{.Name}}']),
        ({project+'_backend',project+'_outbound'},
         ['network','ls','--filter','label=com.docker.compose.project='+project,'--format','{{.Name}}'])):
        observed=subprocess.check_output(['docker','--context','default',*args]).decode().splitlines()
        if len(observed)!=len(set(observed)) or not set(observed).issubset(allowed): raise ValueError


def acl_startup_failure(cmd, env):
    """Return fixed categories only; raw service logs are never returned."""
    try:
        state=subprocess.run(cmd+['ps','-a','--format','json'],env=env,stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL,timeout=30,check=True).stdout
        try: items=json.loads(state) if state.strip() else []
        except json.JSONDecodeError: items=[json.loads(line) for line in state.splitlines() if line.strip()]
        if isinstance(items,dict): items=[items]
        if not isinstance(items,list): return 'STARTUP_STATUS_UNAVAILABLE'
        redis_log=subprocess.run(cmd+['logs','--no-color','--tail','80','redis'],env=env,
                                 stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30).stdout.upper()
        if b'FATAL CONFIG FILE ERROR' in redis_log or b'ERROR LOADING THE ACLS' in redis_log:
            return 'STARTUP_REDIS_CONFIG_INVALID'
        if b'NOPERM' in redis_log or b'NOAUTH' in redis_log:
            return 'STARTUP_REDIS_PERMISSION'
        for service in ('redis','agent','guardrail','fixture'):
            matches=[x for x in items if isinstance(x,dict) and x.get('Service') == service]
            if not matches: return 'STARTUP_'+service.upper()+'_MISSING'
            if len(matches) != 1: return 'STARTUP_'+service.upper()+'_AMBIGUOUS'
            if matches[0].get('State') != 'running': return 'STARTUP_'+service.upper()+'_NOT_RUNNING'
            if matches[0].get('Health') == 'unhealthy':
                if service == 'redis':
                    ident=matches[0].get('ID','')
                    if isinstance(ident,str) and re.fullmatch(r'[0-9a-f]{12,64}',ident):
                        raw=subprocess.run(['docker','--context','default','inspect','--format',
                            '{{json .State.Health}}',ident],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                            timeout=30,check=True).stdout.upper()
                        for marker,code in ((b'WRONGPASS','AUTH_REJECTED'),(b'NOAUTH','AUTH_REQUIRED'),
                                            (b'NOPERM','COMMAND_DENIED'),(b'COULD NOT CONNECT','CONNECT_FAILED'),
                                            (b'NO SUCH FILE','FILE_MISSING'),(b'PERMISSION DENIED','FILE_DENIED')):
                            if marker in raw: return 'STARTUP_REDIS_HEALTH_'+code
                return 'STARTUP_'+service.upper()+'_UNHEALTHY'
        return 'STARTUP_NOT_READY'
    except Exception:
        return 'STARTUP_STATUS_UNAVAILABLE'


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Disposable GitHub runner required; do not run on the active workstation")
    acl_test = os.environ.get('UTER_CI_REDIS_ACL') == 'true'
    staged_product = os.environ.get('UTER_CI_STAGED_PRODUCT') == 'true'
    acl_temp = None
    if staged_product and (not acl_test or os.environ.get('UTER_CI_MAINTENANCE') != 'true'):
        raise SystemExit('Staged CI requires disposable ACL and maintenance fixtures')
    if acl_test:
        if (os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.environ.get('RUNNER_OS') != 'Linux'
                or os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT')):
            raise SystemExit('Disposable hosted Linux runner required')
        endpoint = subprocess.check_output(['docker','context','inspect','default','--format',
                                            '{{.Endpoints.docker.Host}}']).decode().strip()
        if endpoint != 'unix:///var/run/docker.sock': raise SystemExit('Local disposable Docker required')
    home = ROOT / "work/integration"
    home.mkdir(parents=True, exist_ok=False)
    if acl_test: home.chmod(0o700)
    evidence = ROOT / "work/integration-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    source = ROOT / "work/images/protected-guardrail/evidence"
    shutil.copytree(source / "policies", home / "policies")
    shutil.copyfile(home / "policies/default.toml", home / "policies/runtime.toml")
    shutil.copytree(source / "profiles", home / "profiles")
    (home / "models").mkdir()
    admin, service, shared, redis_password, jwt, hmac = [secrets.token_hex(24) for _ in range(6)]
    acl_admin = secrets.token_hex(32) if acl_test else ''
    # All credentials are ephemeral fixtures and never uploaded as artifacts.
    hashes = subprocess.run(["docker", "run", "-i", "--rm", "--network", "none", "--entrypoint", "python", "uter-guardrail-protected", "-c",
        "import bcrypt,json,sys; print(json.dumps([bcrypt.hashpw(x.encode(),bcrypt.gensalt()).decode() for x in json.load(sys.stdin)]))"],
        input=json.dumps([admin,service]).encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout
    admin_hash, service_hash = json.loads(hashes)
    values = {"JWT_SECRET": jwt, "ADMIN_PASSWORD_HASH": admin_hash, "SERVICE_PASSWORD_HASH": service_hash,
        "AGENT_INTERNAL_SHARED_SECRET": shared, "UPSTREAM_MODE": "litellm_openai", "UPSTREAM_URL": "http://fixture:8080",
        "UPSTREAM_OPENAI_MODEL": "test-model", "JUDGE_ENABLED": "false", "TOXICITY_FAIL_CLOSED": "true",
        "CI_ADMIN_PASSWORD": admin}
    if staged_product:values['REDIS_USERNAME']='uter-writer'
    (home / "guardrail.env").write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    (home / "agent.env").write_text(f"AGENT_INTERNAL_SHARED_SECRET={shared}\nGUARDRAIL_SERVICE_PASSWORD={service}\n")
    (home / "redis-password").write_text(redis_password)
    (home / "audit-hmac-key").write_text(hmac)
    redis_config = "bind 0.0.0.0\nappendonly yes\ndir /data\n"
    if staged_product:
        import hashlib
        sys.path.insert(0,str(ROOT))
        from scripts import redis_acl_durable
        acl_temp=tempfile.TemporaryDirectory(prefix='uter-product-acl-')
        acl_dir=Path(acl_temp.name)/'acl';acl_dir.mkdir();os.chown(acl_dir,0,1000);acl_dir.chmod(0o710)
        acl_file=acl_dir/'users.acl'
        acl_file.write_bytes(redis_acl_durable.render(admin_user='uter-maint-test',
            writer_hash=hashlib.sha256(redis_password.encode()).hexdigest(),
            admin_hash=hashlib.sha256(acl_admin.encode()).hexdigest(),writer_on=True))
        os.chown(acl_file,999,1000);acl_file.chmod(0o400)
        redis_config += 'aclfile /acl/users.acl\n'
    elif acl_test:
        commands = ('ping get set del eval incr ttl expire lpush ltrim lrange multi exec discard '
                    'smembers sismember scard sadd srem hgetall hexists hlen hset hdel client|setinfo')
        redis_config += 'user default on >'+redis_password+' ~* &* -@all ' + ' '.join('+'+x for x in commands.split()) + '\n'
        redis_config += 'user uter-maint-test on >'+acl_admin+' ~* &* +@all\n'
    else:
        redis_config += 'requirepass '+redis_password+'\n'
    (home / "redis.conf").write_text(redis_config)
    (home / "empty.env").write_text("")
    override = {"services": {
        "fixture": {"image": "python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea",
            "command": ["python", "/fixture.py"], "volumes": [str(ROOT / "tests/fixtures/upstream.py") + ":/fixture.py:ro"], "networks": ["outbound"]},
        "guardrail": {"cpus": 2,
            "depends_on": {"fixture": {"condition": "service_started"}}}}}
    if staged_product:
        signals=home/'staged-signals';signals.mkdir(mode=0o700)
        override['services']['fixture']['volumes']=[str(ROOT/'tests/fixtures/staged_upstream.py')+':/fixture.py:ro',
                                                     str(signals)+':/signals:rw']
        override['services']['fixture']['environment']={'UTER_STAGED_SIGNALS':'/signals'}
        override['services']['redis']={'volumes':[str(acl_dir)+':/acl:ro'],'ports':['127.0.0.1::6379'],
            'healthcheck':{'test':['CMD-SHELL','REDISCLI_AUTH=$$(cat /run/secrets/redis_password) redis-cli --user uter-writer ping | grep -q PONG'],
                           'interval':'300s','start_period':'10s','start_interval':'1s','timeout':'5s','retries':5}}
    maintenance = os.environ.get('UTER_CI_MAINTENANCE') == 'true'
    if maintenance:
        if os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.environ.get('RUNNER_OS') != 'Linux':
            raise SystemExit('Disposable hosted Linux runner required')
        key = home/'maintenance-key'
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'w', encoding='ascii') as stream:
            stream.write(secrets.token_hex(32))
        run(['sudo', 'chown', '10001:10001', key])
        for service in ('agent', 'guardrail'):
            item = override['services'].setdefault(service, {})
            item['environment'] = {'UTER_MAINTENANCE_ENABLED': 'true',
                                   'UTER_MAINTENANCE_KEY_FILE': '/run/uter-maintenance/key'}
            item['volumes'] = [str(key)+':/run/uter-maintenance/key:ro']
            item['stop_grace_period'] = '90s'
    (home / "override.json").write_text(json.dumps(override))
    env = os.environ.copy()
    env.update(RUNTIME_DIR=str(home), GUARDRAIL_IMAGE="uter-guardrail-protected", AGENT_IMAGE="uter-agent-protected",
        REDIS_IMAGE="redis:7.4-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf", GUARDRAIL_PORT="18000")
    if acl_test:
        env['REDIS_IMAGE']='ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc'
    project = 'uter-acl-'+secrets.token_hex(16) if acl_test else 'uter-compiled-ci'
    if acl_test: ensure_unused_project(project)
    cmd = ["docker", "--context", "default", "compose", "--project-name", project, "--env-file", home / "empty.env", "-f", ROOT / "compose/compose.yaml", "-f", home / "override.json"]
    phase='STARTUP'
    try:
        run(cmd + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "300"], env=env)
        phase='ACCEPTANCE'
        check = (ROOT / "scripts/container_acceptance.py").read_bytes()
        result = run(cmd + ["exec", "-T", "guardrail", "python", "-"], input=check, stdout=subprocess.PIPE, env=env)
        (evidence / "acceptance.json").write_bytes(result.stdout)
        if acl_test:
            phase='ACL_PROBE'
            acl_check = (ROOT/'scripts/redis_acl_product_probe.py').read_bytes()
            result = subprocess.run([str(x) for x in cmd + ['exec','-T','guardrail','python','-']],input=acl_check,
                         stdout=subprocess.PIPE,stderr=subprocess.DEVNULL, env=env)
            allowed={b'REDIS_ACL_PRODUCT_'+name+b'_FAILED' for name in
                     (b'IMPORTS',b'RATE_LIMIT',b'DENY_ADMIN_COMMAND',b'HISTORY',b'RULES',b'APPROVAL')}
            if result.returncode and result.stdout.strip() in allowed:
                phase=result.stdout.strip().decode('ascii')
            if result.stdout.strip() != b'REDIS_ACL_PRODUCT_PROBE_PASS': raise ValueError('ACL_PRODUCT_PROBE_FAILED')
            (evidence/'redis-acl-product.txt').write_text('Selected Redis paths passed with a test-only ACL.\n'
                'This is not production ACL coverage, Redis fencing, backup or recovery.\n',encoding='ascii')
        phase='RESTART'
        run(cmd + ["restart", "guardrail"], env=env)
        run(cmd + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "180"], env=env)
        run(cmd + ["exec", "-T", "guardrail", "python", "-"], input=check, stdout=subprocess.PIPE, env=env)
        (evidence / "restart.txt").write_text("Guardrail restart + repeated acceptance + audit continuity passed\n")
        if staged_product:
            sys.path.insert(0,str(ROOT))
            from scripts import redis_acl_staged_product_ci
            phase='STAGED_PRODUCT'
            redis_acl_staged_product_ci.exercise(home,project,admin,acl_admin,redis_password,acl_dir)
        elif maintenance:
            sys.path.insert(0, str(ROOT))
            from scripts import maintenance_compose_product_ci
            try:
                maintenance_compose_product_ci.exercise(home)
            except Exception as exc:
                allowed = {'MAINTENANCE_CI_ENVIRONMENT_UNVERIFIED', 'MAINTENANCE_CI_PATH_UNVERIFIED',
                           'MAINTENANCE_CI_IDENTITY_UNVERIFIED', 'MAINTENANCE_CI_IDENTITY_CHANGED',
                           'MAINTENANCE_CI_IMAGE_UNVERIFIED', 'MAINTENANCE_CI_RECEIPTS_UNVERIFIED',
                           'MAINTENANCE_RESPONSE_UNVERIFIED', 'MAINTENANCE_INVENTORY_CHANGED',
                           'MAINTENANCE_INITIAL_STATE_UNVERIFIED', 'MAINTENANCE_BOOT_ID_DUPLICATE',
                           'MAINTENANCE_DEADLINE_EXCEEDED', 'MAINTENANCE_INTENT_UNVERIFIED',
                           'MAINTENANCE_POST_UNVERIFIED', 'MAINTENANCE_STATE_UNVERIFIED',
                           'MAINTENANCE_RECEIPT_PERSISTENCE_UNVERIFIED', 'MAINTENANCE_OPERATION_UNCERTAIN'}
                code = str(exc) if str(exc) in allowed else 'MAINTENANCE_CI_UNCLASSIFIED'
                (evidence/'maintenance-failure.txt').write_text(code+'\n', encoding='ascii')
                raise
    except Exception:
        if acl_test and phase=='STARTUP': phase=acl_startup_failure(cmd,env)
        if acl_test: (evidence/'redis-acl-product-failure.txt').write_text(phase+'\n',encoding='ascii')
        raise
    finally:
        try:
            if acl_test: ensure_owned_project(project)
            if not acl_test:
                logs = subprocess.run(cmd + ["logs", "--no-color", "--tail", "150"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode(errors="replace")
                for secret in [admin, service, shared, redis_password, jwt, hmac, admin_hash, service_hash]:
                    logs = logs.replace(secret, "[REDACTED]")
                (evidence / "service-logs.txt").write_text(logs)
            subprocess.run(cmd + ["down", "--volumes", "--remove-orphans"], env=env, check=True)
        except Exception:
            if acl_test: (evidence/'redis-acl-product-failure.txt').write_text('CLEANUP_UNCERTAIN\n',encoding='ascii')
            raise
        finally:
            if acl_temp is not None:acl_temp.cleanup()


if __name__ == "__main__":
    main()
