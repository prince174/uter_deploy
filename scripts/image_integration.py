"""Disposable CI-only Compose acceptance. Refuses to run outside GitHub Actions."""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(argv, **kw):
    return subprocess.run([str(x) for x in argv], check=True, **kw)


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Disposable GitHub runner required; do not run on the active workstation")
    home = ROOT / "work/integration"
    home.mkdir(parents=True, exist_ok=False)
    evidence = ROOT / "work/integration-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    source = ROOT / "work/images/protected-guardrail/evidence"
    shutil.copytree(source / "policies", home / "policies")
    shutil.copyfile(home / "policies/default.toml", home / "policies/runtime.toml")
    shutil.copytree(source / "profiles", home / "profiles")
    (home / "models").mkdir()
    admin, service, shared, redis_password, jwt, hmac = [secrets.token_hex(24) for _ in range(6)]
    # All credentials are ephemeral fixtures and never uploaded as artifacts.
    hashes = subprocess.check_output(["docker", "run", "--rm", "--network", "none", "--entrypoint", "python", "uter-guardrail-protected", "-c",
        "import bcrypt,json,sys; print(json.dumps([bcrypt.hashpw(x.encode(),bcrypt.gensalt()).decode() for x in sys.argv[1:]]))", admin, service])
    admin_hash, service_hash = json.loads(hashes)
    values = {"JWT_SECRET": jwt, "ADMIN_PASSWORD_HASH": admin_hash, "SERVICE_PASSWORD_HASH": service_hash,
        "AGENT_INTERNAL_SHARED_SECRET": shared, "UPSTREAM_MODE": "litellm_openai", "UPSTREAM_URL": "http://fixture:8080",
        "UPSTREAM_OPENAI_MODEL": "test-model", "JUDGE_ENABLED": "false", "TOXICITY_FAIL_CLOSED": "true",
        "CI_ADMIN_PASSWORD": admin}
    (home / "guardrail.env").write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    (home / "agent.env").write_text(f"AGENT_INTERNAL_SHARED_SECRET={shared}\nGUARDRAIL_SERVICE_PASSWORD={service}\n")
    (home / "redis-password").write_text(redis_password)
    (home / "audit-hmac-key").write_text(hmac)
    (home / "redis.conf").write_text(f"bind 0.0.0.0\nappendonly yes\ndir /data\nrequirepass {redis_password}\n")
    (home / "empty.env").write_text("")
    override = {"services": {
        "fixture": {"image": "python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea",
            "command": ["python", "/fixture.py"], "volumes": [str(ROOT / "tests/fixtures/upstream.py") + ":/fixture.py:ro"], "networks": ["outbound"]},
        "guardrail": {"cpus": 2,
            "depends_on": {"fixture": {"condition": "service_started"}}}}}
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
    cmd = ["docker", "compose", "--project-name", "uter-compiled-ci", "--env-file", home / "empty.env", "-f", ROOT / "compose/compose.yaml", "-f", home / "override.json"]
    try:
        run(cmd + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "300"], env=env)
        check = (ROOT / "scripts/container_acceptance.py").read_bytes()
        result = run(cmd + ["exec", "-T", "guardrail", "python", "-"], input=check, stdout=subprocess.PIPE, env=env)
        (evidence / "acceptance.json").write_bytes(result.stdout)
        run(cmd + ["restart", "guardrail"], env=env)
        run(cmd + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "180"], env=env)
        run(cmd + ["exec", "-T", "guardrail", "python", "-"], input=check, stdout=subprocess.PIPE, env=env)
        (evidence / "restart.txt").write_text("Guardrail restart + repeated acceptance + audit continuity passed\n")
        if maintenance:
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
    finally:
        logs = subprocess.run(cmd + ["logs", "--no-color", "--tail", "150"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode(errors="replace")
        for secret in [admin, service, shared, redis_password, jwt, hmac, admin_hash, service_hash]:
            logs = logs.replace(secret, "[REDACTED]")
        (evidence / "service-logs.txt").write_text(logs)
        subprocess.run(cmd + ["down", "--volumes", "--remove-orphans"], env=env, check=True)


if __name__ == "__main__":
    main()
