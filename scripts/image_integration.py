"""Disposable CI-only Compose acceptance. Refuses to run outside GitHub Actions."""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

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
    shutil.copyfile(home / "policies/default.toml", home / "policies/customer.toml")
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
        "guardrail": {"depends_on": {"fixture": {"condition": "service_started"}}}}}
    (home / "override.json").write_text(json.dumps(override))
    env = os.environ.copy()
    env.update(CUSTOMER_DIR=str(home), GUARDRAIL_IMAGE="uter-guardrail-protected", AGENT_IMAGE="uter-agent-protected",
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
    finally:
        logs = subprocess.run(cmd + ["logs", "--no-color", "--tail", "150"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode(errors="replace")
        for secret in [admin, service, shared, redis_password, jwt, hmac, admin_hash, service_hash]:
            logs = logs.replace(secret, "[REDACTED]")
        (evidence / "service-logs.txt").write_text(logs)
        subprocess.run(cmd + ["down", "--volumes", "--remove-orphans"], env=env, check=True)


if __name__ == "__main__":
    main()
