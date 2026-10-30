"""Disposable CI experiment only. This is not a production archive tool.

The snapshot contains synthetic data only. Redis writes it to a container tmpfs;
the host forwards it from RAM to the probe's stdin and never writes it to disk.
It tests Redis 7.4.2, not the digest shipped with the product.
"""
import os
import re
import subprocess
import sys
import time
import uuid

IMAGE = "redis:7.4.2-alpine@sha256:02419de7eddf55aa5bcf49efb74e88fa8d931b4d77c07eff8a6b2144472b6952"
OWNER_LABEL = "io.uter-deploy.synthetic-rdb-probe"
TIMEOUT_SECONDS = 50


def runner_guard(environ):
    if (environ.get("GITHUB_ACTIONS") != "true" or
            environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            environ.get("RUNNER_OS") != "Linux" or
            environ.get("DOCKER_HOST") or
            environ.get("DOCKER_CONTEXT", "default") not in ("", "default")):
        raise RuntimeError("requires a GitHub-hosted Linux runner with the default Docker context")


def run(args, *, data=None):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=TIMEOUT_SECONDS)
    if result.returncode:
        raise RuntimeError("synthetic experiment command failed")
    return result.stdout


def verify_probe(binary, snapshot, expiry, execute=subprocess.run):
    """Feed only synthetic in-memory snapshots; do not print subprocess output."""
    if len(snapshot) < 32 or not snapshot.startswith(b"REDIS0012"):
        raise RuntimeError("not a Redis 7.4 RDB v12 snapshot")
    if snapshot[-8:] == b"\0" * 8:
        raise RuntimeError("synthetic RDB checksum must be enabled")
    cases = ((snapshot, 0), (snapshot[:-1] + bytes([snapshot[-1] ^ 1]), 3), (snapshot[:-8], 1))
    for payload, expected in cases:
        result = execute([binary, str(expiry)], input=payload, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, check=False, timeout=TIMEOUT_SECONDS)
        if result.returncode != expected or result.stdout or result.stderr:
            raise RuntimeError("probe failed a positive or negative check")


def main(binary):
    container = None
    owner = uuid.uuid4().hex
    runner_guard(os.environ)
    if run(["docker", "context", "show"]).strip() != b"default":
        raise RuntimeError("Docker context is not default")
    try:
        container = run(["docker", "run", "-d", "--label", f"{OWNER_LABEL}={owner}",
                         "--network", "none", "--tmpfs", "/data:rw,mode=1777",
                         IMAGE, "redis-server", "--save", "", "--appendonly", "no"]).decode().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container):
            container = None
            raise RuntimeError("unexpected Docker container identifier")
        def redis(*args, data=None):
            return run(["docker", "exec", "-i", container, "redis-cli", "-n", "2", *args], data=data).strip()

        for _ in range(50):
            try:
                if redis("PING") == b"PONG":
                    break
            except RuntimeError:
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("synthetic Redis did not start")
        redis("RPUSH", "sess:synthetic", "alpha")
        redis("-x", "RPUSH", "sess:synthetic", data=b"beta\0x")
        if redis("PEXPIRE", "sess:synthetic", "15000") != b"1":
            raise RuntimeError("cannot set synthetic TTL")
        expiry = int(redis("PEXPIRETIME", "sess:synthetic"))
        if redis("SAVE") != b"OK":
            raise RuntimeError("synthetic snapshot failed")
        snapshot = run(["docker", "exec", container, "cat", "/data/dump.rdb"])
        deadline = time.monotonic() + 30
        while redis("EXISTS", "sess:synthetic") != b"0":
            if time.monotonic() >= deadline:
                raise RuntimeError("synthetic TTL did not expire")
            time.sleep(0.2)
        verify_probe(binary, snapshot, expiry)
        print("Synthetic Redis 7.4 expired-key extraction and integrity checks passed.")
    finally:
        if container:
            try:
                template = '{{.Id}} {{index .Config.Labels "' + OWNER_LABEL + '"}}'
                identity = run(["docker", "inspect", "--format", template, container]).decode().strip()
                if identity == f"{container} {owner}":
                    subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, check=False, timeout=TIMEOUT_SECONDS)
            except (RuntimeError, OSError, subprocess.TimeoutExpired, UnicodeError):
                pass


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: experimental_rdb_probe.py PROBE_BINARY")
    try:
        main(sys.argv[1])
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired):
        raise SystemExit("Synthetic Redis RDB experiment failed; no snapshot was published.")
