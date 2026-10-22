"""Opt-in local watcher. Run checks in snapshots; never changes or pushes Uter."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

EXTENSIONS = {".py", ".toml", ".yaml", ".yml", ".json", ".sh", ".txt"}


def files(source):
    raw = subprocess.check_output(["git", "-C", str(source), "ls-files", "-z", "--cached", "--others", "--exclude-standard"])
    result = {}
    for name in sorted(set(raw.decode().split("\0")) - {""}):
        p = source / name
        parts = Path(name).parts
        if any(x in {"certs", "secrets", "logs", "models", ".git", ".venv"} for x in parts):
            continue
        if p.name.startswith(".env") or p.is_symlink() or not p.is_file():
            continue
        if p.suffix not in EXTENSIONS and p.name != "Dockerfile":
            continue
        result[name] = p.read_bytes()
    return result


def fingerprint(data):
    h = hashlib.sha256()
    for name, content in sorted(data.items()):
        h.update(name.encode() + b"\0" + hashlib.sha256(content).digest())
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--work", type=Path, default=Path(__file__).resolve().parents[1] / "work/watch")
    p.add_argument("--command-json", type=Path, required=True, help="JSON argv array; executed in snapshot")
    p.add_argument("--debounce", type=float, default=10)
    p.add_argument("--once", action="store_true")
    a = p.parse_args()
    source, work = a.source.resolve(), a.work.resolve()
    if work == source or source in work.parents or work in source.parents:
        p.error("work and source must be disjoint")
    command = json.loads(a.command_json.read_text())
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        p.error("command must be a nonempty argv list")
    work.mkdir(parents=True, exist_ok=True)
    lock = work / "watch.lock"
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    last = None
    pending = None
    changed = time.monotonic()
    try:
        while True:
            data = files(source)
            digest = fingerprint(data)
            if digest != pending:
                pending, changed = digest, time.monotonic()
            if digest != last and (a.once or time.monotonic() - changed >= a.debounce):
                snapshot = work / f"snapshot-{time.time_ns()}"
                snapshot.mkdir()
                for name, content in data.items():
                    dest = snapshot / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(content)
                print(f"Testing isolated snapshot {digest[:12]}", flush=True)
                env = os.environ.copy()
                env.pop("PYTHONPATH", None)
                env.pop("PYTHONHOME", None)
                with (snapshot / "checks.log").open("w", encoding="utf-8") as log:
                    code = subprocess.run(command, cwd=snapshot, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
                (work / "status.json").write_text(json.dumps({"fingerprint": digest, "exit_code": code,
                    "snapshot": str(snapshot), "published": False}, indent=2))
                print(f"Checks exit={code}; log: {snapshot / 'checks.log'}", flush=True)
                last = digest
                if a.once:
                    return code
            time.sleep(1)
    finally:
        lock.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
