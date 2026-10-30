#!/usr/bin/env python3
"""Runtime release controller. No product sources or Docker SDK required."""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True  # Do not alter a verified bundle during controller execution.

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?\Z")
IMAGE = re.compile(r"[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}\Z")
ROOT = Path(__file__).resolve().parent


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def validate(m):
    if m.get("schema") != 1 or m.get("config_schema") != 1:
        raise ValueError("Unsupported manifest/config schema")
    if "tooling_schema" in m and (type(m["tooling_schema"]) is not int or m["tooling_schema"] != 1):
        raise ValueError("Unsupported tooling schema")
    if m.get("status") != "released" or not VERSION.fullmatch(m.get("version", "")):
        raise ValueError("Only released, versioned manifests can be installed")
    if not re.fullmatch(r"[0-9a-f]{40}", m.get("source_commit", "")):
        raise ValueError("Full source commit SHA required")
    if 'source_state' in m:
        state = m['source_state']
        if (not isinstance(state, dict) or set(state) != {'kind', 'baseline_commit', 'patch_sha256'}
                or state.get('kind') != 'uncommitted_patch' or state.get('baseline_commit') != m['source_commit']
                or not isinstance(state.get('patch_sha256'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', state['patch_sha256'])):
            raise ValueError('Invalid source snapshot provenance')
    if 'deployment_commit' in m and not re.fullmatch(r'[0-9a-f]{40}',m['deployment_commit']):
        raise ValueError('Full deployment commit SHA required')
    if set(m.get("images", {})) != {"guardrail", "agent", "redis"}:
        raise ValueError("Exactly guardrail, agent and redis images required")
    if any(not IMAGE.fullmatch(v) for v in m["images"].values()):
        raise ValueError("All images must be pinned by sha256 digest")
    ids = m.get("image_config_ids")
    if ids is not None and (not isinstance(ids, dict) or set(ids) != set(m["images"]) or
                            any(not re.fullmatch(r"sha256:[0-9a-f]{64}", v) for v in ids.values())):
        raise ValueError("Optional image_config_ids must cover all images with sha256 IDs")
    if type(m.get("data_epoch")) is not int or m["data_epoch"] < 1:
        raise ValueError("Positive data_epoch required")
    if 'session_identity_gate' in m:
        gate = m['session_identity_gate']
        if (not isinstance(gate, dict) or set(gate) != {'schema', 'from_epoch', 'to_epoch', 'policy'}
                or type(gate.get('schema')) is not int or gate['schema'] != 1
                or type(gate.get('from_epoch')) is not int or gate['from_epoch'] != 1
                or type(gate.get('to_epoch')) is not int or gate['to_epoch'] != 2
                or gate.get('policy') != 'block_unverified_sessions' or m['data_epoch'] != 2):
            raise ValueError('Invalid signed session identity gate')
    if not isinstance(m.get("upgrade_from"), list) or any(not VERSION.fullmatch(v) for v in m["upgrade_from"]):
        raise ValueError("Explicit upgrade_from version list required")
    return m


def inventory(folder):
    result = {}
    for p in sorted(Path(folder).rglob("*")):
        if p.is_symlink():
            raise ValueError("Symlinks are forbidden in bundles")
        if p.is_file() and p.relative_to(folder).as_posix() not in {"checksums.json", "checksums.sig"}:
            result[p.relative_to(folder).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return result


def verify(folder, key_path):
    folder = Path(folder)
    public = load_pem_public_key(Path(key_path).read_bytes())
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("Trusted key must be Ed25519")
    raw = (folder / "checksums.json").read_bytes()
    public.verify(base64.b64decode((folder / "checksums.sig").read_bytes(), validate=True), raw)
    if json.loads(raw) != inventory(folder):
        raise ValueError("Bundle inventory mismatch (changed, extra or missing file)")
    required=["manifest.json", "compose/compose.yaml", "charts/uter/Chart.yaml"]
    manifest=validate(read(folder / "manifest.json"))
    if 'session_identity_gate' in manifest:
        required.append('scripts/session_migration_guard.py')
    if manifest.get('tooling_schema') == 1:
        required += ['uterctl.py','requirements.txt','examples/redis.conf.example','scripts/install.py','scripts/adopt_installation.py',
                     'scripts/backup_crypto.py','scripts/backup_store.py','scripts/backup_snapshot.py',
                     'scripts/archive_safety.py','scripts/restore_backup.py','scripts/recovery_preflight.py',
                     'scripts/recovery_volume.py','scripts/recovery_aof.py','scripts/recover_compose.py',
                     'scripts/recover_kubernetes.py','scripts/recovery_kube_volumes.py',
                     'scripts/extract_signed_bundle.py','scripts/managed_smoke.py','scripts/adopt_managed.py',
                     'scripts/update_installation.py','scripts/smoke_http.py']
    if manifest.get('installation_archive_sha256') is not None:
        if not re.fullmatch(r'[0-9a-f]{64}', manifest['installation_archive_sha256']):
            raise ValueError('Invalid signed installation archive hash')
        required.append('scripts/extract_release_inputs.py')
    for name in required:
        if not (folder / name).is_file():
            raise ValueError(f"Missing {name}")
    return manifest


def transition(old, new):
    if not old:
        return
    changed = old['version'] != new['version']
    if changed and old['version'] not in new['upgrade_from']:
        raise ValueError("Unsupported upgrade path")
    if old['data_epoch'] != new['data_epoch']:
        validate(new)
        expected = {'schema': 1, 'from_epoch': 1, 'to_epoch': 2,
                    'policy': 'block_unverified_sessions'}
        if not (changed and old['data_epoch'] == 1 and new['data_epoch'] == 2
                and new.get('session_identity_gate') == expected):
            raise ValueError("Data migration required; this controller refuses automatic migration")


def run(argv, **kw):
    # argv only; never evaluate user config through a shell.
    subprocess.run([str(x) for x in argv], check=True, **kw)


@contextmanager
def locked(home):
    lock = home / "operation.lock"
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        yield
    finally:
        lock.unlink()


def site_config(home):
    site = read(home / "runtime/site.json")
    if site.get("backend") not in {"compose", "helm"}:
        raise ValueError("backend must be compose or helm")
    for field in ["name", "namespace"]:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,40}", site.get(field, "")):
            raise ValueError(f"Invalid {field}")
    smoke = site.get("smoke_command")
    if not isinstance(smoke, list) or not smoke or not all(isinstance(x, str) for x in smoke):
        raise ValueError("Configure a runtime-owned smoke_command argv list")
    if "context" in site and (not isinstance(site["context"], str) or not site["context"] or site["context"].startswith("-")):
        raise ValueError("Invalid explicit runtime context")
    if "port" in site and (type(site["port"]) is not int or not 1024 <= site["port"] <= 65535):
        raise ValueError("Invalid runtime port")
    if "guardrail_cpus" in site and (type(site["guardrail_cpus"]) not in (int, float) or not 1 <= site["guardrail_cpus"] <= 64):
        raise ValueError("Invalid runtime CPU limit")
    return site


def render_env(home, bundle, m, site=None):
    env = os.environ.copy()
    env.update({k.upper() + "_IMAGE": v for k, v in m["images"].items()})
    env["RUNTIME_DIR"] = (home / "runtime").as_posix()
    if site:
        if "port" in site:
            env["GUARDRAIL_PORT"] = str(site["port"])
        if "guardrail_cpus" in site:
            env["GUARDRAIL_CPUS"] = str(site["guardrail_cpus"])
    return env


def deploy(home, bundle, m, site, *, check=False, offline=False):
    if site["backend"] == "compose":
        runtime = home / "runtime"
        for name in ["guardrail.env", "agent.env", "redis.conf", "redis-password", "audit-hmac-key", "policies/runtime.toml", "profiles/model_profiles.toml"]:
            p = runtime / name
            if not p.is_file() or not p.stat().st_size:
                raise ValueError(f"Required runtime file: {name}")
            if "REPLACE" in p.read_text(encoding="utf-8"):
                raise ValueError(f"Unconfigured runtime file: {name}")
        if not (runtime / "models").is_dir():
            raise ValueError("runtime/models directory required")
        cmd = ["docker"] + (["--context", site["context"]] if site.get("context") else []) + ["compose", "--project-name", site["name"], "--env-file", str(bundle / "empty.env"), "-f", str(bundle / "compose/compose.yaml")]
        env = render_env(home, bundle, m, site)
        run(cmd + ["config", "--quiet"], env=env)
        if check:
            return
        if not offline:
            run(cmd + ["pull"], env=env)
        run(cmd + ["up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "300"], env=env)
    else:
        values = home / "runtime/values.yaml"
        if not values.is_file():
            raise ValueError("runtime/values.yaml required")
        chart = bundle / "charts/uter"
        helm = ["helm"] + (["--kube-context", site["context"]] if site.get("context") else [])
        if check:
            # Check must not overwrite the shared values consumed by a
            # concurrent apply. Keep the private file alive until lint exits.
            with tempfile.TemporaryDirectory(prefix=".uter-helm-check-", dir=home) as directory:
                generated = Path(directory) / "release-values.json"
                write(generated, {"images": m["images"], "productVersion": m["version"]})
                args = ["-f", str(values), "-f", str(generated)]
                run(helm + ["lint", chart] + args)
            return
        generated = home / "release-values.json"
        write(generated, {"images": m["images"], "productVersion": m["version"]})
        args = ["-f", str(values), "-f", str(generated)]
        run(helm + ["lint", chart] + args)
        run(helm + ["upgrade", "--install", site["name"], chart, "--namespace", site["namespace"], "--create-namespace", "--wait", "--timeout", "5m"] + args)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["verify", "check", "apply", "resume", "rollback", "status", "fence-status"])
    parser.add_argument("--home", type=Path, default=Path("runtime-installation"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--key", type=Path, help="Pre-trusted public key, distributed independently")
    parser.add_argument("--backup-receipt", type=Path)
    parser.add_argument("--backup-dir", type=Path, help="New, external directory for an encrypted backup")
    parser.add_argument("--backup-key", type=Path, help="Protected 32-byte backup encryption key")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args(argv)
    home = args.home.resolve()
    if args.command == "fence-status":
        # A journal is a recovery aid, never proof that a fence currently
        # exists. Do not create the installation directory for inspection.
        from scripts import redis_fence_journal
        if not home.is_dir():
            raise ValueError('Installation directory not found')
        marker = home / redis_fence_journal.NAME
        if os.path.lexists(marker):
            record = redis_fence_journal.read(home)
            result = {'journal': 'present', 'backend': record['backend'], 'phase': record['phase'],
                      'operation': record['operation'], 'live_fence_verified': False}
        else:
            result = {'journal': 'absent', 'live_fence_verified': False}
        print(json.dumps(result, sort_keys=True))
        print('Journal observation only; Redis and workloads were not inspected.')
        return
    home.mkdir(parents=True, exist_ok=True)
    state_path = home / "state.json"
    state = read(state_path) if state_path.exists() else {"current": None, "previous": None, "pending": None}
    if args.command == "status":
        print(json.dumps(state, indent=2))
        print("Recorded controller state; not a live health check.")
        return
    recovery = home / "recovery-operation.json"
    if args.command != "verify" and recovery.exists() and read(recovery).get("phase") != "complete":
        raise ValueError("Recovery is incomplete; inspect its journal before controller operations")
    if not args.key:
        raise ValueError("--key required")
    if args.command == "rollback":
        target = state["current"] if state.get("pending") else state.get("previous")
        if not target:
            raise ValueError("No rollback target")
        bundle = home / "releases" / target["version"]
    else:
        if not args.bundle:
            raise ValueError("--bundle required")
        bundle = args.bundle.resolve()
    m = verify(bundle, args.key)
    if args.command == "verify":
        print(f"Verified Uter {m['version']}")
        return
    site = site_config(home)
    if args.command == "resume" and state.get("pending") != m:
        raise ValueError("Resume requires exactly the pending release")
    if args.command != "rollback":
        transition(state["current"], m)
    identity_transition = bool(state.get('current') and args.command != 'rollback'
                               and state['current'].get('data_epoch') == 1
                               and m.get('data_epoch') == 2
                               and m.get('session_identity_gate'))
    if args.command == "check":
        if identity_transition:
            print('Signed transition checked; session and external-writer checks have not run.')
            return
        deploy(home, bundle, m, site, check=True)
        print("Bundle and configuration checked; workloads unchanged.")
        return
    with locked(home):
        # A fence operation can have changed Redis connectivity without
        # reaching a recoverable state. Never let a later managed mutation
        # proceed merely because the controller lock has been released.
        if os.path.lexists(home / 'redis-fence-operation.json'):
            raise ValueError('REDIS_FENCE_REQUIRES_INSPECTION')
        # Re-read after acquiring the lock to reject stale concurrent operations.
        current_state = read(state_path) if state_path.exists() else {"current": None, "previous": None, "pending": None}
        if current_state != state:
            raise ValueError("State changed; retry")
        if args.command == "apply" and state.get("pending"):
            raise ValueError("Previous operation incomplete; inspect and rollback first")
        if args.command == "rollback":
            active = state.get("pending") or state["current"]
            if active["data_epoch"] != m["data_epoch"]:
                raise ValueError("Rollback requires data restoration; refused")
        adopted = state.get("adopted_installer") is True
        if identity_transition and (not adopted or args.command != 'apply' or state.get('pending')):
            raise ValueError('SESSION_MIGRATION_REQUIRES_ADOPTED_IDLE_INSTALLATION')
        if identity_transition and os.path.lexists(home/'session-migration-block.json'):
            raise ValueError('SESSION_MIGRATION_BLOCK_MARKER_EXISTS')
        if adopted and state.get("pending") and args.command == "rollback":
            raise ValueError("Adopted pending update requires verified data restoration; automatic rollback is unavailable")
        if (state["current"] or state.get("pending")) and not adopted:
            if not args.backup_receipt:
                raise ValueError("Existing installation: --backup-receipt required")
            receipt = read(args.backup_receipt)
            if receipt.get("version") != (state.get("pending") or state["current"])["version"] or not receipt.get("backup_id"):
                raise ValueError("Backup receipt must name active/pending version and backup_id")
        destination = home / "releases" / m["version"]
        # Cross-epoch session migration is currently always fail-closed. Do not
        # copy a target release or overwrite generated Helm values before the
        # mandatory backup and guard have made their decision.
        if not identity_transition:
            destination.parent.mkdir(exist_ok=True)
            if destination.exists():
                verify(destination, args.key)
                if (destination / "checksums.json").read_bytes() != (bundle / "checksums.json").read_bytes():
                    raise ValueError("Version already exists with different content")
            else:
                with tempfile.TemporaryDirectory(dir=destination.parent) as tmp:
                    stage = Path(tmp) / "bundle"
                    shutil.copytree(bundle, stage)
                    verify(stage, args.key)
                    stage.rename(destination)
            deploy(home, destination, m, site, check=True)
        backup_meta = None
        if adopted and state["current"]:
            from scripts import backup_crypto, backup_snapshot, backup_store
            if not args.backup_dir or not args.backup_key or args.backup_receipt:
                raise ValueError("Adopted installation requires --backup-dir and --backup-key; receipts alone are insufficient")
            if args.backup_key.resolve().is_relative_to(home):
                raise ValueError("Backup key must be outside the installation home")
            backup_key = backup_crypto.read_key(args.backup_key)
            signed_current = verify(home / "releases" / state["current"]["version"], args.key)
            if signed_current != state["current"]:
                raise ValueError("Current state does not match the signed installed bundle")
            cfg = read(home / "install.json")
            if (cfg.get("name") != site["name"] or site["namespace"] != site["name"] or
                    cfg.get("context") != site.get("context") or
                    cfg.get("backend") != ("kubernetes" if site["backend"] == "helm" else "compose")):
                raise ValueError("Installation identity changed since adoption")
            if state.get("pending"):
                recorded = state.get("last_backup") or {}
                if str(args.backup_dir.resolve()) != recorded.get("path"):
                    raise ValueError("Resume requires the backup created before the pending operation")
                backup_meta = backup_store.verify_set(args.backup_dir, backup_key, home=home, site=site,
                                                       version=state["current"]["version"])
                if backup_meta["id"] != recorded.get("id"):
                    raise ValueError("Pending operation backup identity mismatch")
            else:
                if (home / "backup-operation.json").exists():
                    raise ValueError("Previous backup operation requires inspection before update")
                backup_meta = backup_snapshot.capture(home, cfg, site, state["current"], args.backup_dir,
                                                      backup_key, leave_stopped=True)
                state["last_backup"] = {"id": backup_meta["id"], "path": str(args.backup_dir.resolve()),
                                        "version": backup_meta["version"]}
                if identity_transition:
                    from scripts import session_migration_guard
                    try:
                        session_migration_guard.classify(home, cfg, site, state['current'])
                        # There is no approved external-writer fence yet. Even an
                        # unexpected success must never authorise this transition.
                        raise session_migration_guard.SessionMigrationBlocked(
                            session_migration_guard.FENCE_UNVERIFIED)
                    except BaseException as error:
                        reason = (str(error) if isinstance(error, session_migration_guard.SessionMigrationBlocked)
                                  and str(error) in session_migration_guard.REASONS
                                  else session_migration_guard.SCAN_FAILED)
                        try:
                            backup_snapshot.resume_writers(home, cfg, site, current_state['current'])
                        except BaseException:
                            # Keep the operation journal for inspection. The
                            # encrypted backup remains untouched and recoverable.
                            raise RuntimeError('SESSION_MIGRATION_RESUME_FAILED') from None
                        (home/'backup-operation.json').unlink(missing_ok=True)
                        marker = home/'session-migration-block.json'
                        record = {'schema': 1, 'reason': reason,
                                  'old_version': current_state['current']['version'], 'new_version': m['version'],
                                  'backup_id': backup_meta['id'], 'backup_path': str(args.backup_dir.resolve())}
                        try:
                            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
                            fd = os.open(marker, flags, 0o600)
                            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                                os.fchmod(stream.fileno(), 0o600)
                                json.dump(record, stream, sort_keys=True)
                                stream.write('\n')
                        except OSError:
                            raise RuntimeError('SESSION_MIGRATION_MARKER_FAILED') from None
                        raise ValueError(reason) from None
        state["pending"] = m
        try:
            write(state_path, state)
        except BaseException:
            if adopted and backup_meta and not current_state.get("pending"):
                backup_snapshot.resume_writers(home, cfg, site, current_state["current"])
                (home / "backup-operation.json").unlink(missing_ok=True)
            raise
        try:
            deploy(home, destination, m, site, offline=args.offline)
            run(site["smoke_command"], cwd=home / "runtime")
        except Exception:
            print("Update incomplete. State retained; inspect workloads before explicit rollback.", file=sys.stderr)
            raise
        updated = {"current": m, "previous": state["current"], "pending": None}
        if adopted:
            updated.update(adopted_installer=True, last_backup=state.get("last_backup"))
        write(state_path, updated)
        if adopted and backup_meta:
            (home / "backup-operation.json").unlink(missing_ok=True)
        print(f"Uter {m['version']} applied and runtime smoke test passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"uterctl: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
