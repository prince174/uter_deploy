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
import types

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
    if 'maintenance_protocol' in m:
        capability = m['maintenance_protocol']
        if (not isinstance(capability, dict) or set(capability) != {'version', 'services'}
                or type(capability['version']) is not int or capability['version'] != 1
                or capability['services'] != ['agent', 'guardrail']):
            raise ValueError('Invalid maintenance protocol capability')
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


@contextmanager
def fenced_locked(home, *, reclaim=False):
    """Held managed capability for experimental fenced operations only."""
    from scripts import managed_operation_lock
    with managed_operation_lock.locked(home,reclaim=reclaim):
        yield


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


_FENCE_EXECUTOR_MODULES = (
    'backup_installation', 'backup_crypto', 'backup_store', 'backup_snapshot',
    'archive_safety', 'restore_backup', 'recovery_preflight', 'recovery_volume',
    'recovery_aof', 'recover_compose', 'recover_kubernetes', 'recovery_kube_volumes',
    'extract_signed_bundle', 'managed_smoke', 'adopt_managed', 'update_installation',
    'smoke_http', 'extract_release_inputs', 'preflight', 'fetch_release',
    'install_recovery', 'workload_preflight', 'install', 'adopt_installation',
    'redis_fence_journal', 'compose_nsfirewall_adapter', 'compose_nsfirewall_protocol',
    'compose_nsfirewall_checkpoint', 'compose_fence_adapter', 'compose_fence_recovery_plan',
    'compose_redis_diagnostic', 'compose_systemd_activation', 'experimental_docker_activation_ci',
    'compose_snapshot_only', 'snapshot_only_receipts', 'compose_fence_start', 'compose_fence_resume', 'compose_fence_origin',
    'compose_fence_finalize', 'compose_fenced_update','experimental_operation_lock','managed_operation_lock',
    'maintenance_receipt','maintenance_protocol','maintenance_evidence','maintenance_transport',
    'kubernetes_sealed_config','kubernetes_trusted_kubectl','kubernetes_fence_pin','kubernetes_redis_identity',
)


def _load_signed_fence_executor(executor_key):
    """Validate signed executor and constrain its Python namespace.

    Run only as a fresh Python -I process from a trusted, protected bundle.
    Self-checking cannot authenticate code before it has already begun running:
    the launcher and Python interpreter/dependencies remain trusted.
    """
    if not sys.flags.isolated:
        raise ValueError('FENCE_EXECUTOR_ISOLATED_PYTHON_REQUIRED')
    if any(name in ('scripts','uterctl') or name.startswith('scripts.') for name in sys.modules):
        raise ValueError('FENCE_EXECUTOR_IMPORT_STATE_UNSAFE')
    verify(ROOT,executor_key)
    for name in _FENCE_EXECUTOR_MODULES:
        if not (ROOT/'scripts'/(name+'.py')).is_file():
            raise ValueError('FENCE_EXECUTOR_COMPONENT_MISSING')
    # Build a package confined to this verified bundle; do not resolve a
    # package named scripts through unrelated installed packages or PYTHONPATH.
    import importlib
    import importlib.machinery
    package=types.ModuleType('scripts')
    package.__path__=[str(ROOT/'scripts')]
    package.__package__='scripts'
    package.__spec__=importlib.machinery.ModuleSpec('scripts',loader=None,is_package=True)
    package.__spec__.submodule_search_locations=package.__path__
    sys.modules['scripts']=package
    sys.path.insert(0,str(ROOT))
    for name in ('backup_installation','compose_nsfirewall_adapter','compose_nsfirewall_protocol',
                 'redis_fence_journal','compose_snapshot_only','compose_fence_start','compose_fence_resume','compose_fence_finalize','compose_fenced_update','managed_operation_lock'):
        importlib.import_module('scripts.'+name)
    for name,module in tuple(sys.modules.items()):
        if name.startswith('scripts.'):
            filename=getattr(module,'__file__',None)
            expected=ROOT/'scripts'/(name.split('.',1)[1].replace('.','/')+'.py')
            if not filename or Path(filename).resolve()!=expected or not expected.is_file():
                raise ValueError('FENCE_EXECUTOR_IMPORT_UNSAFE')
        if name=='uterctl':
            filename=getattr(module,'__file__',None)
            if not filename or Path(filename).resolve()!=ROOT/'uterctl.py':
                raise ValueError('FENCE_EXECUTOR_IMPORT_UNSAFE')


def _fence_secret_inputs(home, backup_key_path):
    from scripts import backup_installation
    if backup_key_path is None:
        raise ValueError('FENCE_RECOVERY_BACKUP_KEY_REQUIRED')
    if not Path(home).is_absolute() or not Path(backup_key_path).is_absolute():
        raise ValueError('FENCE_RECOVERY_PATH_NOT_ABSOLUTE')
    # Verify the original paths, not resolved paths, so a symlink or an unsafe
    # ancestor cannot silently redirect the operation or protected backup key.
    try:
        home=backup_installation.private_directory(home)
        key_path=backup_installation.checked_existing_path(backup_key_path)
    except backup_installation.BackupError:
        raise ValueError('FENCE_RECOVERY_PATH_UNSAFE') from None
    if key_path == home or key_path.is_relative_to(home):
        raise ValueError('FENCE_RECOVERY_KEY_LOCATION_INVALID')
    try:
        secret=backup_installation.safe_file(key_path,private=True,limit=32)
    except backup_installation.BackupError:
        raise ValueError('FENCE_RECOVERY_BACKUP_KEY_INVALID') from None
    if len(secret)!=32:
        raise ValueError('FENCE_RECOVERY_BACKUP_KEY_INVALID')
    return home,key_path,secret


def _fence_current_record(home, bundle, publisher_key, allowed_phases):
    """Caller holds lock; bind journal to the exact signed installation."""
    from scripts import backup_installation, redis_fence_journal
    if any(os.path.lexists(home/name) for name in (redis_fence_journal.FINALIZE_ANCHOR,redis_fence_journal.UPDATE_INTENT,redis_fence_journal.UPDATE_START,redis_fence_journal.UPDATE_RESULT,redis_fence_journal.CLEANUP_INTENT)):
        raise ValueError('REDIS_FENCE_REQUIRES_INSPECTION')
    state=backup_installation.safe_json(home/'state.json')
    if (state.get('adopted_installer') is not True or state.get('pending') is not None
            or not isinstance(state.get('current'),dict)):
        raise ValueError('FENCE_RECOVERY_INSTALLATION_UNSUPPORTED')
    current=state['current']
    signed=verify(bundle,publisher_key)
    if signed != current:
        raise ValueError('FENCE_RECOVERY_SIGNED_VERSION_MISMATCH')
    installed=home/'releases'/signed['version']
    if (verify(installed,publisher_key) != signed or
            (installed/'checksums.json').read_bytes() != (Path(bundle)/'checksums.json').read_bytes()):
        raise ValueError('FENCE_RECOVERY_SIGNED_VERSION_MISMATCH')
    site=site_config(home)
    cfg=backup_installation.safe_json(home/'install.json')
    record=redis_fence_journal.read(home)
    if (cfg.get('backend')!='compose' or cfg.get('context')!='default'
            or cfg.get('name')!=site.get('name') or site.get('backend')!='compose'
            or site.get('context')!='default' or site.get('namespace')!=site.get('name')
            or record['backend']!='compose' or record['site']!=site['name']
            or record['phase'] not in allowed_phases):
        raise ValueError('FENCE_RECOVERY_STATE_UNSUPPORTED')
    return record


def recover_compose_redis_before_snapshot(home, bundle, publisher_key, backup_key_path):
    """Recover Redis only before snapshot; never resume writers or clear marker."""
    from scripts import compose_nsfirewall_adapter, compose_nsfirewall_protocol, redis_fence_journal
    home,_,secret=_fence_secret_inputs(home,backup_key_path)
    with fenced_locked(home):
        record=_fence_current_record(home,bundle,publisher_key,
                                     ('prepared','isolating','isolated','pre_capture_aborting'))
        adapter=compose_nsfirewall_adapter.Adapter(home,bundle,publisher_key,secret)
        try:
            compose_nsfirewall_protocol.recover_before_capture(home,record['operation'],adapter)
        finally:
            # close() only closes descriptors; it does not change Redis/firewall.
            adapter.close()
        final=redis_fence_journal.read(home)
        if final['operation']!=record['operation'] or final['phase']!='redis_released':
            raise ValueError('FENCE_RECOVERY_RESULT_UNVERIFIED')
    print('Redis released before snapshot; writers remain stopped and the fence journal is retained.')


def capture_compose_fenced_backup(home,bundle,publisher_key,executor_key,backup_key_path,destination):
    """One fixed fenced backup only; no rollout, restart, or automatic cleanup."""
    from scripts import backup_installation, compose_nsfirewall_adapter, compose_snapshot_only, redis_fence_journal
    home,key_path,secret=_fence_secret_inputs(home,backup_key_path)
    if destination is None or not Path(destination).is_absolute() or '..' in Path(destination).parts:
        raise ValueError('FENCE_BACKUP_DESTINATION_INVALID')
    destination=Path(destination)
    try: parent=backup_installation.private_directory(destination.parent)
    except backup_installation.BackupError:raise ValueError('FENCE_BACKUP_DESTINATION_INVALID') from None
    destination=parent/destination.name
    if (destination==home or destination.is_relative_to(home) or key_path==destination
            or key_path.is_relative_to(destination) or os.path.lexists(destination)):
        raise ValueError('FENCE_BACKUP_DESTINATION_INVALID')
    with fenced_locked(home):
        if os.path.lexists(home/'backup-operation.json'):
            raise ValueError('FENCE_BACKUP_PRIOR_BACKUP_REQUIRES_INSPECTION')
        record=_fence_current_record(home,bundle,publisher_key,('isolated',))
        adapter=compose_nsfirewall_adapter.Adapter(home,bundle,publisher_key,secret)
        try:
            if adapter.attach_before_capture_recovery(record) is not True or adapter.verify_fenced(record) is not True:
                raise ValueError('FENCE_BACKUP_ISOLATION_UNVERIFIED')
            backup_id=compose_snapshot_only.capture(adapter,record,ROOT,executor_key,destination)
        finally:
            adapter.close()
        final=redis_fence_journal.read(home)
        if final['operation']!=record['operation'] or final['phase']!='captured':
            raise ValueError('FENCE_BACKUP_RESULT_UNVERIFIED')
    print('Fenced backup '+backup_id+' created; Redis remains isolated and writers remain stopped.')


def recover_compose_redis_after_snapshot(home,bundle,publisher_key,executor_key,backup_key_path,destination):
    """Recover only Redis after a verified snapshot-only release decision."""
    from scripts import backup_installation, compose_nsfirewall_adapter, compose_snapshot_only, redis_fence_journal
    home,key_path,secret=_fence_secret_inputs(home,backup_key_path)
    if destination is None or not Path(destination).is_absolute() or '..' in Path(destination).parts:
        raise ValueError('FENCE_BACKUP_DESTINATION_INVALID')
    try: destination=backup_installation.private_directory(destination)
    except backup_installation.BackupError:raise ValueError('FENCE_BACKUP_DESTINATION_INVALID') from None
    if (destination==home or destination.is_relative_to(home) or key_path==destination
            or key_path.is_relative_to(destination)):
        raise ValueError('FENCE_BACKUP_DESTINATION_INVALID')
    with fenced_locked(home):
        if os.path.lexists(home/'backup-operation.json'):
            raise ValueError('FENCE_BACKUP_PRIOR_BACKUP_REQUIRES_INSPECTION')
        record=_fence_current_record(home,bundle,publisher_key,('captured','snapshot_releasing'))
        adapter=compose_nsfirewall_adapter.Adapter(home,bundle,publisher_key,secret)
        try:
            backup_id=compose_snapshot_only.recover(adapter,ROOT,executor_key,destination)
        finally:
            adapter.close()
        final=redis_fence_journal.read(home)
        if (final['operation']!=record['operation'] or final['phase']!='redis_released'
                or not isinstance(backup_id,str) or not re.fullmatch(r'[0-9a-f]{32}',backup_id)):
            raise ValueError('FENCE_RECOVERY_RESULT_UNVERIFIED')
    print('Redis released after verified snapshot '+backup_id+'; writers remain stopped and the fence journal is retained.')


def start_compose_fence(home,bundle,publisher_key,backup_key_path):
    """Start the signed local Compose fence; ambiguous failures stay stopped."""
    from scripts import compose_fence_start
    home,_,secret=_fence_secret_inputs(home,backup_key_path)
    with fenced_locked(home):
        operation=compose_fence_start.start(home,bundle,publisher_key,secret)
    print('Compose Redis fence '+operation+' established; writers stopped. '
          'Experimental profile trusts host root, Docker daemon and administrators; '
          'no update or session migration is authorized.')


def resume_compose_writers_after_fence(home,bundle,publisher_key,executor_key,backup_key_path,destination):
    """Start only the original writers; keep the journal and never restore data."""
    from scripts import backup_installation, compose_fence_resume, compose_nsfirewall_adapter, redis_fence_journal
    home,key_path,secret=_fence_secret_inputs(home,backup_key_path)
    if destination is not None:
        if not Path(destination).is_absolute() or '..' in Path(destination).parts:
            raise ValueError('FENCE_BACKUP_DESTINATION_INVALID')
        try: destination=backup_installation.private_directory(destination)
        except backup_installation.BackupError:raise ValueError('FENCE_BACKUP_DESTINATION_INVALID') from None
        if (destination==home or destination.is_relative_to(home) or key_path==destination
                or key_path.is_relative_to(destination)):
            raise ValueError('FENCE_BACKUP_DESTINATION_INVALID')
    with fenced_locked(home):
        if os.path.lexists(home/'backup-operation.json'):
            raise ValueError('FENCE_BACKUP_PRIOR_BACKUP_REQUIRES_INSPECTION')
        record=_fence_current_record(home,bundle,publisher_key,('redis_released',))
        adapter=compose_nsfirewall_adapter.Adapter(home,bundle,publisher_key,secret)
        try:compose_fence_resume.resume(adapter,record,executor_key,destination)
        finally:adapter.close()
        final=redis_fence_journal.read(home)
        if final['operation']!=record['operation'] or final['phase']!='writers_resumed':
            raise ValueError('FENCE_RESUME_RESULT_UNVERIFIED')
    print('Original writers are healthy; the fence journal is retained. '
          'Traffic may have started before health checks; do not restore an older backup over new data.')


def finalize_compose_fence(home,bundle,publisher_key,executor_key,backup_key_path,destination):
    """Recheck running identity/evidence and delete the journal last, never data."""
    from scripts import backup_installation, compose_fence_finalize, compose_nsfirewall_adapter, redis_fence_journal
    home,key_path,secret=_fence_secret_inputs(home,backup_key_path)
    if destination is not None:
        if not Path(destination).is_absolute() or '..' in Path(destination).parts:
            raise ValueError('FENCE_BACKUP_DESTINATION_INVALID')
        try:destination=backup_installation.private_directory(destination)
        except backup_installation.BackupError:raise ValueError('FENCE_BACKUP_DESTINATION_INVALID') from None
        if (destination==home or destination.is_relative_to(home) or key_path==destination
                or key_path.is_relative_to(destination)):
            raise ValueError('FENCE_BACKUP_DESTINATION_INVALID')
    with fenced_locked(home):
        record=_fence_current_record(home,bundle,publisher_key,('writers_resumed',))
        adapter=compose_nsfirewall_adapter.Adapter(home,bundle,publisher_key,secret)
        try:compose_fence_finalize.finalize(adapter,record,executor_key,destination)
        finally:adapter.close()
        if redis_fence_journal.blocks_mutation(home):
            raise ValueError('FENCE_FINALIZE_RESULT_UNVERIFIED')
    print('Compose fence finalized after identity and health checks; backup was not restored or deleted.')


def apply_compose_fenced_update(home,bundle,publisher_key,executor_key,backup_key_path,destination,*,offline=False):
    """One explicitly scoped same-epoch Compose update under the PID lock."""
    from scripts import backup_installation, compose_fenced_update, redis_fence_journal
    home,key_path,secret=_fence_secret_inputs(home,backup_key_path)
    if destination is None or not Path(destination).is_absolute() or '..' in Path(destination).parts:
        raise ValueError('FENCED_UPDATE_DESTINATION_INVALID')
    destination=Path(destination)
    try:parent=backup_installation.private_directory(destination.parent)
    except backup_installation.BackupError:raise ValueError('FENCED_UPDATE_DESTINATION_INVALID') from None
    destination=parent/destination.name
    if (destination==home or destination.is_relative_to(home) or key_path==destination
            or key_path.is_relative_to(destination) or os.path.lexists(destination)):
        raise ValueError('FENCED_UPDATE_DESTINATION_INVALID')
    with fenced_locked(home):
        if redis_fence_journal.blocks_mutation(home):raise ValueError('REDIS_FENCE_REQUIRES_INSPECTION')
        state=backup_installation.safe_json(home/'state.json')
        site=site_config(home)
        current=state.get('current')
        if not isinstance(current,dict) or not VERSION.fullmatch(current.get('version','')):
            raise ValueError('FENCED_UPDATE_CURRENT_INVALID')
        source=home/'releases'/current['version']
        old,new=compose_fenced_update.preflight(home,source,bundle,publisher_key,state,site)
        staged=compose_fenced_update.stage_target(home,bundle,publisher_key,new)
        compose_fenced_update.preflight(home,source,staged,publisher_key,state,site)
        if not offline:compose_fenced_update.pull_writers(home,staged,new,site)
        compose_fenced_update.capture_for_update(home,source,staged,publisher_key,executor_key,secret,destination)
        compose_fenced_update.release_for_update(home,source,staged,publisher_key,executor_key,secret,destination)
        compose_fenced_update.start_target(home,source,staged,publisher_key,executor_key,secret,destination)
        result=compose_fenced_update.finalize_target(home,source,staged,publisher_key,executor_key,secret,destination)
    print('Compose fenced update to '+result['version']+' completed; encrypted backup retained. '
          'Traffic may have started before health checks; never restore an older backup over new data.')


def finish_compose_fenced_update(home,bundle,publisher_key,executor_key,backup_key_path,destination):
    """Explicitly finish only a fully evidenced, healthy target update."""
    from scripts import backup_installation, compose_fenced_update, redis_fence_journal
    home,key_path,secret=_fence_secret_inputs(home,backup_key_path)
    if destination is None or not Path(destination).is_absolute() or '..' in Path(destination).parts:
        raise ValueError('FENCED_UPDATE_DESTINATION_INVALID')
    try:destination=backup_installation.private_directory(destination)
    except backup_installation.BackupError:raise ValueError('FENCED_UPDATE_DESTINATION_INVALID') from None
    if destination==home or destination.is_relative_to(home) or key_path==destination or key_path.is_relative_to(destination):
        raise ValueError('FENCED_UPDATE_DESTINATION_INVALID')
    reclaim=os.path.lexists(home/'operation.lock')
    if reclaim:
        compose_fenced_update.verify_reclaimable_finish(home,secret)
    with fenced_locked(home,reclaim=reclaim):
        if reclaim:
            compose_fenced_update.verify_reclaimable_finish(home,secret)
        if os.path.lexists(home/redis_fence_journal.FINALIZE_ANCHOR):raise ValueError('REDIS_FENCE_REQUIRES_INSPECTION')
        if os.path.lexists(home/redis_fence_journal.CLEANUP_INTENT):
            result=compose_fenced_update.finish_sealed_cleanup(home,bundle,publisher_key,executor_key,secret,destination)
        else:
            record=redis_fence_journal.read(home)
            if record['phase'] not in ('target_running','update_finalizing'):
                raise ValueError('FENCED_UPDATE_RECOVERY_REQUIRES_INSPECTION')
            state=backup_installation.safe_json(home/'state.json')
            new=verify(bundle,publisher_key);current=state.get('current')
            old=state.get('previous') if current==new else current
            if not isinstance(old,dict) or not VERSION.fullmatch(old.get('version','')):
                raise ValueError('FENCED_UPDATE_RECOVERY_REQUIRES_INSPECTION')
            source=home/'releases'/old['version']
            result=compose_fenced_update.finalize_target(home,source,bundle,publisher_key,executor_key,secret,destination)
    print('Verified Compose fenced update to '+result['version']+' finalized; backup retained.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["verify", "check", "apply", "resume", "rollback", "status", "fence-status", "fence-recover-redis", "fence-backup-redis", "fence-start-redis", "fence-recover-snapshot-redis", "fence-resume-writers", "fence-finalize", "fence-finish-update"])
    parser.add_argument("--home", type=Path, default=Path("runtime-installation"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--key", type=Path, help="Pre-trusted public key, distributed independently")
    parser.add_argument("--backup-receipt", type=Path)
    parser.add_argument("--backup-dir", type=Path, help="New, external directory for an encrypted backup")
    parser.add_argument("--backup-key", type=Path, help="Protected 32-byte backup encryption key")
    parser.add_argument("--executor-key", type=Path, help="Pre-trusted public key for the signed executor")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--fenced-update", action="store_true", help="Experimental same-epoch Compose fenced update")
    args = parser.parse_args(argv)
    home = args.home.resolve()
    if args.fenced_update:
        if args.command!='apply' or args.key is None or args.bundle is None or args.executor_key is None:
            raise ValueError('FENCED_UPDATE_ARGUMENTS_REQUIRED')
        if any(not path.is_absolute() for path in (args.home,args.bundle,args.key,args.executor_key)):
            raise ValueError('FENCED_UPDATE_PATH_NOT_ABSOLUTE')
        _load_signed_fence_executor(args.executor_key)
        apply_compose_fenced_update(args.home,args.bundle,args.key,args.executor_key,args.backup_key,args.backup_dir,offline=args.offline)
        return
    if args.command=='fence-finish-update':
        if args.key is None or args.bundle is None or args.executor_key is None:
            raise ValueError('FENCED_UPDATE_ARGUMENTS_REQUIRED')
        if any(not path.is_absolute() for path in (args.home,args.bundle,args.key,args.executor_key)):
            raise ValueError('FENCED_UPDATE_PATH_NOT_ABSOLUTE')
        _load_signed_fence_executor(args.executor_key)
        finish_compose_fenced_update(args.home,args.bundle,args.key,args.executor_key,args.backup_key,args.backup_dir)
        return
    if args.command in ("fence-recover-redis", "fence-backup-redis", "fence-start-redis", "fence-recover-snapshot-redis", "fence-resume-writers", "fence-finalize"):
        if args.key is None or args.bundle is None or args.executor_key is None:
            raise ValueError('FENCE_RECOVERY_SIGNED_BUNDLE_REQUIRED')
        if any(not path.is_absolute() for path in (args.home,args.bundle,args.key,args.executor_key)):
            raise ValueError('FENCE_RECOVERY_PATH_NOT_ABSOLUTE')
        _load_signed_fence_executor(args.executor_key)
        from scripts import redis_fence_journal
        if any(os.path.lexists(args.home/name) for name in (redis_fence_journal.FINALIZE_ANCHOR,redis_fence_journal.UPDATE_INTENT,redis_fence_journal.UPDATE_START,redis_fence_journal.UPDATE_RESULT,redis_fence_journal.CLEANUP_INTENT)):
            raise ValueError('REDIS_FENCE_REQUIRES_INSPECTION')
        if args.command == "fence-recover-redis":
            recover_compose_redis_before_snapshot(args.home, args.bundle, args.key, args.backup_key)
        elif args.command == "fence-backup-redis":
            capture_compose_fenced_backup(args.home,args.bundle,args.key,args.executor_key,args.backup_key,args.backup_dir)
        elif args.command == "fence-recover-snapshot-redis":
            recover_compose_redis_after_snapshot(args.home,args.bundle,args.key,args.executor_key,args.backup_key,args.backup_dir)
        elif args.command == "fence-resume-writers":
            resume_compose_writers_after_fence(args.home,args.bundle,args.key,args.executor_key,args.backup_key,args.backup_dir)
        elif args.command == "fence-finalize":
            finalize_compose_fence(args.home,args.bundle,args.key,args.executor_key,args.backup_key,args.backup_dir)
        else:
            start_compose_fence(args.home,args.bundle,args.key,args.backup_key)
        return
    if args.command == "fence-status":
        # A journal is a recovery aid, never proof that a fence currently
        # exists. Do not create the installation directory for inspection.
        from scripts import redis_fence_journal
        if not home.is_dir():
            raise ValueError('Installation directory not found')
        marker = home / redis_fence_journal.NAME
        anchor = os.path.lexists(home / redis_fence_journal.FINALIZE_ANCHOR)
        if os.path.lexists(marker) and anchor:
            # A linked journal deliberately has nlink=2 and is not accepted by
            # ordinary journal.read(); report the uncertainty without parsing.
            result = {'journal':'present','finalize_anchor':'present','live_fence_verified':False}
        elif os.path.lexists(marker):
            record = redis_fence_journal.read(home)
            result = {'journal': 'present', 'backend': record['backend'], 'phase': record['phase'],
                      'operation': record['operation'], 'finalize_anchor':'absent','live_fence_verified': False}
        else:
            result = {'journal': 'absent', 'finalize_anchor':'present' if anchor else 'absent',
                      'live_fence_verified': False}
        result['update_intent'] = ('present' if os.path.lexists(home / redis_fence_journal.UPDATE_INTENT) else 'absent')
        result['target_start'] = ('present' if os.path.lexists(home / redis_fence_journal.UPDATE_START) else 'absent')
        result['target_result'] = ('present' if os.path.lexists(home / redis_fence_journal.UPDATE_RESULT) else 'absent')
        result['cleanup_intent'] = ('present' if os.path.lexists(home / redis_fence_journal.CLEANUP_INTENT) else 'absent')
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
        if any(os.path.lexists(home/name) for name in ('redis-fence-operation.json','compose-fence-finalize-anchor.json','compose-fenced-update-intent.json','compose-fenced-target-start.json','compose-fenced-target-result.json','compose-fenced-cleanup.json')):
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
