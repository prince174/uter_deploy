"""Bounded, allowlisted diagnostics for disposable signed recovery checks."""
import json
from pathlib import Path

# Values are constant labels: never interpolate stderr, paths, credentials, or API data.
CATEGORIES = (
    ('Bundle inventory mismatch', 'signed-bundle-inventory'),
    ('InvalidSignature', 'signature-invalid'),
    ('Signed backup release changed', 'signed-backup-release-changed'),
    ('Copied signed release changed', 'copied-signed-release-changed'),
    ('Backed-up installation state does not match its signed release', 'backup-signed-state-mismatch'),
    ('Backed-up installation identity does not match', 'backup-installation-identity-mismatch'),
    ('Backed-up installer identity does not match', 'backup-installer-identity-mismatch'),
    ('Backup version and recorded installation state differ', 'backup-version-mismatch'),
    ('Backup belongs to a different installation', 'backup-identity-mismatch'),
    ('Backup must contain a completed adopted installation state', 'backup-state-incomplete'),
    ('Invalid or incomplete backup manifest', 'backup-manifest-invalid'),
    ('Encrypted archive authentication failed', 'backup-authentication-failed'),
    ('InvalidTag', 'backup-authentication-failed'),
    ('Unsupported tooling schema', 'unsupported-tooling-schema'),
    ('Redis snapshot failed structural validation', 'redis-snapshot-invalid'),
    ('Redis AOF baseline did not complete', 'redis-aof-timeout'),
    ('Redis did not enable AOF', 'redis-aof-enable-failed'),
    ('Redis AOF creation or write failed', 'redis-aof-write-failed'),
    ('Restored Redis failed to start', 'redis-start-timeout'),
    ('Recovery volume ownership could not be verified', 'recovery-volume-ownership'),
    ('Recovery namespace ownership could not be verified', 'recovery-namespace-ownership'),
    ('recovery operation failed; output withheld', 'recovery-external-operation-failed'),
    ('Recovery home already exists', 'recovery-home-exists'),
    ('Recovery home must be outside the original installation', 'recovery-home-inside-source'),
    ('Recovery project already exists; choose a new name', 'recovery-project-exists'),
    ('Recovery volume name already exists', 'recovery-volume-exists'),
    ('Recovery staging must be outside the original installation', 'recovery-staging-inside-source'),
    ('Backup backend and staged installation state differ', 'backup-backend-mismatch'),
    ('Invalid backup directory', 'backup-directory-invalid'),
    ('Backup version mismatch', 'backup-version-mismatch'),
    ('Missing backup component', 'backup-component-missing'),
    ('Staging destination already exists', 'staging-destination-exists'),
    ('Export destination already exists', 'export-destination-exists'),
    ('Recovery helper must be a regular signed file', 'recovery-helper-invalid'),
    ('Only the local default Docker context is supported', 'docker-context-unsupported'),
    ('A local Unix Docker socket is required', 'docker-socket-invalid'),
    ('This command requires a Compose backup', 'backup-not-compose'),
    ('This command requires a Kubernetes backup', 'backup-not-kubernetes'),
    ('Recovery project must have a different name', 'recovery-project-name-invalid'),
    ('Recovery namespace must have a different name', 'recovery-namespace-name-invalid'),
    ('Unsafe path in backup archive', 'backup-archive-unsafe-path'),
    ('Links and special files are forbidden in backup archives', 'backup-archive-forbidden-link'),
    ('Unsafe entry in staging archive', 'staging-archive-unsafe'),
    ('[Errno 98]', 'recovery-port-in-use'),
    ('Address already in use', 'recovery-port-in-use'),
    ('PermissionError', 'permission-error'),
    ('FileNotFoundError', 'file-not-found'),
    ('FileExistsError', 'file-exists'),
    ('NotADirectoryError', 'not-a-directory'),
    ('ModuleNotFoundError', 'module-not-found'),
    ('JSONDecodeError', 'invalid-json'),
    ('TimeoutError', 'timeout'),
    ('KeyError', 'missing-key'),
    ('AttributeError', 'attribute-error'),
    ('compose recovery: ValueError:', 'compose-value-error'),
    ('kubernetes recovery: ValueError:', 'kubernetes-value-error'),
    ('compose recovery: TypeError:', 'compose-type-error'),
    ('kubernetes recovery: TypeError:', 'kubernetes-type-error'),
    ('compose recovery: OSError:', 'compose-os-error'),
    ('kubernetes recovery: OSError:', 'kubernetes-os-error'),
    ('compose recovery: RuntimeError:', 'compose-runtime-error'),
    ('kubernetes recovery: RuntimeError:', 'kubernetes-runtime-error'),
)
PHASES = frozenset(('preparing', 'creating-namespace', 'restoring-volumes', 'starting', 'complete'))


def recovery_category(stderr):
    text = stderr.decode('utf-8', errors='replace')[:65536]
    return next((label for pattern, label in CATEGORIES if pattern in text), 'unclassified')


def recovery_phase(target):
    try:
        path = Path(target)/'recovery-operation.json'
        if path.is_symlink() or path.stat().st_size > 4096:
            return 'unknown'
        phase = json.loads(path.read_text(encoding='utf-8')).get('phase')
        return phase if phase in PHASES else 'unknown'
    except (OSError, ValueError, TypeError, AttributeError):
        return 'unavailable'
