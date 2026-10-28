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
    ('PermissionError', 'permission-error'),
    ('FileNotFoundError', 'file-not-found'),
    ('ModuleNotFoundError', 'module-not-found'),
    ('JSONDecodeError', 'invalid-json'),
    ('TimeoutError', 'timeout'),
    ('KeyError', 'missing-key'),
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
