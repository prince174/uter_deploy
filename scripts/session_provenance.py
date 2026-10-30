"""Placeholder for a future session provenance source.

This module is deliberately disconnected from the update gate. No submitted value,
configuration or environment variable can turn the placeholder into evidence.
"""


class ProvenanceUnavailable(ValueError):
    """No verified source exists; the exception never contains session data."""


def require_owner_proof(*, snapshot_id, database, session_key):
    """Refuse to identify the owner of any session.

    Arguments are reserved for a future interface and are deliberately not
    inspected, logged or returned. A real verifier has not been implemented.
    """
    raise ProvenanceUnavailable('SESSION_PROVENANCE_UNAVAILABLE')
