"""Fail-closed gate until continuous external-writer exclusion is proven."""


class NetworkGuardError(ValueError):pass


def assert_external_exclusion(session,operation):
    # A profile, user flag or current Pod list cannot prove continuous network
    # exclusion. No production implementation is available yet.
    raise NetworkGuardError('KUBE_REVERSE_EXTERNAL_ISOLATION_UNVERIFIED')
