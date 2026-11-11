# SQLite security candidate (not a release)

This opt-in Dockerfile builds from an explicit protected image and installs Debian sid
`libsqlite3-0=3.54.1-2` in a Debian 13 builder, alongside stable security updates.
It is experimental: a package from Debian unstable is not a Debian stable security
update, and this candidate is not connected to release or update workflows.
Availability of the exact version is required; do not fall back silently.

On 2026-11-11 the Agent and Guardrail candidates passed local Python/SQLite FTS5 and
native-library smoke tests. Trivy 0.74.0 removed the two zlib High findings but still
reported three SQLite High findings against installed version 3.54.1-2 without a fixed version.
Debian's security tracker reports those CVEs fixed in sid, while trixie has no fix;
that difference is not an exemption and the gate must not be bypassed.

Both images require full integration testing and independent review of package
provenance and compatibility before publication. Existing source, release artifacts,
and deployment gates remain unchanged. The candidate can be reproduced using
`docker build --build-arg PROTECTED_IMAGE=<pinned-image> --build-arg SERVICE=agent
-f packaging/Dockerfile.sqlite-candidate -t <local-candidate> packaging`.

Semgrep 1.154.0 `p/security-audit` had nine Python parse warnings on the Windows
checkout; copies of the same nine files with the UTF-8 BOM removed scanned without
parse errors or findings. Line-ending normalization alone did not fix the warnings.
This is a scanner/encoding observation, not proof
that all other files or rules are free of findings.
