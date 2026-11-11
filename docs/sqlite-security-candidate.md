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

An independent recheck downloaded `libsqlite3-0=3.54.1-2` from the signed
Debian sid repository and compared its unpacked library SHA-256 to the library
inside both local candidate images. Both matched
`225ceb839db2c1dd484cfcaa5ef9fbdd429eb1d5f1e0c39fbd50150bca5fc7bc`.
The tracker marks 3.54.1-2 fixed for CVE-2026-119373, CVE-2026-119374 and
CVE-2026-119379. This is provenance and version evidence for those CVEs only;
it does not establish full image safety, stable support, application compatibility,
or permission to bypass the release gate.

The experimental CI also writes a separate assessment for each image.
It binds the raw Trivy image ID to the loaded SQLite version and exact library hash,
rejects any other High/Critical or secret finding, and retains all three raw High
findings. Its `release_gate_passed` field is always false. The existing strict gate
remains unchanged and is recorded as failed. On explicit manual dispatch only, a
separate, authorised VEX gate may publish unique candidate tags after the exact
image ID, loaded SQLite version and library SHA-256, all raw findings, source
archive audit, and Compose acceptance and restart tests have been checked. Only the
three documented SQLite CVEs qualify; any other High, Critical or secret fails.
Raw Trivy reports and the per-image OpenVEX records are retained. These tags are
not a signed deployment release and do not change the published stable manifest.

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
