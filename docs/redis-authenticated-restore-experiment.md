# Experimental Redis snapshot restoration

This is a development experiment, not a procedure to recover an installation.
It does not authorize backup, update, cutover or resumed writes. The preparation
result explicitly reports `safe_to_update: false` and `safe_to_resume: false`.

The disposable [GitHub Actions run 41136992708](https://github.com/prince174/uter_deploy/actions/runs/41136992708)
passed for commit `27cd4d8`. It started two separate instances of the same
digest-pinned Redis image on an ephemeral hosted runner, using a new labeled
Docker bridge network and host ports bound to `127.0.0.1`. The test trusts that
runner, its host and Docker daemon; this network is not a security boundary
against them. Credentials, data and backup encryption keys were synthetic.

The source instance held six keys over two databases: string, hash, list, set
and sorted-set values, with one absolute expiry 15 minutes in the future. With
no further fixture writes, the test used `SAVE` to generate an RDB and stored
it in an encrypted, HMAC-authenticated backup set. The other two components
were synthetic placeholders, not complete Uter runtime or audit data. After
authenticating the entire backup and checking its installation identity and
version, the test loaded the RDB into a newly created target Redis directory.

The test compared HMAC fingerprints from the source and target, as well as a
second source fingerprint. The fingerprint includes each key's Redis `DUMP`
representation and absolute `PEXPIRETIME` across all 16 configured databases;
the target's expiry was also checked against the fixture timestamp. The chosen
image and values produced equal representations. `DUMP` representation
equality is a conservative same-image test, not a guarantee that every pair of
logically equivalent values or every Redis version has identical bytes.
Modules and Redis Functions are rejected by this fingerprint implementation.

The run also rejected a modified encrypted RDB before starting the target.
Unit tests cover changed identity or version, wrong key, missing components,
tampered manifest, Redis, runtime and audit components, and bounded input.
They exercise failure-closed cleanup without touching a local Docker daemon.
Cleanup of the test containers and network uses verified immutable IDs and
random labels and must complete before the CI reports success.

This does not prove consistency of a backup taken from a running service,
fencing or quiescence of actual writers, migration to a different Redis build,
restoration of an actual Uter installation, crash recovery, backup-key custody,
or data surviving a cutover. The preparation helper assumes a trusted caller
and a locally controlled backup directory protected from concurrent changes and
denial of service. No production path calls this helper.

## Combined fixture evidence

The later [run 41137654093](https://github.com/prince174/uter_deploy/actions/runs/41137654093)
at commit `e8e2179` exercised the experimental evidence combiner against one
synthetic operation and one authenticated backup manifest. It bound the Redis
observation and the audit comparison to the same operation, plan, installation,
backup ID, manifest and component hashes. It also checked the fixture Guardrail
receipt, boot and image/bundle identity. Separate HMAC purposes protect the
records, and mismatch or damaged backup tests refuse the combination. The result
still reports `safe_to_update: false` and `safe_to_resume: false`.

This run restored the synthetic RDB to a real disposable Redis and compared
data and expiry as described above. **Its audit verifier, publisher trust and
operation lock were mocked.** It did not validate an actual signed bundle or
an actual audit chain alongside that Redis restore. The separate
[audit comparison experiment](audit-backup-comparison-experiment.md) did
exercise strict verification in a protected Guardrail image, but combining
the results of separate runs does not prove an integrated recovery.
