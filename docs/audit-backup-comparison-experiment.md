# Experimental audit backup comparison

This is a development experiment, not a user installation or recovery procedure.
It does not authorize a backup, update or restore. The verifier is not connected
to the live update gate; its result always says `safe_to_backup: false` and
`safe_to_update: false`.

The isolated [GitHub Actions run 41136233556](https://github.com/prince174/uter_deploy/actions/runs/41136233556)
passed on commit `bd45ba8`. It loaded the protected Guardrail image from the
successful [snapshot build 41114430468](https://github.com/prince174/uter_deploy/actions/runs/41114430468),
checked the image configuration ID against that artifact, and ran the image by
that immutable ID. The run generated synthetic keys, audit events, a receipt,
an encrypted backup, and a locally signed fixture bundle on the disposable
runner. The fixture signature and image-reference placeholder are not a
publisher signature or registry manifest digest. Trust in the snapshot artifact
also depends on trusting the authors and definition of the workflow that made
it; matching its metadata is not independent provenance verification.

The image generated a rotated audit set and a terminal receipt. The test checked
that this exact build exposes `strict=True`, invoked it with the complete set
and synthetic audit key, and matched the terminal sequence and hash against the
authenticated fixture receipt. It also required a complete numbered rotation
set with a genesis entry and refused an omitted oldest file, swapped files,
modified content and a modified HMAC. These negative cases are rejected by the
comparison's combined checks; they do not all prove which individual check
detected the change. Nine unit tests ran in the same CI job.

The comparison binds its recorded result to the authenticated operation,
backup, image and bundle checksums and writes a separate authenticated evidence
file. Its `strict_auditor` callback is a trusted dependency of this experiment;
the hosted adapter supplies the protected image, but the library itself does
not enforce an image-execution boundary. The local backup directory must be
controlled against concurrent modification and denial of service.

The profile requires all history back to the original genesis. It deliberately
rejects an otherwise valid retained set if earlier rotations have expired under
normal retention. A later design would need an independently authenticated
pre-quiesce inventory and a defensible continuity policy before accepting a
truncated retained history. Strict audit checking does not by itself prove
that the snapshot was taken atomically or that no writer was active.

This run did not exercise live traffic fencing, real Redis isolation, an actual
installation's backup, Compose or Kubernetes recovery, restoration of audit
data, resumed writers, or compatibility between product versions. Those remain
separate work. Earlier published executors also do not acquire the restrictions
in the current repository automatically.
