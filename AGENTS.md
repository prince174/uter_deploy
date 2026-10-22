# Deployment repository

- All changes belong to this repository. Treat `G:\code\uter` as read-only.
- Never start, stop, rebuild or inspect secrets of the developer's active Uter stack.
- Tests use temporary directories and rendered manifests. Live deployment requires an explicitly selected customer environment.
- Never commit product sources, customer configuration, secrets, model weights or generated archives.
- Example manifests must not be installable. Never invent working image digests or claim untested product images are source-free.
- Maintain both Compose and Helm. Test update failure, rollback compatibility and signature verification.
