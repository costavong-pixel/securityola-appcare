# AppCare Dedicated Backup Filesystem Boundary

## Goal

Make every local AppCare backup and restore rehearsal resolve through one
canonical, tenant-scoped filesystem boundary outside the Git repository.

## Canonical roots

- /var/lib/securityola/appcare/backups
- /var/log/securityola/appcare/backups
- /etc/securityola/appcare/backups
- /var/tmp/securityola/appcare-backups

Data paths are limited to staging, snapshots, manifests, restore rehearsals,
job workspaces, and failed jobs below the canonical backup root. Snapshot,
manifest, restore, and job identifiers are validated as safe single path
segments before any path is constructed.

## Security requirements

- Local data is owned by the non-login appcare-backup identity.
- Config is root-owned and group-readable only by appcare-backup.
- Existing symlinks, traversal, absolute paths, protected project roots, and
  WordPress/Barnd/production paths fail closed.
- Vault reads and deletes require tenant and application scope.
- Restore targets are derived from the canonical restore-rehearsal path and can
  never be production targets.
- B2 and Glacier prefixes are deterministic and contain no credential values.
- Local snapshots are test/recovery evidence only, not authoritative off-site
  backups.

## Acceptance criteria

1. The required VPS directories exist with the requested ownership and modes.
2. Filesystem vault artifacts use
   snapshots/<tenant>/<application>/<backup>/ and manifests/<tenant>/<application>/<backup>.json.
3. Restore rehearsals use
   restore-rehearsal/<tenant>/<application>/<restore_job>/, and job/failed
   paths use validated single segments.
4. Tenant A cannot read, delete, or address tenant B's artifact through the
   filesystem vault.
5. Traversal, absolute paths, unsafe characters, symlinks, repository paths,
   WordPress paths, /root, and /var/www are rejected.
6. Deterministic unit and integration tests, Graphify, Saveruflo, and the
   applicable security/static gates pass without provider credentials or live
   cloud access.
