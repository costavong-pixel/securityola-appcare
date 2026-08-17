# BETA-04 Off-site Backup and Restore Testing

## Goal

Make recovery verifiable before AppCare is allowed to modify customer
production. A backup is healthy only after the encrypted artifact, manifest,
checksums, retention policy, and isolated restore have been verified.

## Scope

The first slice defines a provider-neutral backup domain and a deterministic
controlled-test-app rehearsal. It supports descriptors for a Backblaze B2
recent-backup destination and an AWS S3 Glacier Deep Archive destination, but
does not perform live cloud uploads until owner-controlled credentials, vault
ownership, Object Lock policy, and cost/retention settings are supplied
through the approved secret boundary.

In scope:

- tenant/application/environment-safe backup targets;
- Git/source, database, storage/file, and deployment/config snapshot components;
- authenticated encryption through an injected envelope-encryptor boundary;
- manifest and artifact SHA-256 checksums with read-back verification;
- immutable-retention semantics and append-only job evidence;
- isolated restore staging with atomic promotion and no production writes;
- canonical, symlink-free restore/vault roots and safe backup path segments;
- explicit failed/unhealthy states for upload, integrity, credential, duplicate,
  partial-restore, and retention failures;
- RPO/RTO evidence for controlled rehearsals;
- seeded synthetic fixtures and pressure tests.

Out of scope:

- reading `.env`, provider credential values, customer data, or WordPress paths;
- live B2, AWS, Supabase, Vercel, GitHub, or production API calls;
- remediation, deployment, deletion of locked cloud objects, or AI recovery
  decisions;
- claiming that a destination is off-site merely because a local test vault
  passed.

## Acceptance criteria

1. A complete synthetic AppCare test application can be encrypted, stored in an
   isolated vault, read back, checksum-verified, and restored into a new
   isolated directory.
2. The restored component set and each component digest match the source
   manifest; a partial or corrupt restore fails closed and does not promote a
   partial result.
   Persisted test-vault artifacts remain readable and verifiable after a vault
   object is reopened.
3. A failed upload, checksum mismatch, unavailable/revoked credential, or
   duplicate idempotency key produces an unhealthy backup/job result, never a
   healthy backup.
4. Retention lock prevents deletion before expiry and records the rejection;
   the backup job history is append-only and contains no raw credentials.
5. RPO/RTO evidence is recorded for the controlled rehearsal without claiming
   live-provider or customer-production evidence.
6. B2 and Glacier destination descriptors require safe namespaces, immutable
   retention, and opaque credential references; no SDK or live provider access
   is introduced without a separately reviewed integration.
7. WordPress and `/var/www/api.securityola.com` remain untouched.

## User stories

### US1 — Verified backup artifact

As AppCare, I need an encrypted, checksummed manifest and artifact so that
backup existence is never mistaken for backup health.

### US2 — Controlled restore rehearsal

As AppCare, I need a restore to an isolated test application so that recovery
evidence includes verified content and timing rather than an object listing.

### US3 — Fail-closed recovery evidence

As AppCare, I need failures and retention decisions represented separately from
healthy backups so that operators cannot proceed on false recovery confidence.
