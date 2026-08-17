# Architecture

## Server/runtime isolation

SecurityOla AppCare is a separate product runtime from the SecurityOla WordPress plugin and its in-progress backend.

### Hard boundary

AppCare must use its own:
- server/application runtime
- OS/service user
- repository checkout and deployment path
- environment/secrets
- PostgreSQL database and credentials
- queues/cache/workers
- containers/networks/volumes
- logs and observability namespace
- GitHub/provider credentials
- backup buckets/prefixes and encryption credentials
- AppCare-specific hostnames/API endpoints

Do not share with the WordPress product:
- database/schema
- `.env` files
- writable volumes
- queue/worker state
- deploy keys or SSH credentials
- application service account
- production API routes
- backup credentials

The WordPress plugin/backend remains untouched unless a future explicit integration specification is approved.

### AppCare environments

Within the AppCare server/runtime keep separate environments:

`development → staging → production`

At minimum each environment must have separate configuration, database/schema boundary, secrets, worker/job namespace, and deployment identity. Production credentials must never be available to development jobs.

## Repair workflow

Alert/scan
→ preserve evidence
→ create backup
→ reproduce in staging/isolation
→ prepare fix
→ run tests/security validation
→ approve
→ deploy
→ verify production
→ rollback on failed verification
→ continue monitoring

## Backup strategy

Primary recent backup:
- Backblaze B2
- Object Lock / immutable retention where supported

Long-term archive:
- AWS S3 Glacier Deep Archive

Rules:
- backups remain outside the customer's production server/account
- restore testing is required; backup existence alone is not sufficient
- AppCare backup storage/credentials remain separate from the WordPress product

## Initial supported stack

- GitHub
- Vercel
- Supabase
- Lovable-generated or similar web apps

Custom or messy infrastructure is assessed before acceptance.

## BETA-02 read-only connector boundary

The first supported-stack connector slice is intentionally provider-neutral:

- immutable provider capability specifications for GitHub, Vercel, and Supabase;
- metadata-only credential lifecycle with expiry, revocation, and rotation;
- injected/fixture snapshots for deterministic health, permission, inventory,
  and ownership checks;
- stable normalization and additive reconciliation into tenant-owned AppCare
  assets.

No live transport, OAuth callback, provider write method, deployment method,
database query executor, or secret-vault implementation is part of this slice.
Those require a separate owner-authorized integration design.
