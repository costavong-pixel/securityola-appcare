# Development Workflow

## Required workflow tools

- `/speckit` — specification-driven development
- `/saveruflo` — bounded repository preflight/checkpoints/review workflow
- LangGraph — resumable long-running operational workflows
- `/impeccable` — website/portal design QA after functionality works

## BETA-01 isolated control plane

The BETA-01 API is development/staging-only. Run it only with an AppCare-owned
SQLite database or an explicitly isolated AppCare development PostgreSQL
database:

```powershell
$env:APPCARE_ENVIRONMENT = "development"
$env:APPCARE_DATABASE_URL = "sqlite+pysqlite:///./appcare-dev.db"
python -m uvicorn appcare.api:app --host localhost --port 8000
```

For PostgreSQL, set the non-secret `APPCARE_DATABASE_ALLOWED_HOSTS` variable
to a comma-separated list of exact AppCare database hostnames. The database
name must match the environment exactly: `appcare_development`,
`appcare_staging`, or `appcare_test`. A missing or unmatched host/name is
rejected before SQLAlchemy creates an engine or schema.

Do not set the database URL to a production, WordPress Security, Barnd AI
Shield, deployment, or shared-server database. BETA-01 has no provider-write
or deployment execution route, and development jobs must not receive
production credentials.

The BETA-01 acceptance tests cover invalid/expired/disabled authentication,
cross-tenant resource and operation denial, restart durability, job state
transitions, audit hash-chain immutability, health/readiness failure behavior,
secret-safe validation errors, and the absence of production write routes:

```powershell
pytest -q tests/contract tests/integration tests/unit
```

Before promotion, run the complete deterministic and security gates listed in
the feature quickstart. The independent Codex final review is performed by the
current Codex agent/app/cloud session or GitHub Codex review; Codex CLI is
optional and is not a blocker.

## Third-party skill policy

Candidate skill sources may include official vendor repositories, GitHub skill collections, and discovery registries.

Every imported skill must pass:

1. source and dependency inspection
2. permission and secret-handling review
3. disposable sandbox run
4. failure and pressure testing
5. patch/debug if necessary
6. regression retest
7. exact commit/version pinning
8. periodic re-audit

If a skill cannot be fixed safely, drop it.

## Candidate skill areas

- security testing
- Supabase security
- Vercel deployment/rollback
- database backup/restore
- S3/B2/Glacier lifecycle
- monitoring
- failure-injection testing

## BETA-02 connector and inventory checks

Run the isolated synthetic provider tests before the full suite:

```powershell
pytest -q tests/unit/test_connectors.py tests/integration/test_read_only_connectors.py tests/integration/test_asset_inventory.py
```

The fixtures use opaque credential references only. They do not authorize or
contact GitHub, Vercel, or Supabase. Inventory reconciliation writes only
tenant-scoped AppCare `Asset` rows and is additive/idempotent; it never writes
to a provider or accepts a customer secret.
