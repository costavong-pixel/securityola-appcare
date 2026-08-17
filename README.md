# SecurityOla AppCare

SecurityOla AppCare is a managed security and recovery service for AI-built websites and web applications.

## Core promise

**Scan → Fix → Backup → Monitor → Recover**

Initial focus:
- Lovable-style web apps
- GitHub source repositories
- Vercel deployments
- Supabase database/auth/storage

## BETA-01 control plane

BETA-01 provides a development/staging-only FastAPI control plane with
tenant-scoped records, local short-lived authentication, durable jobs,
append-only sanitized audit history, and truthful liveness/readiness checks.
Connector, backup, approval, and deployment records are descriptive state only;
they do not contain provider credentials or execute production actions.

Run the isolated acceptance suite from this checkout with:

```powershell
pytest -q
```

Use only an AppCare-owned development SQLite database or an explicitly isolated
AppCare development PostgreSQL database. For PostgreSQL, configure the
non-secret `APPCARE_DATABASE_ALLOWED_HOSTS` variable with exact allowed host
names and use the environment-specific database name (`appcare_development`,
`appcare_staging`, or `appcare_test`). The application rejects missing or
unmatched host/name targets before engine/schema initialization. Never point
the local API at shared, production, WordPress Security, or deployment
resources.

## Commercial offer

- **Free Check** — external/basic scan
- **Launch & Fix** — $799 one-time starting offer
- **Protection** — $149/month after onboarding approval
- **Emergency Assessment** — $199, credited toward recovery if accepted
- **Emergency Recovery** — from $999 for supported, bounded incidents
- **Complex incidents** — custom quote

## Production rule

No production fix without:
1. backup/snapshot,
2. staging or isolated reproduction,
3. automated validation,
4. production verification,
5. rollback path.

## Third-party skills

Third-party skills are never trusted by default.

**Inspect → sandbox → pressure-test → patch/debug → retest → pin → use**

If a skill cannot be made safe and maintainable, drop it.

## BETA-02 read-only connectors

BETA-02 adds provider-neutral, fixture-backed read-only connector contracts for
GitHub, Vercel, and Supabase. The boundary checks explicit read capabilities,
credential expiry/revocation metadata, application/domain ownership, and
deterministic inventory. It may reconcile observed records into tenant-owned
AppCare assets, but it has no provider deployment, mutation, deletion, SQL
execution, OAuth, or live customer transport path.

The provider mappings are documented in
`specs/002-read-only-connectors/contracts/api.md`. Live provider authorization,
transport, and secret-vault custody remain later owner-controlled gates.
