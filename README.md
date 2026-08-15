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
AppCare development PostgreSQL database. Never point the local API at shared,
production, WordPress Security, or deployment resources.

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
