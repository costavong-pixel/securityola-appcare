# SecurityOla AppCare

SecurityOla AppCare is a managed security and recovery service for websites and web applications.

## Core promise

**Scan -> Fix -> Backup -> Monitor -> Recover**

## Current readiness

The AppCare core platform is mature, but customer onboarding is not yet beta-ready. Historical fixture/reference acceptance must not be interpreted as live customer support.

```text
CORE_PLATFORM_READY=YES
STACK_GENERIC_LINUX_READY=NO
STACK_WORDPRESS_READY=NO
STACK_WOOCOMMERCE_READY=NO
STACK_GITHUB_VERCEL_SUPABASE_READY=NO
CUSTOMER_ONBOARDING_READY=NO
PILOT_READY=NO
PAID_SERVICE_READY=NO
LIVE_CUSTOMER_PRODUCTION_ENABLED=NO
```

Mandatory governance:

- `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`
- `docs/security/PRE_BETA_SECURITY_GATE.md`
- `.specify/memory/constitution.md`
- `specs/013-product-readiness/`

No customer/private-beta readiness claim may bypass those documents.

## Stack roadmap

Initial/core focus included:

- Lovable-style web apps
- GitHub source repositories
- Vercel deployments
- Supabase database/auth/storage

The customer-readiness phase also adds reusable generic Linux/SSH, filesystem, MariaDB/MySQL/PostgreSQL, brownfield normalization, staging/deployment/rollback, live monitoring/scheduling, WordPress, and WooCommerce profiles.

A stack is considered supported only when its mandatory capability matrix passes. A connector contract or fixture does not equal live support.

## Control plane

The control plane provides tenant-scoped records, authentication, durable jobs, append-only sanitized audit history, and truthful liveness/readiness checks. Provider credential values must not be stored in descriptive resource records.

Run the isolated acceptance suite from this checkout with:

```powershell
pytest -q
```

Use only an AppCare-owned development SQLite database or an explicitly isolated AppCare development PostgreSQL database. For PostgreSQL, configure the non-secret `APPCARE_DATABASE_ALLOWED_HOSTS` variable with exact allowed host names and use the environment-specific database name (`appcare_development`, `appcare_staging`, or `appcare_test`). The application rejects missing or unmatched host/name targets before engine/schema initialization. Never point the local API at shared, production, WordPress Security, or deployment resources.

## Commercial offer

- **Free Check** — external/basic scan
- **Launch & Fix** — $799 one-time starting offer
- **Protection** — $149/month after onboarding approval
- **Emergency Assessment** — $199, credited toward recovery if accepted
- **Emergency Recovery** — from $999 for supported, bounded incidents
- **Complex incidents** — custom quote

Commercial pricing does not imply technical supportability. Paid service cannot launch until the paid-service readiness gate passes.

## Production rule

No production fix without:

1. authoritative evidence,
2. valid backup and verified restore path,
3. staging or isolated reproduction,
4. automated regression/security validation,
5. authoritative verified preproduction evidence,
6. exact application-scoped production authorization,
7. production verification,
8. rollback path,
9. monitoring.

Global `LIVE_CUSTOMER_PRODUCTION_ENABLED` remains `NO`.

## Third-party skills

Third-party skills are never trusted by default.

**Inspect -> sandbox -> pressure-test -> patch/debug -> retest -> pin -> use**

If a skill cannot be made safe and maintainable, drop it.

## Historical connector foundation

The original connector slice added provider-neutral, fixture-backed read-only contracts for GitHub, Vercel, and Supabase. It established capability, ownership, tenant-isolation, and credential-metadata boundaries, but intentionally did not prove every live provider transport or customer deployment path.

Live provider/customer support is now governed by the product-readiness capability matrix and real-target acceptance gate.
