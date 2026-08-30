# SecurityOla AppCare

SecurityOla AppCare is a managed security, backup, monitoring, remediation, deployment-safety, and recovery service for supported websites and web applications.

## Core promise

**Scan -> Fix -> Backup -> Monitor -> Recover**

## Binding current implementation blueprint

Current implementation is governed by:

- `APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md`
- `docs/governance/APPCARE_CURRENT_SCOPE.json`
- `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`
- `docs/security/PRE_BETA_SECURITY_GATE.md`
- `.specify/memory/constitution.md`
- `specs/013-product-readiness/`

The blueprint defines 12 dependency-ordered phases, hard exit gates, maturity labels, the first supported stack, the first real acceptance target, and current future-branch exclusions.

No customer/private-beta readiness claim may bypass those documents.

## Current supported profile

The first supported beta profile is deliberately narrow:

- Linux-hosted PHP 8.x;
- Nginx or Apache;
- MariaDB/MySQL;
- direct-filesystem deployment after AppCare normalization;
- Git-based deployment after exact revision/artifact binding.

First real acceptance target:

```text
video.slabfranchise.com
```

WordPress and WooCommerce are documented future branches. Their current implementation is prohibited until separate owner authorization.

Vercel Issue #30 remains separate and is not on the current Linux/PHP critical path.

## Mandatory maturity reporting

Every component must be reported as exactly one of:

```text
DOCUMENTED
COMPONENT_IMPLEMENTED
RUNTIME_INTEGRATED
LIVE_VERIFIED
SERVICE_READY
```

The word `IMPLEMENTED` must not be used alone as a readiness claim.

## Current readiness

The AppCare core platform is mature, but customer onboarding is not beta-ready. Historical fixture/reference acceptance must not be interpreted as live customer support.

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

## Current critical path

```text
P01 Blueprint/enforcement
→ P02 Credential custody/SSH onboarding
→ P03 Live connect/inventory/immutable baseline
→ P04 Streaming filesystem backup
→ P05 Live MariaDB backup/restore
→ P06 B2/Glacier/full application restore
→ P07 Live scanning/test discovery
→ P08 Brownfield normalization/staging/remediation
→ P09 Deploy/verify/migration safety/rollback
→ P10 Monitor/schedule/alert/report
→ P11 Operator/commercial/offboarding/AppCare DR
→ P12 Real-target/S01-S30/pilot decision
```

## Control plane

The control plane provides tenant-scoped records, authentication, durable jobs, append-only sanitized audit history, readiness evaluation, evidence binding, and dashboard state. Provider credential values must not be stored in descriptive resource records.

Run the isolated acceptance suite with:

```powershell
pytest -q
```

Use only an AppCare-owned development SQLite database or an explicitly isolated AppCare development PostgreSQL database. Never point a local API at shared, production, WordPress Security, or deployment resources.

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

1. authoritative evidence;
2. valid backup and remote readback;
3. verified isolated restore path;
4. staging or isolated reproduction;
5. automated regression/security validation;
6. authoritative verified preproduction evidence;
7. exact application-scoped production authorization;
8. production verification;
9. rollback readiness;
10. monitoring.

Global `LIVE_CUSTOMER_PRODUCTION_ENABLED` remains `NO`.

## Shared-product boundary

AppCare and the SecurityOla WordPress Security product may share physical infrastructure but remain separate products and runtimes. AppCare work must not touch WordPress product files, DBs, services, credentials, logs, or backup namespaces.

## Third-party skills

Third-party skills are never trusted by default.

**Inspect -> sandbox -> pressure-test -> patch/debug -> retest -> pin -> use**

Drop any skill that cannot be made safe, maintainable, and testable.
