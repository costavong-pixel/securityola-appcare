# AppCare Product Readiness and Gap Register

Status: **MANDATORY GOVERNANCE**

Owner decision date: 2026-08-27

Target: `AppCare`

This document is the authoritative gap register and completion roadmap for moving AppCare from a proven core platform to a real customer-ready managed service.

It exists because the previous core beta gates proved strong internal contracts, fixtures, reference environments, backup/recovery logic, deployment controls, monitoring state, and release evidence, but did not require one real customer application to complete the entire product promise.

The previous broad statement `PRIVATE_BETA_READY=YES` is revoked.

## Product promise

AppCare must deliver the full lifecycle:

`Scan -> Fix -> Backup -> Monitor -> Recover`

A component, fixture, contract, reference environment, or synthetic rehearsal may prove a subsystem, but it cannot by itself prove customer-service readiness.

## Mandatory readiness levels

Never publish a single ambiguous `READY` state. Use all of the following:

- `CORE_PLATFORM_READY`
- `STACK_READY`
- `CUSTOMER_ONBOARDING_READY`
- `PILOT_READY`
- `PAID_SERVICE_READY`

Current truthful state at adoption:

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

## Product-completeness rules

The following are mandatory:

1. A contract is not an implementation.
2. A fixture adapter is not a live adapter.
3. A reference environment is not a customer environment.
4. A persisted boolean is not provider evidence.
5. A backup engine is not customer backup support until a real source adapter feeds it.
6. A monitoring engine is not a monitoring service without real collectors and a durable scheduler.
7. A rollback state machine is not customer rollback support without a real target-specific rollback adapter.
8. A connector is not `SUPPORTED` while its live transport is unavailable.
9. A supported stack requires every mandatory capability in its capability matrix to pass.
10. Fixture-only acceptance may prove a component but never full customer-service readiness.
11. Any real pilot that reveals a missing mandatory capability automatically downgrades the higher readiness state that depended on it.
12. `PRIVATE_BETA_READY`, `CUSTOMER_ONBOARDING_READY`, or `PILOT_READY` must never be inferred from core release evidence alone.
13. One real external target must complete the mandatory real-target gate before customer beta readiness may become green.
14. Production writes remain disabled until the exact application-scoped owner authorization gate passes.

## Capability matrix required for every supported application

Each application/stack must be evaluated for:

- CONNECT
- INVENTORY
- SOURCE_REVISION
- FILESYSTEM_BACKUP
- DATABASE_BACKUP
- OFFSITE_BACKUP
- REMOTE_READBACK
- ISOLATED_RESTORE
- SECURITY_SCAN
- TEST_DISCOVERY
- STAGING
- REMEDIATION
- DEPLOY
- PRODUCTION_VERIFY
- DATABASE_MIGRATION_SAFETY
- ROLLBACK
- MONITORING
- SCHEDULER
- ALERTING
- REPORTING
- CREDENTIAL_ROTATION
- OFFBOARDING

Allowed capability states:

- `SUPPORTED`
- `NEEDS_CLEANUP`
- `MISSING_CAPABILITY`
- `UNSUPPORTED`
- `BLOCKED_EXTERNAL`

Allowed application supportability states:

- `SUPPORTED`
- `NEEDS_CLEANUP`
- `UNSUPPORTED`

A worker may collect evidence but may not self-approve supportability. The coordinator must resolve supportability from the capability evidence.

## A-Z gap register

### A. Product acceptance gate — P0 — MISSING

The product lacked a top-level acceptance rule requiring a real target to complete the whole service lifecycle. This must be implemented through Spec 013 and the real-target gate.

### B. Machine-readable support matrix — P0 — MISSING

Supportability was discovered ad hoc during pilot attempts. Add a central capability registry and deterministic supportability evaluator.

### C. Live customer connection layer — P0 — MISSING

Implement real customer connectors. First priority is a generic Linux/SSH connector with strict host-key verification, tenant/application binding, timeouts, output caps, least privilege, revocation, and command allowlists. Model output must never become arbitrary production shell execution.

### D. Customer credential vault — P0 — MISSING

Opaque references already exist, but real customer secret custody must be implemented. Secrets must be encrypted, tenant/application scoped, rotatable, revocable, audited, and inaccessible to models/logs/evidence.

### E. Real customer inventory collectors — P0 — MISSING

Collect live OS, web server, runtime, service, application-root, database, port/bind, TLS, storage, deployment, backup, and health metadata through approved bounded collectors.

### F. Immutable revision for brownfield/non-Git sites — P0 — MISSING

Create `CapturedApplicationRevision` from deterministic filesystem/config/runtime/database metadata and hashes. Non-Git sites must still have an immutable identity before remediation/deployment.

### G. Real filesystem backup source — P0 — MISSING

Connect actual customer filesystem data to the existing backup engine. Add include/exclude rules, symlink safety, ownership/permission metadata, large-file streaming, durable-vs-regenerable classification, checksums, and manifests.

### H. Database backup adapters — P0 — MISSING

Implement MariaDB/MySQL and PostgreSQL backup/restore adapters with consistent dump semantics, credential-safe invocation, checksum validation, isolated restore, and post-restore integrity checks.

### I. Real off-site vault runtime — P0 — PARTIAL

B2/Glacier architecture and controlled evidence exist, but customer backup runtime must directly integrate with the authoritative off-site provider boundary rather than depend on isolated rehearsal scripts.

### J. Real customer restore — P0 — PARTIAL

Rebuild files, database, permissions/configuration, and runtime metadata in an isolated restore environment. Separate restore rehearsal from authorized production recovery.

### K. Live security scanners — P0 — MISSING

Keep the existing normalized finding/evidence pipeline but connect it to real bounded source, secret, dependency, permissions, TLS, web-server, service, and exposure scanners.

### L. Test discovery/execution — P0 — MISSING

Discover pytest, PHPUnit/Pest, Composer, npm/pnpm/yarn and other test profiles. `NO_TEST_SUITE` must not become `PASS`. Define safe fallback smoke/security/critical-flow tests.

### M. Brownfield normalization — P0 — MISSING

Legacy direct-filesystem sites should normally be `NEEDS_CLEANUP`, not automatically `UNSUPPORTED`, when AppCare can safely normalize them. Normalization may establish immutable baseline, internal mirror, health probes, versioned releases, rollback references, DB restore, and monitoring profile.

### N. Generic staging builder — P0 — MISSING

Build isolated staging using an approved strategy such as container, isolated directory/service/vhost, or disposable VM. Production email, payments, cron, destructive webhooks, and production credentials must remain disabled or isolated.

### O. Generic remediation for non-Git sites — P0 — PARTIAL

Extend remediation to use `CapturedApplicationRevision` and an AppCare-owned versioned workspace rather than requiring the customer to already use GitHub.

### P. Generic deployment adapters — P0 — MISSING

Implement production-safe deployment strategies such as atomic versioned Linux releases, Docker, and Git-based deployment. Customer direct-filesystem mutation is not an acceptable default production strategy.

### Q. Database migration safety — P0 — MISSING

Classify DB changes as none, reversible, backward-compatible, irreversible, or unknown. Require fresh backup, migration identity, forward/rollback plans, and data-loss risk analysis before deployment.

### R. Real production verification profiles — P0 — MISSING

Per application define HTTP/TLS/service/DB and critical-flow verification. Stack profiles add app-specific flows such as login, API, upload, cart/checkout, or background jobs.

### S. Real rollback adapters — P0 — MISSING

Rollback must restore the exact appropriate files/config/deployment reference and, only when safe, database state. Never blindly restore a database when new transactions may have occurred after deployment.

### T. Live monitoring collectors — P0 — MISSING

Add real collectors for HTTP uptime, TLS expiry, critical flows, service/process, DB connectivity, backup age/integrity, deployment/config changes, and disk capacity. The existing monitoring engine remains the policy/deduplication/persistence layer.

### U. Durable scheduler — P0 — MISSING

Implement PostgreSQL-backed restart-safe scheduling for scans, backups, backup verification, monitoring probes, monthly reports, archive/retention checks, and cost controls. No in-memory-only production scheduler.

### V. Alert delivery/escalation — P1 — MISSING

Deliver alerts to the operator experience and email for beta. Preserve dedupe, suppression, rate limiting, acknowledgement, resolution, escalation, and delivery-failure evidence.

### W. Operator/admin dashboard — P1 — MISSING

Provide a separate operator surface for tenants/apps, supportability, connector health, findings, backups, approvals, deployments, rollback, alerts, incidents, cost/usage, emergency stop, and credentials metadata.

### X. Customer authentication productionization — P1 — PARTIAL

Audit and strengthen login/session recovery, revocation, MFA for privileged operations, roles, approver identity, and app-scoped authorization before external customers.

### Y. Public HTTPS customer control plane — P1 — MISSING

Before public exposure, require TLS, reverse proxy hardening, trusted hosts, rate limiting, CSP/security headers, request limits, safe logs/errors, and abuse controls. DNS changes remain owner-authorized.

### Z. Real-target vertical acceptance — P0 — MISSING

A real external target must complete the mandatory end-to-end lifecycle described below. Fixture substitution is forbidden for the final customer readiness gate.

## Additional paid-service gaps

The following may not block the first internal pilot but do block `PAID_SERVICE_READY=YES`:

- customer onboarding/offboarding and post-cancellation retention
- subscription/billing lifecycle and service suspension policy
- AppCare control-plane disaster recovery
- AppCare service observability/SLOs
- support/on-call Tier 1/2/3 playbook
- data retention/privacy/export/deletion policy
- capacity, concurrency, quota, and cost controls
- provider outage/partial-failure handling
- credential recovery/rotation drills

## Required implementation specs

The following sequence is mandatory:

1. `specs/013-product-readiness/`
2. `specs/014-generic-linux-ssh/`
3. `specs/015-database-adapters/`
4. `specs/016-live-scanning/`
5. `specs/017-brownfield-normalization/`
6. `specs/018-customer-staging-deploy/`
7. `specs/019-live-monitoring-scheduler/`
8. `specs/020-wordpress-profile/`
9. `specs/021-woocommerce-profile/`
10. `specs/022-live-initial-stack-connectors/`
11. `specs/023-real-target-private-beta-gate/`

Each feature spec must include, unless demonstrably inapplicable:

- `spec.md`
- `plan.md`
- `research.md`
- `data-model.md`
- `quickstart.md`
- `tasks.md`
- `checklists/requirements.md`
- `contracts/`

Thin or fixture-only specs cannot close a live-readiness capability.

## Mandatory implementation waves

### Wave 1

- Spec 013 product-readiness governance
- Spec 014 generic Linux/SSH
- Spec 015 DB adapters

### Wave 2

- real filesystem backup source
- real B2 runtime integration
- Spec 016 live scanning

### Wave 3

- Spec 017 brownfield normalization
- Spec 018 staging/deploy/rollback/migration safety

### Wave 4

- Spec 019 live monitoring/scheduler/alerts

### Wave 5

- Spec 020 WordPress profile
- Spec 021 WooCommerce profile

### Wave 6

- Spec 022 prove live GitHub/Supabase and Vercel read-only integration; provider-specific Vercel deployment limitations remain separately tracked

### Wave 7

- Spec 023 real-target acceptance

Every wave requires coordinator architecture review, deterministic/negative/security tests, Codex Security, Graphify, Saveruflo, exact-head CI, and protected merge before the next readiness state can advance.

## Mandatory real-target gate

A real target must demonstrate, in order:

1. CONNECT
2. INVENTORY
3. SUPPORTABILITY
4. IMMUTABLE REVISION
5. FILESYSTEM BACKUP
6. DATABASE BACKUP
7. OFF-SITE B2 UPLOAD
8. REMOTE READBACK
9. CHECKSUM VERIFICATION
10. ISOLATED RESTORE
11. RESTORE VALIDATION
12. LIVE SECURITY SCAN
13. SAFE EVIDENCE-BACKED FINDING
14. REMEDIATION WORKSPACE
15. MINIMAL FIX
16. TESTS
17. SECURITY TESTS
18. ISOLATED STAGING
19. CRITICAL-FLOW VERIFICATION
20. AUTHORITATIVE PREPRODUCTION RECEIPT
21. ROLLBACK READY
22. PRODUCTION AUTHORIZATION PACKAGE

Then stop for explicit owner authorization of the first production mutation.

After authorization:

23. EXACT APPLICATION-SCOPED PRODUCTION AUTHORIZATION
24. CONTROLLED DEPLOY
25. PRODUCTION VERIFICATION
26. SAFE ROLLBACK PROOF
27. ROLLBACK VERIFICATION
28. LIVE MONITORING
29. ALERT TEST
30. BACKUP-HEALTH MONITOR
31. CUSTOMER REPORT
32. OPERATOR REPORT
33. APPCARE RESTART
34. DURABLE-STATE VERIFICATION
35. REAL COST MEASUREMENT

A rollback drill must not intentionally cause a needless production outage. Use staging or an explicitly safe reversible production mutation unless the owner separately authorizes a controlled production failure drill.

## Current real-target evidence

`slabfranchise.com` and `video.slabfranchise.com` exposed the missing generic customer adapter layer. Those discovery results are evidence of readiness gaps, not permission to modify production.

`video.slabfranchise.com` is the intended first real acceptance target after the generic capability layer exists. Its current brownfield traits include direct filesystem deployment, no Git checkout/immutable revision, MariaDB, no atomic rollback, and no verified AppCare off-site application backup. Production cleanup findings must not be changed until backup, revision capture, staging, and rollback capabilities exist.

## Readiness transitions

- `STACK_GENERIC_LINUX_READY=YES` only after the mandatory generic capabilities pass.
- `STACK_WORDPRESS_READY=YES` only after the WordPress profile passes on top of generic Linux/PHP support.
- `STACK_WOOCOMMERCE_READY=YES` only after WooCommerce data/transaction safety and critical-flow gates pass.
- `CUSTOMER_ONBOARDING_READY=YES` only after the real-target gate passes through authoritative preproduction.
- `PILOT_READY=YES` only after an explicitly owner-authorized real pilot production deployment, verification, rollback proof, monitoring, and reporting pass.
- `PAID_SERVICE_READY=YES` only after sustained backup/monitoring operation, operator burden/cost measurement, auth/dashboard readiness, offboarding, credential rotation, and AppCare disaster recovery are proven.

## Governance

This register is binding through the AppCare constitution. It may be amended only through protected PR review with the reason, affected readiness gates, security impact, tests, and exact-head CI evidence recorded.
