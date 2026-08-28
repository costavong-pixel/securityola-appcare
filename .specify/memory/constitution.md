# SecurityOla AppCare Constitution

## Core principles

### I. Security before speed
AppCare is security-sensitive software. The smallest safe, reversible change is preferred, and no convenience may weaken a trust boundary, tenant boundary, approval gate, or rollback path.

### II. Deterministic evidence before AI claims
Scanner output, worker summaries, model explanations, and generated plans are hypotheses until deterministic tests, source evidence, and independent verification support them. Never report a success state that was not actually observed.

### III. Least privilege and tenant isolation
Every connector, service, worker, database role, environment, and deployment identity receives only the permissions required for its bounded task. Tenant ownership and authorization are enforced by code and tested with cross-tenant negative cases.

### IV. No secrets in artifacts
Credentials, customer data, private infrastructure details, vulnerable-customer evidence, and secret values must not appear in source, logs, prompts, worker packets, checkpoints, tests, issues, or public reports. Presence-only checks and sanitized identifiers are used instead.

### V. Staging, backup, and reversibility before production
Production writes require preserved evidence, a valid backup or snapshot, isolated reproduction, automated validation, explicit policy approval, a known rollback target, and post-change verification. Development and staging never receive production credentials.

### VI. AppCare and WordPress remain separate
AppCare and the SecurityOla WordPress product share no application path, service identity, database, schema, secrets, queues, workers, writable volumes, deployment credentials, logs, backup namespace, or production route. Server actions must explicitly declare `TARGET=AppCare` or `TARGET=WordPress Security`; this project uses only `TARGET=AppCare`.

### VII. Third-party skills are untrusted
A candidate skill is discoverable material until its upstream source, revision, dependencies, permissions, secret handling, sandbox behavior, failure behavior, and regression tests are reviewed. Unsafe or unmaintainable candidates are dropped in favor of AppCare-owned wrappers.

### VIII. Coordinator owns final decisions
The Codex session's primary GPT-5.6 Luna Max coordinator owns architecture, threat-model scope, security policy, dependency and skill acceptance, supportability, deployment logic, merge/release decisions, and final verification. OpenCode/DeepSeek/Qwen workers may perform only bounded delegated tasks and may not approve their own work. Terra escalation is advisory and cannot self-approve release.

### IX. Exact review and CI evidence is required
Every engineering issue closes only after the complete diff, dependency changes, Graphify impact, deterministic tests, security/failure tests, secret scan, independent coordinator/Codex review, exact-head GitHub Actions result, and sanitized Saveruflo checkpoint are recorded. Codex CLI is optional and its absence or lack of authentication is not a blocker.

### X. Product completeness is a security and release invariant
AppCare MUST distinguish a safe core framework from a customer-ready service.

The following rules are binding:

1. A contract is not an implementation.
2. A fixture adapter is not a live adapter.
3. A reference environment is not a customer environment.
4. A persisted boolean is not provider evidence.
5. A backup engine is not customer backup support until a real customer-source adapter feeds it.
6. A monitoring engine is not a monitoring service without real collectors and a durable scheduler.
7. A rollback state machine is not customer rollback support without a real target-specific rollback adapter.
8. A connector is not supported while its live transport is unavailable.
9. A stack is not supported until every mandatory capability in its capability matrix passes.
10. Fixture/reference evidence may prove a component but cannot substitute for mandatory real-target evidence.
11. A real pilot that reveals a missing mandatory capability automatically downgrades every dependent readiness state.
12. Readiness MUST be reported separately as core-platform, stack, customer-onboarding, pilot, and paid-service readiness.
13. No higher-level green status may hide a mandatory lower-level red status.
14. `CUSTOMER_ONBOARDING_READY=YES` requires at least one real external target to complete the mandatory AppCare lifecycle through authoritative verified preproduction.
15. `PILOT_READY=YES` additionally requires an explicitly owner-authorized production deployment, production verification, safe rollback proof, live monitoring, alerting, reporting, restart durability, and real cost measurement.
16. `PAID_SERVICE_READY=YES` additionally requires sustained operations, operator/customer workflows, credential rotation, offboarding, capacity/cost controls, and tested AppCare disaster recovery.
17. `LIVE_CUSTOMER_PRODUCTION_ENABLED` remains globally false; production authority is exact tenant/application/action scoped.

The authoritative gap register and implementation roadmap is `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`. Spec 013 and the subsequent live-capability specs are binding prerequisites for customer readiness.

### XI. Mandatory pre-beta security review
No customer private beta or external beta launch is permitted until `docs/security/PRE_BETA_SECURITY_GATE.md` passes against the exact release candidate.

The gate includes, at minimum, full Codex Security review, final diff review, dependency and secret scans, tenant isolation, authentication/authorization, credential custody, SSH/remote execution, filesystem/archive safety, database safety, backup/restore, scanner execution, remediation/AI boundaries, supply chain, staging isolation, deployment, rollback/data-loss safety, monitoring/SSRF, scheduler/worker safety, dashboard/API/public-edge security, privacy/logging, AppCare/WordPress isolation, denial-of-service/resource controls, AppCare disaster recovery, stack-specific security, and safe real-target adversarial acceptance.

A missing, failed, stale, mismatched, or inconclusive mandatory security result blocks beta readiness. Security findings are not waived merely to meet a launch date.

## Scope and workflow

The historical BETA-00 through BETA-10 queue proved the AppCare core platform. It does not by itself establish customer-service readiness.

The current customer-readiness phase begins with `specs/013-product-readiness/` and continues through the generic live adapters, database, scanning, brownfield normalization, staging/deployment, monitoring/scheduler, WordPress/WooCommerce profiles, live initial-stack connectors, and real-target private-beta gate defined in the authoritative gap register.

Every issue follows:

`Saveruflo preflight -> Graphify query/update -> constitution/specify/clarify/plan/checklist/tasks/analyze/converge as needed -> bounded implementation -> coordinator actual-diff review -> deterministic/security/failure tests -> Codex Security -> exact-head CI -> checkpoint -> Graphify impact review -> protected merge`.

The original supported-stack focus was GitHub, Vercel, Supabase, and Lovable-generated or similar modern web applications. A stack is not now considered live-supported until its current mandatory capability matrix passes. Generic Linux/PHP, WordPress, and WooCommerce support are additional profiles governed by the same core safety requirements.

## Governance

This constitution, `AGENTS.md`, `SECURITY.md`, `ARCHITECTURE.md`, `WORKER_PROTOCOL.md`, `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`, `docs/security/PRE_BETA_SECURITY_GATE.md`, the current Spec Kit feature, and the current GitHub issue are jointly binding. Conflicts are resolved in favor of the stricter security boundary, the product-completeness invariant, and the explicit user instruction.

Any amendment records the reason, affected workflow/readiness gates, security impact, tests, and new version before implementation relies on it.

**Version**: 1.1.0 | **Ratified**: 2026-08-12 | **Last Amended**: 2026-08-27
