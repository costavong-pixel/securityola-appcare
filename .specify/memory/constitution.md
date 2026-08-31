# SecurityOla AppCare Constitution

## Core principles

### I. Security before speed
AppCare is security-sensitive software. The smallest safe, reversible change is preferred, and no convenience may weaken a trust boundary, tenant boundary, approval gate, recovery path, or phase dependency.

### II. Deterministic evidence before AI claims
Scanner output, worker summaries, model explanations, and generated plans are hypotheses until deterministic tests, source evidence, and independent verification support them. Never report a success or maturity state that was not actually observed.

### III. Least privilege and tenant isolation
Every connector, service, worker, database role, environment, and deployment identity receives only the permissions required for its bounded task. Tenant ownership and authorization are enforced by code and tested with cross-tenant negative cases.

### IV. No secrets in artifacts
Credentials, customer data, private infrastructure details, vulnerable-customer evidence, and secret values must not appear in source, logs, prompts, worker packets, checkpoints, tests, issues, or public reports. Presence-only checks and sanitized identifiers are used instead.

### V. Staging, backup, and reversibility before production
Production writes require preserved evidence, a mandatory pre-change backup, remote readback, verified restore viability, isolated reproduction, automated validation, explicit application-scoped approval, a known rollback target, and post-change verification. Development and staging never receive production credentials or production side effects.

### VI. AppCare and WordPress remain separate
AppCare and the SecurityOla WordPress product share no application path, service identity, database, schema, secrets, queues, workers, writable volumes, deployment credentials, logs, backup namespace, or production route. Server actions must explicitly declare `TARGET=AppCare` or `TARGET=WordPress Security`; this project uses only `TARGET=AppCare`.

WordPress and WooCommerce are future branches under the current owner-approved scope. Their implementation requires separate owner authorization.

### VII. Third-party skills are untrusted
A candidate skill is discoverable material until its upstream source, revision, dependencies, permissions, secret handling, sandbox behavior, failure behavior, and regression tests are reviewed. Unsafe or unmaintainable candidates are dropped in favor of AppCare-owned wrappers.

### VIII. Coordinator, coder routing, and reviewer roles are independent
GPT-5.6 Luna Max is the primary coordinator and owns dependency planning, architecture integration, task packets, coder-lane routing, acceptance criteria, actual-diff review, trust-boundary approvals, readiness decisions, and final owner-facing reports.

GPT-5.3 Spark is the preferred coder for bounded Luna-approved tasks while included Spark quota is available. Spark cannot approve its own work, set readiness, merge, or authorize production.

When Spark quota is limited, exhausted, or unavailable, the owner-approved fallback is:

```text
GPT-5.6 Luna Max coordinator
→ Prompt Ola VPS
→ direct DeepSeek worker
→ owner's DeepSeek API
```

For the direct DeepSeek route, Codex Spark quota is not involved and the OpenAI API is not involved. The DeepSeek API credential remains in protected server-side custody and must never enter prompts, task packets, Git, GitHub, normal logs, CI artifacts, evidence, or reports. DeepSeek cannot approve itself, set architecture/readiness, merge, authorize production, or widen scope.

The Prompt Ola VPS is only a worker host for this route. AppCare work must use a dedicated isolated AppCare checkout/worktree and state directory and must not read or modify Prompt Ola production files, databases, services, credentials, logs, or deployment paths.

The existing `scripts/deepseek-worker.sh` uses an OpenCode-routed model and is not automatically evidence of the direct DeepSeek API route. The direct launcher/provider must be independently built or safely adapted, tested, reviewed, and exact-head qualified before it can be reported as runtime-integrated.

GPT-5.6 Terra is the independent architecture/security challenger. Terra does not merge or self-approve a fix it authored.

Codex Security remains an independent scan and verification lane. Auxiliary OpenCode/Qwen workers may perform bounded delegated work but cannot replace Luna, Terra, or Codex Security.

### IX. Exact review and CI evidence is required
Every engineering issue closes only after the complete diff, dependency changes, Graphify impact, deterministic tests, security/failure tests, secret scan, independent Luna/Terra/Codex review as applicable, exact-head GitHub Actions result, and sanitized Saveruflo checkpoint when available are recorded. Unavailable tooling is reported as `UNAVAILABLE`, never fabricated as `PASS`.

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
14. `CUSTOMER_ONBOARDING_READY=YES` requires the approved real target to complete the mandatory AppCare lifecycle through authoritative verified preproduction.
15. `PILOT_READY=YES` additionally requires an explicitly owner-authorized production deployment, production verification, safe rollback proof, live monitoring, alerting, reporting, restart durability, credential rotation, offboarding proof, and real cost measurement.
16. `PAID_SERVICE_READY=YES` additionally requires sustained operations, operator/customer workflows, billing/cancellation, external secret custody, capacity/cost controls, and tested AppCare disaster recovery.
17. `LIVE_CUSTOMER_PRODUCTION_ENABLED` remains globally false; production authority is exact tenant/application/action scoped.
18. Every component must report one maturity level: `DOCUMENTED`, `COMPONENT_IMPLEMENTED`, `RUNTIME_INTEGRATED`, `LIVE_VERIFIED`, or `SERVICE_READY`.
19. The unqualified word `IMPLEMENTED` is not a valid readiness report.
20. Every implementation phase has a hard exit gate, and no readiness state may bypass a failed dependency.

The authoritative current implementation dependency plan is `APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md`, with machine-readable scope in `docs/governance/APPCARE_CURRENT_SCOPE.json`. Model/coder lane selection is governed by `docs/governance/APPCARE_MODEL_EXECUTION_ROUTING.md` and `docs/governance/APPCARE_MODEL_EXECUTION_ROUTING.json`. The broad gap backlog remains `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`.

### XI. Mandatory pre-beta security review
No customer private beta or external beta launch is permitted until `docs/security/PRE_BETA_SECURITY_GATE.md` passes against the exact release candidate.

The gate includes, at minimum, full Codex Security review, final diff review, dependency and secret scans, tenant isolation, authentication/authorization, credential custody, SSH/remote execution, filesystem/archive safety, database safety, backup/restore, scanner execution, remediation/AI boundaries, supply chain, staging isolation, deployment, rollback/data-loss safety, monitoring/SSRF, scheduler/worker safety, dashboard/API/public-edge security, privacy/logging, AppCare/WordPress isolation, denial-of-service/resource controls, AppCare disaster recovery, stack-specific security, and safe real-target adversarial acceptance.

A missing, failed, stale, mismatched, or inconclusive mandatory security result blocks beta readiness. Security findings are not waived merely to meet a launch date.

## Scope and workflow

The historical BETA-00 through BETA-10 queue proved the AppCare core platform. It does not by itself establish customer-service readiness.

The current supported profile is Linux-hosted PHP 8.x with Nginx or Apache and MariaDB/MySQL. The first real acceptance target is `video.slabfranchise.com`.

The current customer-readiness work follows the 12 phases in `APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md`:

`P01 blueprint -> P02 credential custody -> P03 connect/inventory/revision -> P04 filesystem backup -> P05 live DB backup -> P06 offsite/full restore -> P07 scanning/tests -> P08 normalize/stage/remediate -> P09 deploy/verify/rollback -> P10 monitor/schedule/alert/report -> P11 productize/offboard/self-DR -> P12 real-target/security/beta decision`.

Every issue follows:

`Saveruflo preflight when available -> Graphify query/update -> constitution/specify/clarify/plan/checklist/tasks/analyze/converge as needed -> Luna dependency plan and coder-lane routing -> Terra design challenge -> bounded implementation -> Luna actual-diff review -> Terra security review -> deterministic/security/failure tests -> Codex Security -> exact-head CI -> checkpoint -> Graphify impact review -> protected merge`.

## Governance

This constitution, `APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md`, `docs/governance/APPCARE_CURRENT_SCOPE.json`, `docs/governance/APPCARE_MODEL_EXECUTION_ROUTING.md`, `docs/governance/APPCARE_MODEL_EXECUTION_ROUTING.json`, `AGENTS.md`, `SECURITY.md`, `ARCHITECTURE.md`, `WORKER_PROTOCOL.md`, `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`, `docs/security/PRE_BETA_SECURITY_GATE.md`, the current Spec Kit feature, and the current GitHub issue are jointly binding.

Conflicts are resolved in favor of the explicit owner decision, the stricter security boundary, the current-scope blueprint, the model-execution routing policy, and the product-completeness invariant.

Any amendment records the reason, affected workflow/readiness gates, security impact, tests, and new version before implementation relies on it.

**Version**: 1.3.0 | **Ratified**: 2026-08-12 | **Last Amended**: 2026-08-30
