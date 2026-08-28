# Feature Specification: Product Readiness and Real-Customer Completeness Gate

**Feature**: `013-product-readiness`

**Created**: 2026-08-27

**Status**: Mandatory governance foundation

**Target**: AppCare only

## Purpose

Prevent AppCare from declaring customer/private-beta readiness when only internal contracts, fixtures, reference environments, or synthetic rehearsals have passed.

This specification makes readiness layered, evidence-backed, downgradeable, stack-specific, and dependent on real-target acceptance.

The authoritative gap register is `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`. The mandatory pre-beta security review is `docs/security/PRE_BETA_SECURITY_GATE.md`.

## User stories

### US1 — Truthful layered readiness

As an operator/owner, I need separate readiness states for the core platform, each supported stack, customer onboarding, pilot operation, and paid service so that a lower-layer gap cannot be hidden by a higher-level green label.

### US2 — Deterministic supportability

As an onboarding operator, I need AppCare to evaluate every required capability for one tenant/application and return `SUPPORTED`, `NEEDS_CLEANUP`, or `UNSUPPORTED` from evidence rather than worker judgment.

### US3 — Live-vs-fixture evidence distinction

As a release reviewer, I need every evidence item to state whether it came from a fixture/reference environment or a live customer/provider boundary so that synthetic evidence cannot accidentally satisfy a live readiness gate.

### US4 — Automatic readiness downgrade

As the owner, I need a newly discovered mandatory missing capability from a real pilot to invalidate any higher readiness state that depended on it.

### US5 — Real-target final gate

As a beta launch reviewer, I need at least one real external target to complete the mandatory AppCare lifecycle through verified preproduction before customer onboarding can be declared ready, and through owner-authorized production/monitoring/recovery before pilot readiness can be declared ready.

## Functional requirements

- **FR-001**: The system MUST define independent readiness levels: core, stack, customer onboarding, pilot, and paid service.
- **FR-002**: The system MUST never infer a higher readiness level solely from core release evidence.
- **FR-003**: Every application supportability decision MUST resolve a mandatory capability matrix.
- **FR-004**: Every capability result MUST contain tenant/application scope, capability, status, evidence reference, evidence class, timestamp, and coordinator decision where required.
- **FR-005**: Allowed capability states are `SUPPORTED`, `NEEDS_CLEANUP`, `MISSING_CAPABILITY`, `UNSUPPORTED`, and `BLOCKED_EXTERNAL`.
- **FR-006**: Allowed application supportability states are `SUPPORTED`, `NEEDS_CLEANUP`, and `UNSUPPORTED`.
- **FR-007**: Evidence MUST distinguish `fixture`, `reference`, `controlled_live_provider`, and `real_target` classes.
- **FR-008**: A readiness rule requiring real-target evidence MUST reject fixture/reference evidence even when all other fields match.
- **FR-009**: A newly discovered mandatory missing capability MUST downgrade dependent readiness states and create immutable audit evidence.
- **FR-010**: A worker/model MUST NOT self-approve stack supportability, production readiness, or beta readiness.
- **FR-011**: The coordinator MUST approve/reject supportability from actual capability evidence.
- **FR-012**: `CUSTOMER_ONBOARDING_READY=YES` MUST require a real target to pass the mandatory lifecycle through authoritative preproduction.
- **FR-013**: `PILOT_READY=YES` MUST additionally require an owner-authorized real production deployment, production verification, rollback proof, live monitoring, alerting, reporting, restart durability, and real cost measurement.
- **FR-014**: `PAID_SERVICE_READY=YES` MUST additionally require sustained backup/monitoring operation, operator workflow, customer auth/dashboard readiness, offboarding, credential rotation, cost controls, and AppCare disaster recovery.
- **FR-015**: `LIVE_CUSTOMER_PRODUCTION_ENABLED` MUST remain globally false; production authorization is exact tenant/application/action scoped.
- **FR-016**: Any release-readiness evaluator MUST fail closed when mandatory evidence is missing, stale, mismatched, inconclusive, or from the wrong evidence class.
- **FR-017**: The final beta decision MUST require every mandatory item in `docs/security/PRE_BETA_SECURITY_GATE.md` to pass against the exact release candidate.
- **FR-018**: Governance changes to readiness requirements MUST occur through protected PR review and exact-head CI.

## Mandatory capability matrix

Every supported application must resolve:

CONNECT, INVENTORY, SOURCE_REVISION, FILESYSTEM_BACKUP, DATABASE_BACKUP, OFFSITE_BACKUP, REMOTE_READBACK, ISOLATED_RESTORE, SECURITY_SCAN, TEST_DISCOVERY, STAGING, REMEDIATION, DEPLOY, PRODUCTION_VERIFY, DATABASE_MIGRATION_SAFETY, ROLLBACK, MONITORING, SCHEDULER, ALERTING, REPORTING, CREDENTIAL_ROTATION, OFFBOARDING.

## Success criteria

- **SC-001**: A fixture-only complete evidence set cannot produce `CUSTOMER_ONBOARDING_READY=YES`.
- **SC-002**: A stack with one mandatory `MISSING_CAPABILITY` cannot produce `STACK_READY=YES`.
- **SC-003**: A real pilot discovery that introduces a mandatory missing capability deterministically downgrades dependent readiness.
- **SC-004**: Cross-tenant or cross-application capability evidence is rejected.
- **SC-005**: Stale/mismatched revision/artifact evidence is rejected.
- **SC-006**: A worker-provided approval string cannot bypass coordinator/release policy.
- **SC-007**: The final beta gate rejects release when any mandatory security gate is missing or failed.
- **SC-008**: Full deterministic, negative, security, Graphify, Saveruflo, Codex Security, and exact-head CI evidence passes before merge.

## Out of scope

This governance feature does not itself implement SSH, database, backup-source, staging, deployment, monitoring-collector, WordPress, WooCommerce, or provider transport capabilities. Those are delivered in Specs 014–023 and cannot be marked complete by this spec.
