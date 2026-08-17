# Tasks: AppCare Control Plane and Tenant-Safe Audit Trail

**Input**: Design documents from `specs/001-control-plane-audit/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/api.md`, and `quickstart.md`

**Tests**: Required by FR-012 and the acceptance criteria. Security and negative tests are written before the implementation they protect.

**Organization**: Tasks are grouped by user story so each slice has an independent test and review boundary.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the repository-compatible service layout and locked runtime dependencies.

- [x] T001 Add the AppCare service dependency declarations and bounded development configuration in `pyproject.toml`, `requirements-dev.txt`, and `requirements-dev.lock`.
- [x] T002 [P] Create the service package layout in `appcare/api.py`, `appcare/config.py`, `appcare/db.py`, `appcare/auth/`, `appcare/models/`, `appcare/repositories/`, `appcare/services/`, and `appcare/routes/`.
- [x] T003 [P] Create the unit/integration/contract test layout in `tests/unit/`, `tests/integration/`, and `tests/contract/` with shared isolated database fixtures in `tests/conftest.py`.
- [x] T004 [P] Add the BETA-01 service run and environment-safety notes to `DEVELOPMENT.md` and `specs/001-control-plane-audit/quickstart.md` without adding credentials or production paths.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Build the security and persistence boundaries that every user story depends on.

**Checkpoint**: No user-story implementation starts until these checks pass.

- [x] T005 Implement validated development/staging settings, safe defaults, and secret-free error/log configuration in `appcare/config.py` and `tests/unit/test_config.py`.
- [x] T006 Implement SQLAlchemy engine/session creation, transaction scope, schema bootstrap, PostgreSQL URL handling, isolated SQLite fixture handling, and fail-closed audit-trigger setup in `appcare/db.py` and `tests/integration/test_database_boundary.py`.
- [x] T007 [P] Implement shared declarative model/base metadata and timestamp/opaque-ID conventions in `appcare/models/base.py` and `appcare/models/__init__.py`.
- [x] T008 [P] Implement the common API error response and safe validation boundary in `appcare/api.py`, `appcare/routes/__init__.py`, and `tests/unit/test_error_sanitization.py`.
- [x] T009 Implement the application factory and dependency-injected database/session lifecycle in `appcare/api.py` and `tests/contract/test_app_factory.py`.

---

## Phase 3: User Story 1 - Manage Tenant-Owned AppCare Resources (Priority: P1) 🎯 MVP

**Goal**: Authenticate users and enforce tenant ownership on every control-plane resource.

**Independent Test**: Two fake tenant users can access their own records but cannot read, modify, or delete the other tenant’s records, and unauthenticated requests fail before tenant data is loaded.

### Tests for User Story 1

- [x] T010 [P] [US1] Add authentication and bearer-token contract tests in `tests/contract/test_auth_api.py` covering valid, invalid, expired, and disabled-user cases without logging token values.
- [x] T011 [P] [US1] Add two-tenant cross-tenant negative tests in `tests/integration/test_tenant_isolation.py` for applications, assets, findings, and user-owned records.
- [x] T012 [P] [US1] Add input/error and secret-redaction tests in `tests/unit/test_tenant_validation.py` for foreign tenant IDs, malformed opaque IDs, disabled tenants, and secret-like metadata.

### Implementation for User Story 1

- [x] T013 [P] [US1] Implement Tenant and User models, membership/status constraints, and safe identity serialization in `appcare/models/identity.py`.
- [x] T014 [P] [US1] Implement Application, Asset, and Finding models with tenant-matching foreign keys and validation in `appcare/models/resources.py`.
- [x] T015 [US1] Implement password/token verification and authenticated tenant context in `appcare/auth/service.py` and `appcare/auth/dependencies.py`.
- [x] T016 [US1] Implement tenant-filtered repository helpers and ownership checks in `appcare/repositories/tenant_scope.py`.
- [x] T017 [US1] Implement authentication and tenant-owned resource routes in `appcare/routes/auth.py` and `appcare/routes/resources.py` using the authenticated tenant context, never a client-supplied tenant selector.
- [x] T018 [US1] Run the User Story 1 independent test suite and fix all cross-tenant leakage, existence-oracle, and secret-output failures before proceeding.

**Checkpoint**: User Story 1 is independently usable and tenant isolation is proven by negative tests.

---

## Phase 4: User Story 2 - Track Durable Jobs and Audit History (Priority: P1)

**Goal**: Persist job state and append-only audit history across restart with trustworthy integrity metadata.

**Independent Test**: Create a job and audit event, restart the API against the same isolated database, retrieve both records, and prove update/delete attempts cannot change the audit event.

### Tests for User Story 2

- [x] T019 [P] [US2] Add job state, retry, cost, and invalid-transition tests in `tests/integration/test_jobs.py`.
- [x] T020 [P] [US2] Add append-only audit, hash-chain, sanitization, and direct mutation failure tests in `tests/integration/test_audit_immutability.py`.
- [x] T021 [P] [US2] Add stop/restart persistence tests in `tests/integration/test_restart_durability.py` using the same isolated database URL across application instances.

### Implementation for User Story 2

- [x] T022 [P] [US2] Implement Connector, Job, Backup, Approval, and Deployment models with validated statuses, cost/retry fields, tenant ownership, and no executable provider fields in `appcare/models/operations.py`.
- [x] T023 [P] [US2] Implement the append-only Audit Event model, metadata sanitizer, previous-event hash lookup, and event hash calculation in `appcare/models/audit.py` and `appcare/services/audit.py`.
- [x] T024 [US2] Implement database and ORM mutation guards for audit events in `appcare/db.py`, `appcare/models/audit.py`, and the isolated dialect tests in `tests/integration/test_audit_immutability.py`.
- [x] T025 [US2] Implement durable job creation/status service and tenant-scoped job routes in `appcare/services/control_plane.py` and `appcare/routes/jobs.py`.
- [x] T026 [US2] Implement bounded tenant-scoped audit listing and append operations with no audit update/delete route in `appcare/routes/audit.py`.
- [x] T027 [US2] Run the User Story 2 restart, state-transition, hash-chain, and mutation-failure tests and correct any durability or immutability regression.

**Checkpoint**: User Stories 1 and 2 are independently testable; committed state survives restart and audit history cannot be rewritten through supported or direct test paths.

---

## Phase 5: User Story 3 - Observe a Safe Control Plane Boundary (Priority: P2)

**Goal**: Provide truthful liveness/readiness signals and descriptive operational records without production write capability.

**Independent Test**: Liveness remains process-only, readiness reflects the isolated persistence dependency, and route/service inspection plus tests prove there is no external production write operation.

### Tests for User Story 3

- [x] T028 [P] [US3] Add liveness/readiness healthy, unavailable-dependency, timeout, and secret-redaction tests in `tests/integration/test_health_readiness.py`.
- [x] T029 [P] [US3] Add no-production-write route/service and public-safety tests in `tests/integration/test_no_production_writes.py`.
- [x] T030 [P] [US3] Add descriptive connector/backup/approval/deployment contract tests in `tests/contract/test_operations_api.py`.

### Implementation for User Story 3

- [x] T031 [US3] Implement unauthenticated liveness and isolated-dependency readiness checks in `appcare/routes/health.py`.
- [x] T032 [US3] Implement descriptive connector, backup, approval, and deployment routes with explicit rejection of execute/deploy/sync/provider-write operations in `appcare/routes/resources.py` and `appcare/services/control_plane.py`.
- [x] T033 [US3] Register all routes, response schemas, bounded pagination, and safe error handling in `appcare/api.py` and `appcare/routes/__init__.py`.
- [x] T034 [US3] Run the User Story 3 independent test suite and verify no production URL, credential, SDK, deployment socket, or write capability enters the BETA-01 tree.

**Checkpoint**: All BETA-01 user stories are independently testable without production access.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Close the feature with deterministic evidence and the AppCare beta loop.

- [x] T035 [P] Update `README.md`, `DEVELOPMENT.md`, `SECURITY.md` references, and `specs/001-control-plane-audit/quickstart.md` with the final safe local setup and test commands.
- [x] T036 [P] Run `python scripts/check_public_safety.py`, `python scripts/scan_worker_changes.py` fixtures, and secret-pattern/failure tests without printing any secret values.
- [x] T037 Run full pytest, Ruff, mypy, build-lock, dependency, security/failure, and exact-head CI gates from the BETA-01 branch.
- [x] T038 Run fresh Codex Security validation and Graphify impact review against the exact BETA-01 diff.
- [x] T039 Run the independent Codex final review through the current Codex agent/app/cloud session or GitHub Codex review; Codex CLI is optional and not a blocker.
- [x] T040 Save the Saveruflo checkpoint with exact branch/head, issue acceptance evidence, findings, tests, CI, and WordPress untouched status.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies; creates the service and test layout.
- **Foundational (Phase 2)**: Depends on Setup and blocks every user story.
- **User Story 1 (Phase 3)**: Depends on Foundational; MVP tenant/auth slice.
- **User Story 2 (Phase 4)**: Depends on Foundational and integrates with the tenant context from US1.
- **User Story 3 (Phase 5)**: Depends on Foundational and the descriptive operation models from US2.
- **Polish (Phase 6)**: Depends on all desired user stories and all failure tests passing.

### User Story Dependencies

- **US1 (P1)**: Starts after Foundational; no dependency on US2/US3.
- **US2 (P1)**: Starts after Foundational; reuses US1 tenant/auth helpers but has its own durable job/audit tests.
- **US3 (P2)**: Starts after Foundational; uses the shared application factory and operation models but adds no external write capability.

### Parallel Opportunities

- T002–T004 can run in parallel because they touch disjoint setup paths.
- T007–T008 can run in parallel with database work after T002.
- T010–T012, T013–T014, T019–T021, T022–T023, and T028–T030 are parallelizable within their story phases.
- DeepSeek may receive only one bounded packet at a time per write set; Codex reviews each actual diff before the next dependent packet.

## Implementation Strategy

### MVP First (US1)

1. Complete Setup and Foundational phases.
2. Write and fail the US1 tenant/auth tests.
3. Implement the smallest authenticated tenant-owned resource slice.
4. Run the US1 checkpoint and security review before adding durable jobs/audit.

### Incremental Delivery

1. Add US2 only after US1 tenant checks are green.
2. Add US3 only with descriptive operation records and no provider execution.
3. Finish the full deterministic/security/exact-head loop before any merge or issue close.

## Notes

- Every task has a checkbox, sequential ID, required story label where applicable, and concrete file path.
- Tests are explicit because tenant isolation, audit immutability, restart durability, and no-production-write behavior are acceptance-critical.
- No task authorizes production access, WordPress Security access, credentials, deployment, or external provider writes.
