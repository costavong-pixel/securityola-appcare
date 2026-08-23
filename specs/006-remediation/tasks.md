# Tasks: BETA-06 Safe Remediation Workspace

**Input**: Design documents from `/specs/006-remediation/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/remediation.md`, `quickstart.md`

**Tests**: Required by issue #7 acceptance and the repository constitution.

## Phase 1: Setup

- [x] T001 Record the BETA-06 Vercel skill audit, deferred decision, and preview boundary in `docs/engineering/THIRD_PARTY_SKILLS.md` and `docs/engineering/BETA-06-REMEDIATION.md`.
- [x] T002 Add the repository-native BETA-06 specification, plan, research, data model, contracts, checklist, and quickstart under `specs/006-remediation/`.
- [x] T003 Update `AGENTS.md` and `BETA_LOOP.md` to point the active Speckit plan and beta loop at BETA-06 without changing production or WordPress scope.

## Phase 2: Foundational safety contracts

- [x] T004 [P] Define tenant-scoped remediation, workspace, file-change, patch, gate, preview, review, and approval contracts in `appcare/remediation/contracts.py`.
- [x] T005 [P] Add symlink-safe disposable workspace creation and cleanup in `appcare/remediation/workspace.py`.
- [x] T006 [P] Add deterministic patch identity, evidence binding, path/content policy, preimage validation, and rollback metadata in `appcare/remediation/patches.py`.
- [x] T007 [P] Add tenant-scoped approval request/decision records in `appcare/remediation/approval.py`.

## Phase 3: User Story 1 — Prepare a bounded remediation (P1) 🎯 MVP

**Goal**: Produce one deterministic, tenant-scoped patch candidate inside a disposable workspace.

**Independent Test**: `tests/unit/test_remediation.py` proves a valid seeded finding/evidence/change creates one bounded patch and rejected findings create none.

- [x] T008 [P] [US1] Add workspace and patch construction unit fixtures in `tests/unit/test_remediation.py`.
- [x] T009 [US1] Implement deterministic patch construction from finding/evidence references in `appcare/remediation/patches.py`.
- [x] T010 [US1] Implement workspace containment, job identity, and safe file staging in `appcare/remediation/workspace.py`.
- [x] T011 [US1] Add scanner-failure, suppressed-finding, missing-evidence, cross-tenant, and duplicate-delivery rejection tests in `tests/unit/test_remediation.py`.

## Phase 4: User Story 2 — Validate and review a patch (P1)

**Goal**: Reject unsafe or unverified changes and retain sanitized evidence for review/rollback.

**Independent Test**: `tests/integration/test_remediation_boundaries.py` proves valid changes pass and every unsafe/failing fixture blocks promotion without an external call.

- [x] T012 [P] [US2] Implement bounded regression/security gate protocols and fail-closed aggregation in `appcare/remediation/gates.py`.
- [x] T013 [P] [US2] Implement sanitized review evidence and rollback/reference commit records in `appcare/remediation/contracts.py` and `appcare/remediation/patches.py`.
- [x] T014 [US2] Add valid, malformed, forbidden-path, secret, symlink, preimage-drift, delete/rename, and partial-apply tests in `tests/integration/test_remediation_boundaries.py`.
- [x] T015 [US2] Add failing, unavailable, timeout, duplicate, and cross-tenant gate tests in `tests/integration/test_remediation_boundaries.py`.

## Phase 5: User Story 3 — Verify an isolated preview (P2)

**Goal**: Provide fixture preview evidence and fail closed for unreviewed/live provider execution.

**Independent Test**: Preview fixture passes only for the approved synthetic target; unapproved Vercel/live/production/arbitrary-target requests are denied with no external call.

- [x] T016 [P] [US3] Implement fixture and unapproved Vercel preview adapters with scope and skill-review checks in `appcare/remediation/preview.py`.
- [x] T017 [P] [US3] Add approval queue request/decision integration and preview evidence tests in `tests/integration/test_remediation_boundaries.py`.
- [x] T018 [US3] Add preview protection, smoke/security failure, missing scope, production target, and arbitrary project negative tests in `tests/integration/test_remediation_boundaries.py`.

## Phase 6: Polish and cross-cutting gates

- [x] T019 [P] Export the remediation boundary through `appcare/remediation/__init__.py` and document its workflow integration boundary without adding provider authority.
- [x] T020 [P] Add BETA-06 deterministic validation instructions and sanitized evidence format in `docs/engineering/BETA-06-REMEDIATION.md` and `specs/006-remediation/quickstart.md`.
- [x] T021 Run unit/integration/security/failure tests, Ruff, mypy, public-safety, worker restrictions, dependency audit, and inspect the actual diff.
- [x] T022 Run applicable Codex Security review, Graphify final update/impact query, and Saveruflo checkpoint for the exact reviewed head.
- [x] T023 Push the BETA-06 branch, wait for exact-head CI, and update PR evidence; protected merge remains gated by the live-preview acceptance condition.
- [ ] T024 Close issue #7 and update BETA-MASTER only after acceptance evidence is complete; otherwise record the precise external preview blocker and keep the issue open.

## Current completion state

T001–T023 are complete on exact head `0847c13c7114141075aa210cbcfe5a63f221f2d6`.
PR #21 is draft and exact-head CI run `32104247854` passed. T024 remains open
because no owner-controlled Vercel skill, project authorization, or credential
boundary is available; the live adapter correctly fails closed.

## Dependencies and Execution Order

- Setup tasks T001–T003 precede implementation.
- Foundational tasks T004–T007 precede user-story tasks.
- US1 (T008–T011) precedes US2 because the validator consumes the patch contract.
- US2 (T012–T015) precedes US3 because preview requires passed patch/test gates.
- T019–T024 follow the completed user stories and exact diff review.

## Parallel Opportunities

- T004–T007 can proceed in parallel after the specification is approved.
- T008, T012, T013, T016, and T019–T020 can be parallelized only when they touch separate files and the shared contract is stable.
- Negative test additions may run in parallel by test file sections, but Codex owns the final merge of contract-sensitive changes.

## Implementation Strategy

1. Complete the foundation and MVP patch/workspace path.
2. Add deterministic gates and review/rollback evidence.
3. Add fixture preview and fail-closed live boundary plus approval queue.
4. Run the full repository gates and independent Codex review.
5. Require exact-head CI and protected merge; do not silently claim live Vercel acceptance.
