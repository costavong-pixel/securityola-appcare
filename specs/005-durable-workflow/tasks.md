# BETA-05 Implementation Tasks

## Phase 1 — specification and dependency boundary

- [ ] T001 Record the LangGraph/PostgreSQL persistence decision and safety
  constraints.
- [ ] T002 Add pinned LangGraph and PostgreSQL checkpointer dependencies with a
  regenerated hashed lock.
- [ ] T003 Define typed state, action, evidence, transition, approval, retry,
  timeout, and cost-budget contracts.

## Phase 2 — durable runtime

- [ ] T004 Add workflow action/evidence/transition records with tenant scope and
  idempotency constraints.
- [ ] T005 Add the fail-closed PostgreSQL checkpointer factory and strict
  serializer configuration.
- [ ] T006 Implement the scan-to-recovery graph and explicit safe routing.
- [ ] T007 Implement approval interrupt/resume and failed-verification rollback
  routing.

## Phase 3 — failure proof

- [ ] T008 Add duplicate delivery, crash/restart, retry exhaustion, timeout,
  cost-budget, approval restart, and rollback failure-injection tests.
- [ ] T009 Verify evidence/AI-explanation separation and secret/public-safety
  boundaries.
- [ ] T010 Run deterministic, security, dependency, Graphify, Saveruflo,
  independent review, and exact-head CI gates.
- [ ] T011 Close issue #6 only after the exact committed head passes all gates;
  update BETA-MASTER and continue to BETA-06.
