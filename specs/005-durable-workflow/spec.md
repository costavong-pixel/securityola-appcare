# BETA-05 Durable Scan-to-Recovery Workflow

**Feature Branch**: `codex/beta-05-scanning`
**Issue**: #6
**Status**: Active implementation scope
**Target**: AppCare only

## Goal

Make AppCare jobs resumable, bounded, auditable, and safe across worker
failures. The workflow is a durable orchestration boundary; it does not grant
the graph production credentials or deployment authority.

## Workflow

```text
intake/scope
  -> asset inventory
  -> verified backup gate
  -> parallel scan adapters
  -> normalize/evidence gate
  -> risk policy
  -> isolated workspace
  -> remediation plan
  -> patch/test
  -> approval interrupt
  -> controlled deploy adapter
  -> post-deploy verification
  -> rollback adapter on verification failure
  -> monitor/report
```

The BETA-05 implementation provides the graph, state, persistence adapter,
idempotency ledger, evidence references, audit transitions, approval pause, and
failure-injection tests. Provider, deployment, and remediation adapters remain
injected descriptive test doubles; no live production action is implemented.

## Acceptance scenarios

1. **Durable resume**: kill or recreate a worker after a completed node and
   resume the same `thread_id` without repeating successful side effects.
2. **Duplicate delivery**: invoke the same workflow/action event twice and
   verify that the idempotency key produces one action result and one transition
   event.
3. **Bounded failure**: transient failures consume a finite retry budget; the
   workflow stops and escalates with a sanitized failure code instead of
   looping forever.
4. **Approval durability**: a high-risk workflow pauses at a LangGraph
   `interrupt`, survives a new process/graph instance, and resumes only after
   an explicit approval decision.
5. **Rollback routing**: failed post-deploy verification routes to one
   idempotent rollback action and records the failed verification and rollback
   transition separately.
6. **Evidence separation**: tool evidence is persisted as evidence references
   and digests; AI explanation references are separate and cannot replace
   deterministic evidence.

## Safety requirements

- Checkpoints use PostgreSQL in the runtime path and are scoped by AppCare
  workflow/thread identifiers.
- State contains sanitized identifiers, bounded policy fields, evidence
  references, and approval state only; it contains no provider credentials,
  `.env` values, private keys, or raw customer artifacts.
- Every transition is recorded as a durable workflow transition and an
  append-only AppCare audit event.
- Backup, deploy, and rollback operations use durable idempotency keys. An
  adapter must make the external operation idempotent for crash recovery.
- Retry, timeout, and cost budgets are explicit and finite.
- Production and WordPress resources remain outside the test graph and its
  fixtures.
