# Implementation Plan: BETA-05 Durable Scan-to-Recovery Workflow

**Branch**: `codex/beta-05-scanning`
**Issue**: #6
**Spec**: [spec.md](spec.md)

## Technical decisions

### LangGraph and persistence

Use `langgraph==1.2.9` with `langgraph-checkpoint-postgres==3.1.2` and the
existing `psycopg==3.3.4`. The runtime graph is compiled with a PostgreSQL
checkpointer. The adapter opens a Psycopg connection with `autocommit=True` and
`dict_row`, calls `setup()` as an explicit schema step, and uses a strict
non-pickle serializer configuration. The database URL is validated by the
existing AppCare environment/host boundary and is never printed.

Tests use `InMemorySaver` only as an isolated deterministic graph fixture; they
do not represent production durability. The PostgreSQL factory is separately
validated for fail-closed configuration and is the only runtime checkpointer
path.

### State and side effects

The LangGraph state is a typed `TypedDict` containing bounded strings,
identifiers, policy counters, transition status, evidence references, and
approval fields. Raw scanner output, backup artifacts, AI prompts, and
explanations are not state payloads.

SQLAlchemy workflow ledgers provide durable idempotency and evidence records:

- `WorkflowAction` records one action key and result reference;
- `WorkflowTransition` records one transition key and links to an audit event;
- `WorkflowEvidence` records a digest and sanitized summary without raw tool
  output.

The graph calls injected adapters only through the ledger. A resumed action
reuses the same idempotency key, so a provider/deployment adapter can safely
deduplicate a crash-replayed request.

### Failure and approval policy

The graph keeps scanner failure separate from findings/evidence. Each action
has finite attempts, a timeout budget, and a cost budget. Exhaustion produces a
sanitized escalation/failure state and a transition event. High-risk work
creates an idempotent approval-pending action, then pauses with LangGraph
`interrupt`; the node has no non-idempotent side effect after the pause until a
decision is supplied.

## Project structure

```text
appcare/workflows/
├── __init__.py
├── checkpointer.py
├── contracts.py
├── graph.py
└── store.py

specs/005-durable-workflow/
├── spec.md
├── plan.md
├── data-model.md
├── contracts/workflow.md
├── checklists/requirements.md
└── tasks.md

tests/unit/test_workflows.py
tests/integration/test_workflows.py
```

## Test strategy

- graph construction and typed-state validation;
- checkpoint configuration rejection for non-AppCare or non-PostgreSQL URLs;
- action/transition/evidence idempotency on an isolated SQLite AppCare DB;
- interrupt pause/resume with a recreated graph and shared in-memory fixture;
- retry exhaustion, timeout, cost-budget exhaustion, duplicate delivery, and
  failed-verification rollback routing;
- repository Ruff, mypy, public-safety, dependency, security, Graphify, and
  exact-head CI gates.
