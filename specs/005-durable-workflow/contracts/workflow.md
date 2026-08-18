# BETA-05 Workflow Contracts

## Runtime boundary

```python
build_workflow(runtime, checkpointer)
```

The builder accepts an explicit runtime with a durable store and injected
adapters. It does not discover credentials, call providers, deploy code, or
spawn workers.

## Action adapter

An action adapter receives a deterministic `action_key`, the action kind, and
sanitized workflow state. It returns a bounded result reference and cost. The
adapter must be idempotent for that key. It may raise a retryable failure or a
terminal failure; the workflow converts both into bounded sanitized state.

The workflow store claims the durable action row with a database row lock and
holds that lock through the finite adapter attempt sequence. This prevents
concurrent workers from invoking the same committed action row concurrently.
The stable key is still required for crash recovery because a provider side
effect can occur before the ledger transaction commits.

## Scan adapter

The scan adapter returns evidence references and scanner-failure records. A
scanner failure is not converted into a finding. Deterministic evidence must
exist before any AI explanation reference can be attached.

## Approval

High-risk actions call a durable LangGraph interrupt with a JSON-safe approval
request. Resume input must contain an explicit decision and decision reference.
Approval rejection routes to a terminal escalation/failure state; approval is
required before the deploy action.

## Observability

Each graph transition produces a durable workflow transition and an append-only
audit event. All externally visible failure messages are stable reason codes;
secrets and raw provider responses are excluded.
