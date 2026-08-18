# BETA-05 Durable Workflow Data Model

## Typed LangGraph state

The persisted graph state contains only:

- `workflow_id`, `tenant_id`, `application_id`, `job_id`;
- current phase/status and target environment;
- risk, backup, scan, evidence, approval, deployment, and rollback statuses;
- bounded retry/timeout/cost counters and policy limits;
- deterministic evidence references and AI explanation references;
- sanitized failure/escalation codes.

It never contains provider credentials, access tokens, private keys, `.env`
values, raw scanner payloads, customer backup bytes, or unrestricted prompts.

## SQLAlchemy durable records

### WorkflowAction

One idempotent side-effect intent per `(tenant_id, workflow_id, action_key)`.
The record stores action kind, status, attempt count, result reference, and
sanitized failure code. A successful record is returned for duplicate delivery;
the external adapter receives the same action key after a crash boundary.

### WorkflowTransition

One audit transition per `(tenant_id, workflow_id, transition_key)`. It stores
from/to phases, outcome, sanitized metadata, evidence references, timestamp, and
the linked append-only AppCare audit-event identifier.

### WorkflowEvidence

One deterministic evidence record per `(tenant_id, workflow_id, evidence_ref)`.
It stores evidence kind, source, digest, and bounded sanitized summary. It does
not store raw tool output or AI explanation content.
