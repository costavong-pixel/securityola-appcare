# BETA-05 Durable Workflow Boundary

AppCare BETA-05 introduces the durable scan-to-recovery orchestration boundary
for issue #6. The graph is resumable and auditable, but it is not a production
deployment authority.

The design and acceptance criteria are in
[specs/005-durable-workflow/spec.md](../../specs/005-durable-workflow/spec.md)
and [specs/005-durable-workflow/plan.md](../../specs/005-durable-workflow/plan.md).

Runtime rules:

- PostgreSQL is the runtime checkpoint backend; in-memory persistence is a
  deterministic test fixture only.
- Workflow state contains references and bounded policy data, never secrets or
  raw tool/customer data.
- Durable action keys protect backup, deploy, and rollback adapters from
  duplicate delivery. The PostgreSQL action row is selected `FOR UPDATE` and
  remains locked through the bounded adapter attempt sequence, so concurrent
  workers cannot execute the same committed action row at the same time.
  Adapter idempotency remains required at the external boundary because a
  process can fail after a provider side effect and before the ledger commit.
- Scanner failure remains distinct from a finding.
- High-risk actions pause at explicit approval interrupts.
- Failed post-deploy verification routes to rollback; no node itself grants
  production authorization.
- `WORDPRESS=UNTOUCHED` and no live provider calls are BETA-05 constraints.
