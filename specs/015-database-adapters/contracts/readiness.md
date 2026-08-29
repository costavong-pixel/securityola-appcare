# Contract: Database-adapter readiness integration

## Spec 013 authority

Spec 015 MUST use the existing Spec 013 readiness contracts:

1. Validate `tenant_id`, `application_id`, and `stack_id` with the existing
   Spec 013 scope rules.
2. Emit `CapabilityEvidence` through `ApplicationCapabilityRegistry`.
3. Use `SupportabilityEvaluator` as the only authoritative supportability
   evaluator.
4. Reuse the existing evidence classes:
   `fixture`, `reference`, `controlled_live_provider`, and `real_target`.
5. Require coordinator approval before any authoritative supportability or
   readiness claim.
6. Use the existing downgrade path when a real target later reveals a missing or
   unsupported mandatory capability.

The runtime entry point for this adapter is
`register_database_capability_evidence`. It constructs the scoped result,
adds it to `ApplicationCapabilityRegistry`, and may persist it through the
existing `SqlAlchemyReadinessStore` boundary. The helper records blocked
evidence as blocked; it never upgrades evidence class or invokes a second
supportability evaluator.

Spec 015 MUST NOT define a second supportability matrix, readiness enum, or
worker-approval path.

## Capability mapping

| Capability | Evidence supplied by Spec 015 | Promotion rule |
| --- | --- | --- |
| `database_backup` | verified logical dump, readback, checksum, manifest, coordinator review | may become `supported` for the exact scope |
| `remote_readback` | supporting evidence that the database artifact was read back and matched | must not become whole-app `supported` from database evidence alone |
| `isolated_restore` | supporting evidence that the database artifact restored into an isolated target and passed verification | must not become whole-app `supported` from database evidence alone |

All other mandatory capabilities remain governed by their own specs and
evidence.

## Evidence-class contract

Accepted evidence classes remain:

- `fixture`
- `reference`
- `controlled_live_provider`
- `real_target`

Rules:

- Repository tests and fake brokers use `fixture`.
- AppCare-owned isolated lab databases may produce `reference`.
- Authorized live infrastructure under AppCare control but not a real customer
  target may produce `controlled_live_provider`.
- Exact customer/application evidence may produce `real_target`.

No caller, worker, or review summary may upgrade one class to another.

## Readiness floor

This documentation package does not change live readiness.

Even after downstream code exists:

- `database_backup` support alone does not satisfy the full mandatory capability
  matrix;
- database-only readback or restore evidence does not certify whole-application
  backup support;
- customer onboarding, pilot, and paid-service readiness still require
  `real_target` evidence and the rest of the mandatory matrix;
- the global production-enabled flag remains `NO`.

## Explicit outcome

The repository implementation is present after the implementation wave, but
this spec does not promote a live database capability by itself. The correct
status until the required live evidence exists is:

- design documented: yes
- repository implementation: present
- fixture and negative tests: required and reviewable
- live database capability: missing unless controlled-live or real-target
  evidence is accepted by Spec 013
- customer onboarding readiness: no
- pilot readiness: no
- paid-service readiness: no

Any stronger claim requires the implementation, security review,
deterministic tests, exact-head CI, coordinator approval, and bounded live
evidence collection. A merge without that evidence must not change readiness
or production-enabled state.
