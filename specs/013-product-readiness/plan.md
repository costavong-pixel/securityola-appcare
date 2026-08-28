# Implementation Plan: 013 Product Readiness

## Goal

Make product completeness a first-class enforced AppCare concept before any further private-beta claim.

## Inputs

- `.specify/memory/constitution.md`
- `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`
- `docs/security/PRE_BETA_SECURITY_GATE.md`
- existing release, deployment, backup, monitoring, connector, and workflow models

## Architecture changes

1. Introduce layered readiness models rather than one global ready flag.
2. Add a mandatory capability registry/matrix per tenant/application/stack.
3. Add evidence classes so fixture/reference/live-provider/real-target evidence cannot be confused.
4. Add deterministic supportability evaluation.
5. Add readiness downgrade propagation when a real target reveals a mandatory gap.
6. Extend release evaluation to require the pre-beta security gate for customer readiness.
7. Preserve historical BETA-00..BETA-10 evidence as core-platform evidence; do not rewrite history.

## Delivery order

### P1 — Governance and schemas

- constitution amendment
- readiness/gap register
- mandatory security gate
- Spec 013 artifacts
- readiness/evidence/capability data models

### P2 — Evaluators

- supportability evaluator
- layered readiness evaluator
- downgrade rules
- evidence-class validation
- coordinator decision binding

### P3 — API/dashboard exposure

Expose sanitized readiness/supportability state to operator paths. Do not expose private customer infrastructure details publicly.

### P4 — Release-gate integration

Prevent customer/pilot readiness when required live evidence or security evidence is absent. Keep global production disabled.

### P5 — Test and acceptance

Negative tests must prove that fixture-only evidence, stale evidence, cross-tenant evidence, missing capability evidence, and worker self-approval cannot create a false-ready state.

## Dependencies

Spec 013 must merge before implementation of Specs 014–023 relies on new readiness terminology.

## Safety

No customer production access is required for Spec 013 implementation. No customer credentials are required. No WordPress product resource may be touched.

## Engineering loop

`/saveruflo preflight -> /graphify update/query -> Spec Kit -> bounded implementation -> deterministic tests -> negative/failure tests -> Codex Security diff scan -> exact-head CI -> /graphify final -> /saveruflo checkpoint -> coordinator approval -> protected merge`
