# Data Model: 013 Product Readiness

## ReadinessLevel

Fields:

- `level`: core | stack | customer_onboarding | pilot | paid_service
- `scope`: global or stack identifier
- `status`: ready | blocked | partial
- `evidence_refs[]`
- `evaluated_at`
- `evaluator`
- `reason_codes[]`

## CapabilityEvidence

Fields:

- `tenant_id`
- `application_id`
- `stack_id`
- `capability`
- `status`: supported | needs_cleanup | missing_capability | unsupported | blocked_external
- `evidence_class`: fixture | reference | controlled_live_provider | real_target
- `evidence_ref`
- `source_revision` when applicable
- `artifact_digest` when applicable
- `observed_at`
- `coordinator_decision` when approval is required

Identity must be deterministic for the same scoped capability/evidence event. Cross-tenant/application reuse is forbidden.

## SupportabilityDecision

Fields:

- `tenant_id`
- `application_id`
- `stack_id`
- `status`: supported | needs_cleanup | unsupported
- `mandatory_capability_digest`
- `blocking_capabilities[]`
- `cleanup_capabilities[]`
- `evidence_refs[]`
- `coordinator`
- `decided_at`

A worker cannot create an authoritative supportability decision.

## ReadinessDowngrade

Append-only event fields:

- `previous_level`
- `previous_status`
- `new_status`
- `trigger_capability`
- `trigger_evidence_ref`
- `affected_scopes[]`
- `reason_code`
- `recorded_at`

## SecurityGateDecision

Fields:

- `release_candidate_sha`
- `gate_version`
- `individual_gate_results`
- `security_findings_open`
- `codex_security_refs[]`
- `dependency_audit_ref`
- `secret_scan_ref`
- `graphify_ref`
- `saveruflo_ref`
- `exact_head_ci_ref`
- `real_target_security_ref`
- `known_limitations_ref`
- `coordinator_decision`
- `decided_at`

Allowed coordinator decisions:

- approve_for_controlled_private_beta
- reject
- blocked

## Invariants

1. Mandatory real-target gates cannot accept fixture/reference evidence.
2. A readiness decision cannot reference another tenant/application's evidence.
3. Missing mandatory capability evidence is blocking, not neutral.
4. Stale revision/artifact-bound evidence is blocking.
5. A downgrade event is append-only and cannot be hidden by later worker output.
6. Global live production enablement remains false; production authorization is application/action scoped elsewhere.
