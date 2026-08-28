# Spec 013 integration contract

Spec 014 MUST use the existing readiness contracts:

1. Validate tenant/application/stack with validate_scope_segment.
2. Create CapabilityEvidence for connect and inventory only.
3. Add evidence through ApplicationCapabilityRegistry.
4. Call SupportabilityEvaluator for the deterministic mandatory matrix.
5. Require the existing Luna coordinator approval before an authoritative
   supportability decision.
6. Let missing evidence produce MISSING_CAPABILITY; do not fill the matrix
   with fixture booleans.
7. If a real-target failure is later observed, use the existing readiness
   downgrade mechanism; do not create another downgrade store or status enum.

Expected post-Spec-014 matrix for a Linux target with valid live evidence:

| Capability | Expected status |
| --- | --- |
| connect | supported |
| inventory | supported |
| source_revision | missing_capability |
| filesystem_backup | missing_capability |
| database_backup | missing_capability |
| offsite_backup | missing_capability |
| remote_readback | missing_capability |
| isolated_restore | missing_capability |
| security_scan | missing_capability |
| test_discovery | missing_capability |
| staging | missing_capability |
| remediation | missing_capability |
| deploy | missing_capability |
| production_verify | missing_capability |
| database_migration_safety | missing_capability |
| rollback | missing_capability |
| monitoring | missing_capability |
| scheduler | missing_capability |
| alerting | missing_capability |
| reporting | missing_capability |
| credential_rotation | missing_capability until the later credential spec |
| offboarding | missing_capability |

This matrix is not a second evaluator; it is an acceptance expectation for the
existing Spec 013 evaluator.

