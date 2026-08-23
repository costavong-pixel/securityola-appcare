# Security and Remediation Requirements Checklist: Safe Remediation Workspace

**Purpose**: Validate that BETA-06 requirements are complete, clear, measurable, and safe to implement.
**Created**: 2026-08-18
**Feature**: [spec.md](../spec.md)

## Requirement Completeness

- [x] CHK001 All three user journeys define an independently testable outcome. [Completeness, Spec §User Scenarios]
- [x] CHK002 Workspace creation, patch derivation, validation, gates, preview, approval, and rollback evidence are explicitly represented. [Completeness, Spec §FR-001–FR-012]
- [x] CHK003 Scanner failure and missing deterministic evidence are explicitly distinguished from a finding. [Completeness, Spec §FR-003, FR-013]
- [x] CHK004 Customer production, WordPress, credentials, and arbitrary infrastructure are explicit exclusions. [Completeness, Spec §FR-015]

## Requirement Clarity

- [x] CHK005 Tenant, application, job, finding, evidence, and source-revision scope is defined. [Clarity, Spec §FR-001, FR-004]
- [x] CHK006 Unsafe path, symlink, traversal, secret, delete, rename, and generated-diff categories are named rather than hidden under a generic unsafe label. [Clarity, Spec §FR-005, FR-006]
- [x] CHK007 Preview is defined as non-production and AppCare-owned, and unapproved live execution is defined as fail-closed. [Clarity, Spec §FR-010]
- [x] CHK008 Approval is explicitly separated from merge, deployment, DNS, and production authority. [Clarity, Spec §FR-012]

## Requirement Consistency

- [x] CHK009 Preview readiness requires passed patch and test gates, while production deployment remains outside BETA-06. [Consistency, Spec §FR-008–FR-011]
- [x] CHK010 The requirement to preserve rollback/reference metadata is consistent across patch, preview, and approval flows. [Consistency, Spec §FR-004, FR-011, SC-004]
- [x] CHK011 The no-secret rule is consistent across workspaces, patch content, evidence, adapters, and output artifacts. [Consistency, Spec §FR-005, FR-015]

## Acceptance Criteria Quality

- [x] CHK012 Valid and invalid seeded fixtures have measurable 100% pass/rejection outcomes. [Measurability, Spec §SC-001–SC-003]
- [x] CHK013 Idempotency is stated as one stable identity/result for repeated requests. [Measurability, Spec §SC-005]
- [x] CHK014 The no-external-call requirement is stated for unsafe and unapproved cases. [Measurability, Spec §SC-002, SC-006]

## Scenario and Edge-Case Coverage

- [x] CHK015 Primary preparation and alternate no-remediation flows are defined. [Coverage, Spec §User Story 1]
- [x] CHK016 Exception flows for path, secret, preimage, gate, provider, and approval failures are defined. [Coverage, Spec §Edge Cases]
- [x] CHK017 Recovery/rollback reference behavior is defined when preview or later verification fails. [Coverage, Spec §Edge Cases, FR-004]
- [x] CHK018 Cross-tenant and cross-application behavior is explicitly required to fail closed. [Security, Spec §FR-001, FR-013]

## Dependencies and Assumptions

- [x] CHK019 The existing BETA-03 evidence and BETA-05 workflow boundaries are named as dependencies. [Dependency, Spec §Assumptions]
- [x] CHK020 Vercel skill review status and the fixture/fail-closed fallback are documented. [Dependency, Spec §FR-010, Assumptions]

## Notes

All items passed during the specification review. No clarification marker was
needed because BETA-06 is explicitly non-production and the existing AppCare
workflow supplies the default tenant, evidence, approval, and rollback model.
