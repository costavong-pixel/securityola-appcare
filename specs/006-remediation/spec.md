# Feature Specification: Safe Remediation Workspace

**Feature Branch**: `codex/beta-06-remediation`

**Issue**: #7

**Created**: 2026-08-18

**Status**: Draft for implementation

**Target**: AppCare only

**Input**: Build a safe AppCare remediation workspace with deterministic patch validation, regression and security test boundaries, reviewable PR evidence, sandboxed preview verification, approval queue, and rollback references without production or WordPress access.

## User Scenarios & Testing

### User Story 1 - Prepare a bounded remediation (Priority: P1)

As an AppCare operator, I want a finding-backed fix prepared inside a disposable workspace so that proposed changes cannot escape the tenant, job, or AppCare repository boundary.

**Why this priority**: A safe, reproducible patch is the foundation for every later review or preview action.

**Independent Test**: Seed one vulnerable finding and one false-positive finding, create a workspace for the vulnerable finding, and confirm that only the deterministic remediation change is produced inside the workspace.

**Acceptance Scenarios**:

1. **Given** a tenant-scoped finding with deterministic evidence, **When** a remediation job is created, **Then** the job receives a disposable workspace tied to that tenant, application, and job identifier.
2. **Given** evidence with no approved remediation change, **When** patch preparation is requested, **Then** no patch is generated and the job is marked as requiring review.
3. **Given** a false-positive or suppressed finding, **When** patch preparation is requested, **Then** no remediation patch is generated.

---

### User Story 2 - Validate and review a patch (Priority: P1)

As an AppCare reviewer, I want deterministic regression/security gates and complete before/after evidence so that unsafe or unrelated changes cannot progress to preview or approval.

**Why this priority**: Automated evidence and explicit rollback references prevent a plausible-looking fix from becoming an unreviewed change.

**Independent Test**: Submit valid, unrelated-path, secret-bearing, malformed, cross-tenant, and failing-test patch fixtures and confirm only the valid patch passes all gates.

**Acceptance Scenarios**:

1. **Given** a patch with an allowed path, matching preimage, deterministic evidence, and passing tests, **When** validation runs, **Then** the patch is reviewable and includes a reference commit and rollback reference.
2. **Given** a patch that touches a forbidden path, contains secret-like material, changes an unrelated file, or fails a required test, **When** validation runs, **Then** promotion is blocked with a sanitized failure code.
3. **Given** duplicate delivery of the same patch job, **When** validation runs again, **Then** it returns the same sanitized result without creating a second patch identity.

---

### User Story 3 - Verify an isolated preview (Priority: P2)

As an AppCare reviewer, I want a preview request and internal approval record that are explicitly separated from production so that a tested patch can be inspected without granting deployment or merge authority.

**Why this priority**: Preview evidence is the last safe inspection point before the later beta that addresses controlled production deployment.

**Independent Test**: Run the fixture preview adapter with a valid patch and with unsafe or unapproved provider settings, then verify that the safe fixture path produces sanitized preview evidence while unapproved live execution fails closed.

**Acceptance Scenarios**:

1. **Given** a patch that passed deterministic gates, **When** a preview is requested, **Then** the request is constrained to an AppCare-owned non-production preview target.
2. **Given** an unreviewed Vercel skill, missing provider scope, production target, or arbitrary project reference, **When** preview execution is requested, **Then** the request is denied without an external call.
3. **Given** a preview smoke/security failure, **When** the result is recorded, **Then** approval remains pending or is rejected and the patch keeps its rollback reference.

### Edge Cases

- A workspace root is missing, symlinked, outside the AppCare repository, or contains a forbidden production/WordPress marker.
- A finding references another tenant, another application, a scanner failure, or no deterministic evidence.
- A patch uses an absolute path, parent traversal, symlink, rename/delete operation, forbidden file, secret-like value, or an unapproved extension.
- The workspace preimage changed before patch application, or one file fails during an otherwise multi-file apply.
- Regression tests pass but security tests fail, or either adapter is unavailable or times out.
- A preview request uses a production target, arbitrary provider/project, missing approval, unreviewed skill, or protected preview that cannot be verified.
- Approval is duplicated, expired, rejected, or submitted by a different tenant.
- A preview succeeds but later verification fails; no production promotion is available in this beta and the rollback reference remains the required recovery target.

## Requirements

### Functional Requirements

- **FR-001**: The system MUST create each remediation workspace from a validated tenant, application, job, and source revision.
- **FR-002**: The system MUST reject workspace paths that cross a symlink, escape the AppCare repository boundary, or identify WordPress, production, or unrelated infrastructure.
- **FR-003**: The system MUST derive a patch only from deterministic finding evidence and an explicitly bounded remediation change description.
- **FR-004**: The system MUST preserve the finding fingerprint, evidence references, source revision, changed paths, patch digest, and rollback/reference commit metadata.
- **FR-005**: The system MUST reject absolute paths, traversal, symlink targets, secret-like content, credential references, and unrelated or forbidden files.
- **FR-006**: The system MUST reject deletions, renames, and broad generated changes unless a future beta explicitly adds a reviewed capability.
- **FR-007**: The system MUST validate preimages before applying a patch and MUST prevent partial application from leaving an inconsistent workspace.
- **FR-008**: The system MUST run bounded regression and security test adapters after patch preparation; a failure or unavailable result MUST block promotion.
- **FR-009**: The system MUST provide a sanitized review/PR evidence record without automatically creating a public PR, merging, or granting release authority.
- **FR-010**: The system MUST provide a preview adapter boundary that accepts only an AppCare-owned non-production target and fails closed when provider scope, skill review, or sandbox approval is absent.
- **FR-011**: The system MUST verify preview smoke/security evidence before an approval can be considered ready.
- **FR-012**: The system MUST provide an internal tenant-scoped approval queue whose decisions do not grant production or merge authority.
- **FR-013**: The system MUST keep scanner failures distinct from findings and MUST refuse remediation for scanner-failure-only evidence.
- **FR-014**: The system MUST be idempotent for repeated remediation, validation, preview, and approval events.
- **FR-015**: The system MUST never read, store, print, prompt for, or expose raw provider credentials, `.env` files, customer artifacts, OpenCode auth stores, WordPress resources, or production paths.

### Key Entities

- **Remediation job**: Tenant/application-scoped intent connecting one finding to one source revision and disposable workspace.
- **Remediation workspace**: Disposable AppCare-only filesystem area for patch preparation and bounded validation.
- **Patch candidate**: Reviewable change set containing preimages, postimages/digests, deterministic evidence references, changed paths, and rollback/reference commit metadata.
- **Validation result**: Sanitized outcome of scope, integrity, regression, and security gates.
- **Preview record**: Non-production preview request/result with provider-scope and smoke/security evidence references.
- **Approval request**: Tenant-scoped internal decision record that can approve or reject review progression but cannot authorize production.

## Success Criteria

### Measurable Outcomes

- **SC-001**: 100% of seeded valid remediation fixtures produce a workspace and patch whose files remain under the declared AppCare workspace root.
- **SC-002**: 100% of seeded unsafe-path, secret, cross-tenant, malformed, missing-evidence, and scanner-failure fixtures are rejected without an external provider call.
- **SC-003**: 100% of seeded failing regression or security test results block preview readiness and approval readiness.
- **SC-004**: Every accepted patch record contains a deterministic evidence reference, source revision, patch digest, and rollback/reference commit.
- **SC-005**: Replaying the same remediation, validation, preview, or approval event produces one stable sanitized identity and does not duplicate the side-effect boundary.
- **SC-006**: No BETA-06 test or adapter can write to customer production, `/var/www/api.securityola.com`, WordPress resources, or an arbitrary external target.

## Assumptions

- BETA-06 uses synthetic and repository-local fixtures; customer production data and credentials are out of scope.
- A deterministic remediation change is supplied by an AppCare-owned adapter or fixture; AI explanations cannot create a patch by themselves.
- Preview verification is represented by an AppCare-owned sandbox/fixture adapter until a separately reviewed Vercel execution boundary is available.
- GitHub PR creation and Vercel preview execution remain explicit adapters; this beta does not grant worker merge, deployment, DNS, or production authority.
- The existing BETA-05 workflow, audit, tenant, backup, and rollback contracts remain the source of truth for later orchestration.
