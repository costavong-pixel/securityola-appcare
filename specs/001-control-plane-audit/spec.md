# Feature Specification: AppCare Control Plane and Tenant-Safe Audit Trail

**Feature Branch**: `codex/beta-01-control-plane`

**Created**: 2026-08-14

**Status**: Draft

**Input**: User description: "Create the minimal AppCare control plane without production write access, including a web/API project skeleton, durable tenant-safe data for users, apps/assets, connectors, jobs, findings, backups, approvals, deployments, and audit events; authentication and tenant isolation; immutable/auditable event history; job cost/retry/status fields; and health/readiness endpoints."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Manage tenant-owned AppCare resources (Priority: P1)

An authenticated AppCare user can work with resources belonging to their tenant, while the system consistently prevents access to another tenant's assets and events.

**Why this priority**: Tenant isolation is the primary safety boundary for every later connector, scan, backup, and remediation feature.

**Independent Test**: Create two test tenants and users, create resources for each, and verify that each user can read and change only their own tenant's resources; cross-tenant reads and writes fail without revealing whether the other resource exists.

**Acceptance Scenarios**:

1. **Given** two authenticated users belong to separate tenants, **When** each requests its own tenant resources, **Then** each receives only resources owned by its tenant.
2. **Given** a resource belongs to tenant A, **When** a tenant B user requests, updates, or deletes it, **Then** the operation is denied and no resource data is returned.
3. **Given** an unauthenticated or invalidly authenticated request, **When** it targets a tenant resource, **Then** the request is denied before tenant data is loaded.

---

### User Story 2 - Track durable jobs and audit history (Priority: P1)

An AppCare user and operator can see the durable state of jobs and a trustworthy history of control-plane events, including cost, retry, and status information, even after the API restarts.

**Why this priority**: Scanning, backup, approval, and deployment workflows cannot be trusted unless their state and security-relevant actions survive process failure and cannot be rewritten silently.

**Independent Test**: Create a job and audit event, restart the API process, retrieve both records, and verify that an existing event cannot be edited or deleted through the control-plane interface.

**Acceptance Scenarios**:

1. **Given** a job is created, **When** its status, retry count, and cost change, **Then** the latest durable state is returned with valid values and tenant ownership.
2. **Given** a security-relevant action occurs, **When** the audit history is queried after an API restart, **Then** the event remains available with actor, tenant, action, subject, timestamp, and outcome metadata.
3. **Given** an existing audit event, **When** a caller attempts to alter or remove it, **Then** the operation is rejected and the original event remains unchanged.

---

### User Story 3 - Observe a safe control plane boundary (Priority: P2)

An operator can determine whether the AppCare control plane is alive and ready to serve development or staging requests, while connector and deployment records remain descriptive only and cannot write to production systems.

**Why this priority**: Clear health signals and an explicit no-production-write boundary make the foundation usable without accidentally opening the later integration or deployment phases.

**Independent Test**: Call the liveness and readiness checks in healthy and unavailable-dependency states, then attempt to invoke a connector or deployment action and verify that no production write capability exists.

**Acceptance Scenarios**:

1. **Given** the control plane is running, **When** an operator calls its health checks, **Then** liveness and readiness return distinct, truthful results without exposing secrets.
2. **Given** a connector, backup, approval, or deployment record exists, **When** a caller requests its control-plane representation, **Then** the record is tenant-scoped and contains no executable production write path.
3. **Given** a required development dependency is unavailable, **When** readiness is checked, **Then** readiness fails clearly while liveness remains available when the process itself is alive.

### Edge Cases

- A user belongs to no tenant, or a tenant is disabled, during an otherwise valid request.
- A resource identifier is well-formed but belongs to another tenant or does not exist.
- A duplicate request retries after a network timeout and must not create contradictory audit state.
- A job receives an invalid status transition, negative retry count, or invalid cost value.
- The API restarts while a job or audit event is being written.
- The readiness dependency is unavailable, slow, or returns malformed status.
- Audit metadata contains a secret-like value or an oversized/untrusted string.
- Connector and deployment records are requested with credentials or production targets; the foundation must reject capability expansion.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The control plane MUST authenticate requests before loading tenant-owned data.
- **FR-002**: Every tenant-owned resource MUST have an unambiguous tenant owner and authorization check.
- **FR-003**: The system MUST deny cross-tenant reads, updates, and deletes without returning the other tenant's data.
- **FR-004**: The control plane MUST represent tenants, users, applications/assets, connectors, jobs, findings, backups, approvals, deployments, and audit events with explicit relationships and lifecycle state.
- **FR-005**: Job records MUST persist status, retry count, cost, timestamps, and failure information with validated values.
- **FR-006**: Audit events MUST be append-only through the application boundary and MUST retain tenant, actor, action, subject, timestamp, outcome, and sanitized metadata.
- **FR-007**: Restarting the API MUST NOT discard committed job or audit state.
- **FR-008**: Health and readiness checks MUST be available as separate operations and MUST not disclose secrets or customer data.
- **FR-009**: Connector, backup, approval, and deployment records MUST be descriptive control-plane state only; BETA-01 MUST NOT expose a production write connector or deployment authority.
- **FR-010**: Secrets MUST NOT be written to logs, audit metadata, API error responses, test fixtures, or generated artifacts.
- **FR-011**: Invalid authentication, tenant ownership, state transitions, and input values MUST fail closed with stable, non-sensitive errors.
- **FR-012**: The control plane MUST provide deterministic tests for tenant isolation, audit immutability, restart durability, health/readiness behavior, and the absence of production write capability.

### Key Entities *(include if feature involves data)*

- **Tenant**: An isolated AppCare customer boundary that owns users and application resources.
- **User**: An authenticated actor with tenant membership and control-plane permissions.
- **Application/Asset**: A tenant-owned application or asset record that later scans and connectors may reference.
- **Connector**: A tenant-scoped description of an external integration; BETA-01 stores state but does not perform production writes.
- **Job**: A durable unit of work with status, retry, cost, timestamps, and failure state.
- **Finding**: A tenant-owned security observation associated with an application or asset.
- **Backup**: A tenant-owned record describing backup state and verification metadata without performing an external backup in BETA-01.
- **Approval**: A tenant-scoped record of an approval decision and its actor/status without authorizing production deployment.
- **Deployment**: A tenant-scoped descriptive record of a deployment intent/status with no production execution capability.
- **Audit Event**: An append-only, tenant-scoped record of a security-relevant action and its sanitized outcome.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In automated negative tests, 100% of cross-tenant resource and audit-event access attempts are denied without leaking the target tenant's data.
- **SC-002**: After at least one controlled API restart, 100% of committed test jobs and audit events remain retrievable with unchanged identifiers and ownership.
- **SC-003**: 100% of attempted audit-event edits or deletions through the control-plane boundary are rejected and leave the original event unchanged.
- **SC-004**: Health checks distinguish process liveness from dependency readiness in all defined healthy and unavailable-dependency test cases, without logging or returning secret values.
- **SC-005**: The BETA-01 code and tests contain no production write connector, deployment credential, or executable production integration path.
- **SC-006**: The full deterministic, security, failure, dependency, secret, and exact-head CI gates pass for the BETA-01 implementation.

## Assumptions

- BETA-01 is a development/staging control-plane foundation; production deployment and external write connectors remain explicitly out of scope.
- A standard authenticated session model and tenant membership model are sufficient defaults for the foundation; provider-specific OAuth and connector credentials are deferred to later beta issues.
- Durable relational persistence is required by issue #2, but the implementation may choose the smallest repository-compatible local/development setup that can prove restart durability without connecting to production.
- The initial API surface can remain minimal and internal to the AppCare development workflow as long as the acceptance scenarios are executable and testable.
- Existing BETA-00 isolation, secret-screening, exact-head CI, and independent review controls remain mandatory for this feature.
