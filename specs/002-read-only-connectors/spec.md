# Feature Specification: Read-Only Connectors and Asset Inventory

**Feature Branch**: `codex/beta-02-connectors`

**Created**: 2026-08-15

**Status**: Draft

**Input**: BETA-02 issue #3 — read-only GitHub, Vercel, and Supabase connectors with asset inventory, scoped connection reference metadata, health/permission checks, and ownership verification.

## User Scenarios & Testing

### User Story 1 - Connect a supported application safely (Priority: P1)

As an AppCare operator, I want to register a GitHub, Vercel, or Supabase connection for one tenant-owned application so that AppCare can verify access and ownership without receiving broader authority than the connection needs.

**Why this priority**: A trustworthy, least-privilege connection boundary is required before any inventory can be collected. It prevents an inventory feature from becoming an accidental deployment, mutation, or cross-tenant access path.

**Independent Test**: With fake provider responses and two test tenants, register each supported provider, run health/permission/ownership checks, and verify that only the owning tenant can read the connection result and that no write operation is exposed.

**Acceptance Scenarios**:

1. **Given** a tenant-owned application and a declared provider scope, **When** an operator registers a connection, **Then** the connection records the provider, tenant, application, permitted read capabilities, and safe status without storing a live credential value.
2. **Given** a connection with valid read-only permission, **When** AppCare runs its health and permission check, **Then** the result identifies the connection as usable for its declared read capabilities and does not attempt deployment, mutation, or deletion.
3. **Given** a connection that cannot prove ownership of the tenant’s application, **When** the ownership check runs, **Then** the connection is rejected or marked unusable without revealing another tenant’s identifiers or provider response details.

---

### User Story 2 - Reconcile an application inventory (Priority: P2)

As an AppCare operator, I want to inventory the read-only resources associated with an owned application so that the dashboard can show a repeatable security-relevant asset baseline.

**Why this priority**: Inventory is the first customer-visible value of the connectors and provides the asset set used by later scanning and monitoring stages.

**Independent Test**: Replay the same deterministic provider snapshot twice and verify that the second run produces the same tenant-scoped asset set without duplicate records or mutation outside the inventory boundary.

**Acceptance Scenarios**:

1. **Given** a usable read-only connection, **When** inventory runs, **Then** GitHub repositories, Vercel projects/deployments, and Supabase project/auth/storage/database metadata are represented as tenant-owned assets with safe references and provenance.
2. **Given** the same provider snapshot is inventoried again, **When** reconciliation completes, **Then** existing assets are reused or deterministically reconciled and no duplicate assets or contradictory audit events are created.
3. **Given** one provider resource disappears from a later snapshot, **When** reconciliation runs, **Then** the prior asset is marked according to the documented read-only lifecycle policy and is not deleted from customer history by the connector.

---

### User Story 3 - Handle credentials and failures safely (Priority: P3)

As an AppCare operator, I want connector failures and credential lifecycle changes to be visible without exposing secrets, so that access can be repaired safely.

**Why this priority**: Revocation, expiration, provider outages, and insufficient scopes are normal integration conditions. They must fail closed without leaking credentials into logs, responses, audit history, or job state.

**Independent Test**: Run health and inventory checks against fake expired, revoked, insufficient-scope, timeout, rate-limit, and malformed-provider responses and verify stable sanitized outcomes, bounded retries, and preserved tenant isolation.

**Acceptance Scenarios**:

1. **Given** an expired, revoked, or insufficiently scoped credential reference, **When** a check runs, **Then** the connection fails safely with a non-secret reason and no retry loop that could amplify provider access.
2. **Given** a provider timeout, rate limit, or malformed response, **When** inventory runs, **Then** the job records a bounded failure state without logging raw headers, tokens, response bodies, or connection URLs containing credentials.
3. **Given** a connection belongs to tenant A, **When** tenant B submits its identifier or attempts to read its health or inventory state, **Then** the request is denied without an existence oracle.

---

### Edge Cases

- A provider returns an expired, revoked, invalid, or insufficiently scoped credential result.
- A provider is unavailable, rate-limited, times out, or returns malformed data.
- An ownership check returns a resource belonging to another tenant or an ambiguous ownership result.
- The same inventory snapshot is submitted repeatedly or arrives out of order.
- A resource disappears from a later snapshot; history remains auditable and no destructive connector action occurs.
- A request names an invalid, foreign, disabled, or deleted connection identifier.
- A provider response contains token-shaped values, authorization headers, credential-bearing URLs, or unexpectedly large metadata.
- A connector is configured with a capability outside the approved read-only scope.

## Requirements

### Functional Requirements

- **FR-001**: The system MUST support read-only connection records for GitHub, Vercel, and Supabase under an authenticated AppCare tenant and application.
- **FR-002**: The system MUST record the minimum approved capability scope for every connection and MUST reject capabilities that can deploy, mutate databases, delete data, or otherwise write to a provider.
- **FR-003**: The system MUST keep live credential values outside repository artifacts, logs, API responses, audit metadata, and job state; stored connection information MUST be limited to scoped, non-secret references and lifecycle metadata.
- **FR-004**: The system MUST verify that a connection and its discovered resources belong to the authenticated tenant before returning or persisting them.
- **FR-005**: The system MUST provide health, permission, and ownership outcomes for each connection using stable, sanitized states that do not disclose provider secrets or another tenant’s data.
- **FR-006**: The system MUST inventory GitHub repositories, Vercel projects/deployments, and Supabase project/auth/storage/database metadata only through read-only provider capabilities.
- **FR-007**: The system MUST reconcile repeated inventory snapshots idempotently using stable provider references and tenant ownership, without creating duplicate assets or destructive provider actions.
- **FR-008**: The system MUST preserve an auditable local history when a previously observed asset is absent from a later snapshot; connector reconciliation MUST NOT delete customer history.
- **FR-009**: The system MUST fail closed for expired, revoked, malformed, insufficiently scoped, or ambiguous credential/ownership results and MUST bound retries for provider failures.
- **FR-010**: The system MUST prevent one tenant from reading, updating, inventorying, or checking the health of another tenant’s connections, assets, jobs, or audit events.
- **FR-011**: The system MUST expose no deployment, database mutation, deletion, synchronization-write, or arbitrary provider-command operation in BETA-02.
- **FR-012**: The system MUST provide deterministic tests for least-privilege scope enforcement, revoked/expired credentials, redaction, tenant isolation, ownership checks, provider failures, and idempotent inventory.

### Key Entities

- **Connector**: A tenant-owned connection registration for one supported provider and application, with provider identity, safe lifecycle state, approved read-only capabilities, health status, permission status, and ownership status.
- **Scoped Credential Reference**: Non-secret metadata describing the credential authority, scope family, expiration/revocation state, and reference identity without containing the credential value.
- **Asset**: A tenant-owned provider resource discovered by inventory, with stable provider reference, resource type, safe display metadata, ownership evidence, and lifecycle state.
- **Inventory Snapshot**: A repeatable, auditable result set for one connector run, including a deterministic input/version marker, outcome, counts, and references to discovered assets without raw provider secrets.
- **Connector Check**: A sanitized health, permission, or ownership result attached to a connector and job, including status, reason code, checked time, and safe evidence references.

## Success Criteria

### Measurable Outcomes

- **SC-001**: 100% of connector capability tests reject deployment, mutation, deletion, or arbitrary provider-command permissions before a provider call is eligible.
- **SC-002**: 100% of cross-tenant connection, asset, health, inventory, job, and audit access attempts are denied without returning foreign data or secret-bearing error details.
- **SC-003**: 100% of deterministic expired, revoked, insufficient-scope, timeout, rate-limit, and malformed-response fixtures produce bounded sanitized outcomes with no credential value in logs, responses, audit metadata, or job state.
- **SC-004**: Replaying the same provider snapshot at least three times produces one stable asset set per provider reference with no duplicate inventory records.
- **SC-005**: A supported read-only connection can complete health, permission, ownership, and initial inventory checks using only approved read capabilities, with no deployment, database mutation, or deletion request emitted.
- **SC-006**: The complete BETA-02 deterministic, security, failure, dependency, secret, independent-review, and exact-head CI gates pass before merge.

## Assumptions

- AppCare users have already authenticated and selected an application they own; provider-specific account ownership remains subject to the explicit ownership check.
- BETA-02 uses fake provider responses and non-live credential metadata in automated tests; no production provider account is required for implementation or CI.
- Existing AppCare tenant authentication, tenant-scoped repositories, durable jobs, sanitized audit events, and no-production-write boundary are reused as the foundation.
- Provider capability names and ownership evidence are modeled through narrow connector contracts so the implementation can use approved adapters without exposing provider SDK authority to the rest of the application.
- Provider inventory is read-only in this beta; deployment, database mutation, deletion, write synchronization, and credential rotation execution are deferred to later explicitly authorized work.
- A missing or unavailable optional DeepSeek worker does not block Codex implementation, review, or release gates.
