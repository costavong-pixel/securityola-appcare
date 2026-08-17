# Feature Specification: Evidence-Backed Security Scanning Foundation

**Feature Branch**: `codex/beta-03-scanning`

**Created**: 2026-08-17

**Status**: Draft

**Input**: User description: Build the BETA-03 scanning foundation with deterministic evidence, source/secret/dependency scanner boundaries, normalized findings, deduplication, separate scanner failures, tenant/target enforcement, and seeded vulnerability and false-positive fixtures.

## User Scenarios & Testing

### User Story 1 - Produce trustworthy findings (Priority: P1)

As an AppCare scan consumer, I need scanner output to become a finding only after validation, scope checks, deterministic evidence capture, normalization, deduplication, and severity/confidence assignment, so that security decisions are grounded in repeatable evidence.

**Why this priority**: A trustworthy finding pipeline is the minimum useful security product and prevents unsupported AI or scanner claims.

**Independent Test**: Run the pipeline against seeded vulnerable and duplicate inputs and verify deterministic evidence, normalized fields, stable fingerprints, one deduplicated finding, and preserved source references.

**Acceptance Scenarios**:

1. **Given** a valid in-scope scanner observation, **When** it passes the pipeline, **Then** the system emits a normalized finding linked to deterministic evidence.
2. **Given** two observations with the same target, rule, location, and normalized evidence, **When** they are processed, **Then** they converge on one stable finding identity while retaining evidence provenance.
3. **Given** a known false-positive observation with a recorded suppression reason, **When** it is processed, **Then** the finding is suppressed without deleting or hiding its evidence.

### User Story 2 - Integrate scanners without coupling failures to findings (Priority: P1)

As an AppCare scanner operator, I need source, secret, and dependency scanners behind explicit contracts, so that each adapter can be replaced, tested with fixtures, and reported consistently without leaking provider-specific behavior.

**Why this priority**: Scanner diversity is necessary for useful coverage, but adapters must remain bounded and interchangeable.

**Independent Test**: Execute each adapter against seeded success, malformed-output, and execution-error fixtures and verify the common observation contract and distinct scanner failure state.

**Acceptance Scenarios**:

1. **Given** a source, secret, or dependency adapter with valid output, **When** it completes, **Then** its observations enter the common validation pipeline.
2. **Given** an adapter timeout, malformed result, or unavailable tool, **When** the scan runs, **Then** the system records a scanner failure with diagnostic evidence and emits no finding for that failure.
3. **Given** a secret-like scanner result, **When** it is normalized, **Then** raw secret material is rejected or redacted before persistence or response serialization.

### User Story 3 - Keep scanning tenant- and target-safe (Priority: P1)

As an AppCare tenant, I need every scan and finding to remain bound to the authorized tenant and target, so that one customer cannot inspect or influence another customer’s evidence.

**Why this priority**: A cross-tenant or cross-target finding is a security failure even when the scanner result itself is accurate.

**Independent Test**: Submit matching and mismatching tenant/target contexts, including duplicate and suppression requests, and verify allowed cases succeed while boundary violations fail closed without persistence.

**Acceptance Scenarios**:

1. **Given** a scan context and observation for the same authorized tenant and target, **When** it is processed, **Then** evidence and findings retain that scope.
2. **Given** an observation or suppression request for a different tenant or target, **When** it is processed, **Then** the request is rejected and no evidence or finding crosses the boundary.
3. **Given** an empty, malformed, or untrusted target identifier, **When** it is submitted, **Then** the scan fails safely before adapter execution.

## Edge Cases

- Scanner output is empty, truncated, duplicated, malformed, or contains unsupported severity/confidence values.
- A scanner reports the same issue at different textual locations or with reordered evidence fields.
- A target is deleted, disabled, renamed, or belongs to another tenant between scan start and result ingestion.
- A scanner process exits successfully but returns an invalid schema.
- A scanner process fails after producing partial output.
- A finding contains a credential-like locator, raw secret, private key, or unsafe metadata.
- A false-positive suppression is missing a reason, references another tenant, or attempts to suppress a scanner failure.
- A repeated scan receives the same observation in a different order.

## Requirements

### Functional Requirements

- **FR-001**: The system MUST define provider-neutral contracts for source, secret, and dependency scanner adapters.
- **FR-002**: The system MUST validate scanner observations before they enter evidence or finding processing.
- **FR-003**: The system MUST enforce the authorized tenant and target scope before adapter execution and before persistence or response.
- **FR-004**: The system MUST create deterministic evidence records containing a stable digest, source adapter identity, target scope, and sanitized observation details.
- **FR-005**: The system MUST normalize valid observations into findings with stable severity, confidence, affected asset, remediation metadata, and evidence references.
- **FR-006**: The system MUST generate a deterministic fingerprint from normalized scope, rule, location, and evidence identity fields.
- **FR-007**: The system MUST deduplicate observations with the same fingerprint without discarding their evidence provenance.
- **FR-008**: The system MUST represent scanner execution, timeout, unavailable-tool, malformed-output, and validation failures separately from findings.
- **FR-009**: The system MUST preserve evidence when a finding is suppressed and MUST require a tenant-scoped suppression reason.
- **FR-010**: The system MUST reject or redact credential-like values and unsafe metadata before persistence, logs, or responses.
- **FR-011**: The system MUST provide seeded vulnerable, duplicate, false-positive, malformed, out-of-scope, and scanner-failure fixtures.
- **FR-012**: The system MUST not perform remediation writes, deployment, production access, provider authorization, or AI explanation in this feature.

### Key Entities

- **ScanContext**: Authorized tenant, target, scan identity, and bounded execution metadata.
- **ScannerObservation**: Adapter-produced candidate observation before normalization.
- **EvidenceRecord**: Deterministic, sanitized proof attached to an observation or failure.
- **Finding**: Normalized security result with severity, confidence, fingerprint, scope, lifecycle, and evidence references.
- **ScannerFailure**: Explicit non-finding state describing adapter or pipeline failure and its sanitized evidence.
- **Suppression**: Tenant-scoped decision that hides a finding from active results while retaining evidence and reason.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Every seeded valid vulnerability produces the same finding fingerprint and evidence digest across repeated runs.
- **SC-002**: Every seeded duplicate pair produces one active finding with both source observations represented in evidence provenance.
- **SC-003**: Every seeded false positive is suppressible only with a valid scope and recorded reason; its evidence remains queryable in the test result.
- **SC-004**: Every seeded scanner error produces a scanner failure and zero findings.
- **SC-005**: Every seeded cross-tenant or cross-target case is rejected before persistence and leaves no out-of-scope finding or evidence.
- **SC-006**: The full deterministic test suite, static checks, safety checks, dependency audit, security review, and exact-head CI pass without production or WordPress access.

## Assumptions

- Scan execution is initiated by an already authenticated AppCare control-plane context.
- Provider-specific scanner binaries and live customer targets are out of scope; adapters use deterministic synthetic inputs in this beta.
- Evidence is sanitized and public-safe; raw secrets and customer content are never fixtures.
- AI explanation, remediation, and deployment are later beta capabilities and cannot be invoked by this foundation.
