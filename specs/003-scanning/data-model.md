# BETA-03 Data Model

## ScanContext

Represents the authorized execution scope.

- `scan_id`: stable scan identifier
- `tenant_id`: owning tenant identifier
- `target_id`: authorized application/asset identifier
- `target_kind`: bounded target category
- `requested_at`: deterministic testable timestamp metadata
- `adapter_allowlist`: permitted adapter categories

Validation: all identifiers are non-empty, normalized, and compared exactly; adapter execution requires a matching allowlist.

## ScannerObservation

Adapter-produced candidate data before finding creation.

- `adapter_kind`: source, secret, or dependency
- `rule_id`: normalized rule/check identifier
- `title` and `summary`: sanitized descriptive fields
- `location`: sanitized file, package, endpoint, or configuration location
- `raw_evidence`: untrusted adapter payload accepted only for immediate validation/sanitization
- `severity` and `confidence`: constrained values
- `asset_id`: target-bound affected asset

Validation: unsupported fields, secret-like values, invalid severity/confidence, and mismatched scope are rejected.

## EvidenceRecord

Deterministic sanitized proof for an observation or scanner failure.

- `evidence_id`: digest-derived identifier
- `kind`: observation or scanner_failure
- `source`: adapter and check identity
- `scope`: tenant and target identifiers
- `canonical_payload`: allowlisted sanitized data
- `digest`: hash of canonical payload
- `observed_at`: execution metadata

Evidence is immutable within a pipeline result and cannot contain raw credentials or secret-like values.

## Finding

Normalized security result derived only from valid evidence.

- `fingerprint`: deterministic identity across repeated scans
- `rule_id`, `title`, `description`, `location`
- `severity`, `confidence`
- `tenant_id`, `target_id`, `asset_id`
- `evidence_ids`: one or more retained evidence references
- `remediation`: descriptive metadata only in BETA-03
- `status`: active or suppressed

Fingerprint inputs: tenant, target, adapter kind, rule, asset, normalized location, severity, and evidence identity.

## ScannerFailure

Non-finding result for execution or validation failure.

- `failure_id`: deterministic failure identity
- `adapter_kind`
- `code`: timeout, unavailable, malformed_output, validation_error, out_of_scope, or secret_rejected
- `message`: sanitized diagnostic
- `scope`
- `evidence_id`
- `retryable`: explicit boolean

ScannerFailure MUST NOT have a finding fingerprint or severity classification.

## Suppression

Evidence-preserving false-positive decision.

- `fingerprint`
- `tenant_id`, `target_id`
- `reason`: required sanitized explanation
- `actor`: bounded actor identifier
- `status`: suppressed

Suppression is accepted only when its scope matches the finding scope and the target finding exists.
