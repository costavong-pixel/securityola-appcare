# BETA-03 Research Decisions

## Decision: Keep the first scanning foundation pure and provider-neutral

- **Rationale**: Existing AppCare control-plane and tenant-scope services are stable, while live scanner binaries and customer targets are explicitly out of scope. Pure domain contracts allow deterministic tests before adding runtime integrations.
- **Alternatives considered**: Run external scanners immediately; rejected because it would expand credentials, network, and production-target risk before the evidence contract is proven.

## Decision: Treat scanner failures as a separate result category

- **Rationale**: A timeout, unavailable tool, malformed output, or validation error is evidence about scan execution, not evidence that a vulnerability exists. Separate types make the invariant testable.
- **Alternatives considered**: Convert failures into low-confidence findings; rejected because it would create false positives and hide coverage gaps.

## Decision: Use canonical sanitized evidence for identity

- **Rationale**: Stable sorted serialization and a digest make repeated observations comparable even when scanners reorder fields. Sanitization prevents secrets or unsafe metadata from becoming persistent evidence.
- **Alternatives considered**: Use provider-native IDs only; rejected because provider IDs are not consistent across source, secret, and dependency scanners.

## Decision: Require tenant and target scope at both ingestion and result handling

- **Rationale**: Checking only at scan start leaves a boundary gap when results or suppression requests are replayed. Checking both sides prevents cross-tenant/cross-target evidence association.
- **Alternatives considered**: Trust adapter-owned scope; rejected because adapters are replaceable and untrusted inputs must be validated centrally.

## Decision: Preserve evidence during false-positive suppression

- **Rationale**: Suppression is a scoped decision about active presentation, not deletion of proof. Retaining evidence supports auditability and later review.
- **Alternatives considered**: Delete suppressed records; rejected because it destroys the ability to explain or reverse the decision.
