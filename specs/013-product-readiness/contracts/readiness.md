# Contract: Product Readiness

## Capability evaluation

Input:

- tenant/application identity
- stack identity
- mandatory capability set
- evidence references

Output:

- one scoped result per mandatory capability
- deterministic supportability decision
- blocking/cleanup capability list

The evaluator fails closed for missing, stale, cross-scope, malformed, or wrong-class evidence.

## Readiness evaluation

Core readiness, stack readiness, customer-onboarding readiness, pilot readiness, and paid-service readiness are independent outputs.

A higher-level ready result requires all mandatory lower-level conditions declared for that level; a green core result alone cannot imply a green customer/pilot result.

## Evidence class contract

Allowed evidence classes:

- fixture
- reference
- controlled_live_provider
- real_target

A gate declares the minimum acceptable evidence class. A real-target requirement cannot be satisfied by fixture/reference evidence.

## Coordinator contract

Authoritative supportability/readiness decisions must be coordinator-approved. Worker/model summary text has no authority to promote readiness.

## Production contract

This feature cannot set a global live-production flag. Customer production operations remain governed by exact tenant/application/revision/artifact/action authorization and the existing production-control gates.
