# Inventory and evidence contract

## Required scope

Every record binds:

- tenant ID;
- application ID;
- stable target reference;
- operation kind;
- normalized identity;
- safe metadata;
- observed timestamp;
- source reference;
- evidence class;
- digest.

## Evidence classes

- FIXTURE: injected deterministic test data only.
- REFERENCE: controlled reference environment, not a customer target.
- CONTROLLED_LIVE_PROVIDER: provider-controlled test evidence.
- REAL_TARGET: an actual authorized target. It requires the live operation
  and cannot be asserted by a caller.

The class is assigned by the coordinator-controlled execution context. A
payload field or worker claim cannot upgrade it.

## Normalization

Normalize identifiers case-consistently, sort record collections by stable
identity, allowlist metadata keys, bound all strings, reject unsafe text, and
hash the canonical JSON representation. Raw remote output is transient only.

## Spec 013 adapter

The adapter emits CapabilityEvidence with the target scope and evidence
class. connect is passed only when the strict connection probe succeeds.
inventory is passed only when required typed inventory is safe and complete.
Otherwise an explicit failure/partial result is emitted. The existing
supportability evaluator resolves the final status.

