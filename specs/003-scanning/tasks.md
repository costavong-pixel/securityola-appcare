# BETA-03 Implementation Tasks

## Phase 1: Setup

- [ ] T001 Create the bounded scanning package structure in `appcare/scanning/__init__.py` and register the feature directory in `.specify/feature.json`
- [ ] T002 [P] Add seeded synthetic scanning fixtures in `tests/fixtures/scanning/vulnerable.json`, `tests/fixtures/scanning/duplicate.json`, `tests/fixtures/scanning/false_positive.json`, `tests/fixtures/scanning/malformed.json`, `tests/fixtures/scanning/out_of_scope.json`, and `tests/fixtures/scanning/scanner_failure.json`

## Phase 2: Foundational contracts and safety

- [ ] T003 Define immutable scan context, observation, evidence, finding, scanner failure, suppression, and adapter result models in `appcare/scanning/models.py`
- [ ] T004 [P] Define source, secret, and dependency adapter protocols and read-only result contracts in `appcare/scanning/contracts.py`
- [ ] T005 Implement tenant/target validation and adapter allowlist checks in `appcare/scanning/scope.py`
- [ ] T006 Implement sanitized canonical serialization, evidence digests, and deterministic fingerprints in `appcare/scanning/canonical.py`
- [ ] T007 Add unit coverage for contract validation, scope failures, canonical ordering, secret rejection, and fingerprint stability in `tests/unit/test_scanning.py`

## Phase 3: User Story 1 — Trustworthy findings [US1]

**Independent test**: A seeded vulnerable observation produces one normalized finding with stable evidence and fingerprint; duplicate observations converge without losing provenance.

- [ ] T008 [US1] Implement observation validation and sanitized evidence creation in `appcare/scanning/pipeline.py`
- [ ] T009 [US1] Implement finding normalization, severity/confidence constraints, and deterministic fingerprint assignment in `appcare/scanning/pipeline.py`
- [ ] T010 [US1] Implement duplicate grouping that preserves all evidence references in `appcare/scanning/pipeline.py`
- [ ] T011 [P] [US1] Add vulnerable and duplicate end-to-end assertions in `tests/integration/test_scanning.py`

## Phase 4: User Story 2 — Adapter boundaries and failures [US2]

**Independent test**: Source, secret, and dependency fixtures use the common adapter contract; malformed output and execution errors produce scanner failures and zero findings.

- [ ] T012 [US2] Implement bounded source, secret, and dependency adapter wrappers in `appcare/scanning/adapters.py`
- [ ] T013 [US2] Implement explicit scanner failure construction for timeout, unavailable, malformed, validation, and secret-rejected states in `appcare/scanning/models.py`
- [ ] T014 [US2] Implement failure-preserving pipeline branching that cannot assign severity or finding fingerprints to failures in `appcare/scanning/pipeline.py`
- [ ] T015 [P] [US2] Add adapter success, malformed-output, timeout, unavailable-tool, and secret-redaction tests in `tests/integration/test_scanning.py`

## Phase 5: User Story 3 — Tenant/target-safe suppression [US3]

**Independent test**: Matching scope succeeds; cross-tenant, cross-target, malformed-target, and invalid suppression requests fail closed with no out-of-scope evidence or finding.

- [ ] T016 [US3] Implement evidence-preserving, scope-checked false-positive suppression in `appcare/scanning/suppression.py`
- [ ] T017 [US3] Integrate scope enforcement before adapter execution and before finding/suppression result handling in `appcare/scanning/pipeline.py`
- [ ] T018 [P] [US3] Add out-of-scope, cross-tenant, cross-target, and invalid suppression tests in `tests/integration/test_scanning.py`

## Phase 6: Documentation and cross-cutting verification

- [ ] T019 [P] Update scanning architecture and security boundaries in `ARCHITECTURE.md` and `SECURITY.md`
- [ ] T020 [P] Document the synthetic scanning foundation and no-remediation boundary in `README.md` and `DEVELOPMENT.md`
- [ ] T021 Run focused and full deterministic tests plus Ruff, mypy, public-safety, worker-policy, build-lock, and dependency gates in the repository
- [ ] T022 Run negative/failure/security tests, inspect the actual diff with Luna/Codex Security, and record any repair loop in `.token-saver/beta03-final-gates/`

## Dependencies

```text
T001 → T003–T006 → T007 → T008–T010 → T012–T015 → T016–T018 → T019–T022
T002 can run in parallel with T001.
T011 can run in parallel with T008–T010 after contracts exist.
T015 and T018 can run in parallel after pipeline branches exist.
```

## MVP scope

T001–T011 provide the minimum useful evidence-backed finding pipeline. T012–T018 are required for the BETA-03 acceptance gate because adapter failure separation and tenant boundaries are security-critical, not optional polish.

## Implementation strategy

Implement contracts and canonical safety first, then deliver the vulnerable/duplicate finding path, add adapter and failure branches, add suppression and boundary negatives, and finish with full deterministic/security/CI evidence. No task grants a worker architecture, security approval, release, merge, or deployment authority.
