# Spec 014 tasks

Tasks are dependency ordered. No task authorizes production mutation.

## Specification and review

- [x] T001 Read Spec 013 governance and repository connector conventions
- [x] T002 Write Spec 014 requirements, threat model, data model, and contracts
- [x] T003 Luna reviews the complete Spec 014 artifacts and records scope/threat approval
- [x] T004 Run repository-native consistency analysis and resolve contradictions

## Contracts and validators

- [x] T005 Add immutable LinuxTarget and operation/result contracts
- [x] T006 Add strict host/address/fingerprint/identity validators
- [x] T007 Add approved-root/system-path/service/database validators
- [x] T008 Add opaque credential-provider and lifecycle interfaces
- [x] T009 Add bounded execution and normalized evidence contracts

## Trusted execution

- [x] T010 Add closed typed command registry with read-only capability classes
- [x] T011 Add shell-free bounded OpenSSH runner behind a protocol
- [x] T012 Add pre-registered host-key verification and target-scoped known-hosts handling
- [x] T013 Add credential scope/revocation/expiry enforcement at the transport boundary
- [x] T014 Add fail-closed operation/replay/timeout/output-limit handling

## Inventory

- [x] T015 Implement typed connection and host inventory collectors
- [x] T016 Implement typed filesystem metadata and safe-file collectors
- [x] T017 Implement web-server, runtime, service, and network collectors
- [x] T018 Implement storage/application-root collectors and partial results
- [x] T019 Implement deterministic normalization and sanitization

## Spec 013 integration

- [x] T020 Emit scoped CONNECT/INVENTORY CapabilityEvidence
- [x] T021 Integrate with ApplicationCapabilityRegistry and SupportabilityEvaluator
- [x] T022 Verify downstream capabilities remain MISSING_CAPABILITY

## Tests and gates

- [x] T023 Add positive typed-operation and inventory tests
- [x] T024 Add host-key, credential, tenant, path, symlink, command, output, timeout, and replay negative tests
- [x] T025 Add secret-shaped output and evidence sanitization tests
- [x] T026 Add fixture-vs-real evidence-class tests
- [x] T027 Run full tests, Ruff, mypy, dependency scan, and secret scan
- [x] T028 Run Codex Security diff scan and repair/retest any finding
- [ ] T029 Run Graphify impact review and final update
- [ ] T030 Run exact-head CI and protected PR review
- [ ] T031 Perform bounded live read-only acceptance only with an existing trust anchor
- [ ] T032 Record accurate final readiness/capability disposition and checkpoint

