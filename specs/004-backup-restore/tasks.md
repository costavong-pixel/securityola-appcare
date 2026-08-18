# BETA-04 Implementation Tasks

## Phase 1 — specification and boundary

- [x] T001 Register `specs/004-backup-restore` and update the active Speckit marker.
- [x] T002 Record the candidate-skill audit and reject unreviewed live-provider skills.
- [x] T003 Define target, destination, source, vault, encryption, manifest, and restore contracts.

## Phase 2 — verified artifact

- [x] T004 Implement encrypted artifact envelope and canonical checksums.
- [x] T005 Implement immutable test-vault semantics and append-only job evidence.
- [x] T006 Implement backup verification and distinct unhealthy failure states.

## Phase 3 — isolated restore

- [x] T007 Implement staged restore and atomic promotion into a non-production destination.
- [x] T008 Add synthetic Git/database/storage/config fixture source.
- [x] T009 Add restore and RPO/RTO evidence tests.

## Phase 4 — pressure tests and gates

- [x] T010 Test interrupted upload, corruption, revoked credentials, duplicate jobs,
  large data, partial restore, retention expiry, and locked deletion.
- [ ] T011 Run static, dependency, public-safety, worker-policy, security, Graphify,
  Saveruflo, independent review, and exact-head CI gates. Local BETA-04 tests,
  Ruff, mypy, public-safety, Graphify, and live evidence are complete; exact-head
  CI and protected-merge verification remain.
- [ ] T012 Close issue #5 only if live-provider acceptance is either verified with
  authorized credentials or explicitly recorded as an owner-controlled blocker.
