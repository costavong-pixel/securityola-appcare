# BETA-04 Implementation Tasks

## Phase 1 — specification and boundary

- [ ] T001 Register `specs/004-backup-restore` and update the active Speckit marker.
- [ ] T002 Record the candidate-skill audit and reject unreviewed live-provider skills.
- [ ] T003 Define target, destination, source, vault, encryption, manifest, and restore contracts.

## Phase 2 — verified artifact

- [ ] T004 Implement encrypted artifact envelope and canonical checksums.
- [ ] T005 Implement immutable test-vault semantics and append-only job evidence.
- [ ] T006 Implement backup verification and distinct unhealthy failure states.

## Phase 3 — isolated restore

- [ ] T007 Implement staged restore and atomic promotion into a non-production destination.
- [ ] T008 Add synthetic Git/database/storage/config fixture source.
- [ ] T009 Add restore and RPO/RTO evidence tests.

## Phase 4 — pressure tests and gates

- [ ] T010 Test interrupted upload, corruption, revoked credentials, duplicate jobs,
  large data, partial restore, retention expiry, and locked deletion.
- [ ] T011 Run static, dependency, public-safety, worker-policy, security, Graphify,
  Saveruflo, independent review, and exact-head CI gates.
- [ ] T012 Close issue #5 only if live-provider acceptance is either verified with
  authorized credentials or explicitly recorded as an owner-controlled blocker.
