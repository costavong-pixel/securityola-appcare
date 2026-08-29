# Spec 015 tasks

Tasks are dependency ordered. No task authorizes production restore or customer
production database access.

## Specification and review

- [x] T001 Confirm Spec 013, Spec 014, and current backup-pipeline boundaries for database adapter scope.
- [x] T002 Finalize Spec 015 contracts, plan, data model, security contract, readiness contract, and checklist.
- [x] T003 Record Luna/Terra scope approval and repository-native consistency review for the Spec 015 package.
- [x] T004 Resolve any contradiction with the constitution, gap register, pre-beta security gate, or current backup contracts before implementation starts.

## Contracts and validators

- [x] T005 Add immutable database target, transport binding, credential metadata, dump request, artifact, and restore target contracts.
- [x] T006 Add strict validators for engine family, database identifiers, logical database names, tool profiles, byte caps, and timeout bounds.
- [x] T007 Add tenant/application/stack binding checks between database target, transport identity, credential metadata, and manifest evidence.
- [x] T008 Add closed per-engine command template registry with no free-form SQL or argv path.

## Broker and staging pipeline

- [x] T009 Add a no-secret database execution broker protocol and a deterministic fake broker for tests.
- [x] T010 Add transient credential injection that never exposes plaintext values in argv, logs, evidence, or fixtures.
- [x] T011 Add bounded staging artifact writing with streaming SHA-256 and the `536870912` byte cap.
- [x] T012 Add failure handling for timeout, cancellation, disconnect, malformed output, and dump truncation.
- [x] T013 Add manifest metadata binding for engine family, dump format, tool profile, consistency mode, and limitation codes.

## MariaDB/MySQL adapter

- [x] T014 Implement MariaDB/MySQL probe, logical dump, restore, and post-restore verification templates.
- [x] T015 Detect and report unsupported or limited-consistency conditions such as non-transactional tables or mixed-engine risk.
- [x] T016 Ensure MariaDB/MySQL restore rehearsal uses only isolated non-production targets and deterministic cleanup.

## PostgreSQL adapter

- [x] T017 Implement PostgreSQL probe, custom-archive dump, restore, and post-restore verification templates.
- [x] T018 Block cluster-global backup paths and surface extension, ownership, or role prerequisites as explicit outcomes.
- [x] T019 Ensure PostgreSQL restore rehearsal uses only isolated non-production targets and deterministic cleanup.

## Existing backup-pipeline integration

- [x] T020 Integrate staged database artifacts with the existing backup manifest and vault readback flow.
- [x] T021 Bind dump/readback evidence to exact `backup_id`, target, and artifact digest.
- [x] T022 Persist restore-rehearsal evidence with explicit verified, failed, and restart-recovery-required outcomes.

## Spec 013 integration

- [x] T023 Emit authoritative `database_backup` `CapabilityEvidence` only from verified dump/readback outcomes.
- [x] T024 Emit supporting evidence refs for the database portions of `remote_readback` and `isolated_restore` without falsely promoting whole-application support.
- [x] T025 Verify the existing `SupportabilityEvaluator` remains the only readiness/supportability authority.
- [x] T026 Add downgrade-path coverage so real-target missing capability evidence can still invalidate readiness later.

## Tests and gates

- [x] T027 Add positive unit and integration tests for each engine family's dump, readback, restore, and verification flow.
- [x] T028 Add adversarial tests for credential leakage, wrong tenant/app/stack, wrong target, wrong engine, wrong database, arbitrary SQL, argv injection, oversized output, timeout, cancellation, disconnect, corruption, duplicate idempotency, restart, and same-target concurrency.
- [x] T029 Add evidence-class tests proving fixture, reference, and controlled-live-provider results cannot become `real_target`.
- [x] T030 Add tests that a database-only success cannot independently promote whole-application `remote_readback` or `isolated_restore`.
- [ ] T031 Run full deterministic/static/security suite, Codex Security diff scan, Graphify review, Saveruflo checkpoint, and exact-head CI.
- [ ] T032 Record accurate final capability and readiness disposition with unverified live boundaries left explicit.
