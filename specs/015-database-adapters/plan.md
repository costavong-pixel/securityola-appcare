# Spec 015 implementation plan

## Scope

Define the repository-native implementation plan for typed MariaDB/MySQL and
PostgreSQL logical backup adapters inside the existing AppCare backup and
readiness boundaries.

The implementation must extend current backup primitives without introducing
arbitrary SQL, plaintext credential custody, or false-ready claims. This plan
does not authorize production restore, deployment mutation, or customer
production database access.

## Inputs

- `.specify/memory/constitution.md`
- `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`
- `docs/security/PRE_BETA_SECURITY_GATE.md`
- `specs/013-product-readiness/`
- `specs/014-generic-linux-ssh/`
- `specs/004-backup-restore/`
- `appcare/backups/contracts.py`
- `appcare/backups/models.py`
- `appcare/backups/pipeline.py`
- `appcare/readiness/contracts.py`
- `appcare/readiness/registry.py`

## Constitution check

| Principle | Design response | Status |
|---|---|---|
| Security before speed | Closed broker/templates, explicit caps, no arbitrary SQL, and fail-closed outcomes. | PASS |
| Deterministic evidence before AI claims | Spec 013 capability evidence remains authoritative; design approval is not live evidence. | PASS |
| Least privilege and tenant isolation | Targets, credentials, transport identity, and restore scope remain exact tenant/application bound. | PASS |
| No secrets in artifacts | Opaque references only; broker-only secret resolution; no secret argv or evidence. | PASS |
| Staging, backup, and reversibility before production | Restore remains isolated and non-production; no production authority is introduced. | PASS |
| AppCare and WordPress remain separate | Product markers and namespaces remain rejected by current backup boundaries. | PASS |
| Coordinator owns final decisions | Workers may not self-approve capability or readiness. | PASS |
| Product completeness is invariant | Database adapter design contributes one missing capability but does not close the full live-support matrix. | PASS |

## Design slices

### Slice A - contracts and typed targets

Add immutable database contracts for:

- `DatabaseTarget`
- `DatabaseTransportBinding`
- `DatabaseCredentialMetadata`
- `DatabaseDumpRequest`
- `DatabaseDumpArtifact`
- `DatabaseRestoreTarget`
- `DatabaseRestoreEvidence`

Reuse Spec 013 validators and evidence classes where practical. Reuse Spec 014
transport identity rather than inventing a second remote-target model.

### Slice B - database execution broker

Introduce a no-secret broker protocol that:

- resolves only opaque credential references;
- binds to an approved transport target identity;
- executes only closed command templates;
- streams dump bytes into an AppCare-owned staging file with live byte counting;
- returns bounded exit status and sanitized metadata only.

The broker is the sole place where a secret may exist transiently in memory or
an ephemeral process-local file.

### Slice C - per-engine command profiles

Implement closed, versioned command profiles for:

- MariaDB/MySQL logical dump
- MariaDB/MySQL logical restore
- MariaDB/MySQL post-restore verification
- PostgreSQL logical dump
- PostgreSQL logical restore
- PostgreSQL post-restore verification

The caller chooses only the validated engine family and approved tool profile.
The registry chooses the exact argv template. No free-form SQL is exposed.

### Slice D - staging artifact and manifest integration

Extend the backup pipeline with bounded staging support for database dumps:

- create staging file inside the existing AppCare backup boundary;
- compute SHA-256 while streaming;
- enforce the `536870912` byte hard cap;
- promote only after successful exit and complete digest sealing;
- record limitation codes and dump format in deterministic manifest metadata;
- delete incomplete staging files on failure, timeout, or cancellation.

This slice may require a repository-native adjustment from in-memory
`BackupComponent.payload: bytes` handling toward a bounded staged-file or stream
promotion path for database components.

### Slice E - isolated restore rehearsal

Restore database artifacts only into an approved isolated target:

- non-production environment only;
- exact tenant/application/isolation identity;
- no overwrite of authoritative databases;
- cleanup or quarantine of partial state on failure;
- closed post-restore verification templates for each engine family.

The restore result becomes evidence only after restore plus verification both
pass.

### Slice F - Spec 013 evidence integration

Emit `CapabilityEvidence` through the existing Spec 013 registry:

- authoritative `database_backup` only after verified dump/readback;
- supporting evidence for database portions of `remote_readback` and
  `isolated_restore`;
- no whole-application promotion unless matching filesystem and database
  components bind to the same backup identity and verification bundle.

Readiness wording stays truthful: code and reference evidence are not live
customer support.

### Slice G - deterministic and adversarial tests

Add unit, contract, and integration coverage for:

- target validation and scope binding;
- broker secret boundary and argv closure;
- per-engine dump/restore/verify template selection;
- dump truncation, timeout, cancellation, disconnect, and malformed output;
- checksum, manifest, and receipt mismatch;
- cross-tenant, wrong-app, wrong-engine, and wrong-target restore rejection;
- restart recovery, duplicate idempotency, and same-target concurrency;
- consistency limitation detection and honest status mapping;
- evidence-class downgrade and no self-approval behavior.

## Data flow

Validated `DatabaseTarget`
-> `DatabaseCredentialProvider.resolve(reference)`
-> typed `DatabaseExecutionBroker`
-> closed engine/tool profile
-> bounded staging dump artifact
-> checksum + manifest binding
-> existing backup vault readback verification
-> isolated `DatabaseRestoreTarget`
-> closed post-restore verification
-> Spec 013 capability evidence
-> `ApplicationCapabilityRegistry`
-> `SupportabilityEvaluator`

No direct raw SQL, no plaintext DSN persistence, and no production restore step
exists in this flow.

## Verification strategy

- focused unit tests for validators, template registry, caps, and status
  mapping;
- integration tests with fake broker implementations and isolated local
  databases or deterministic fixtures;
- restart, duplicate, concurrency, timeout, truncation, and corruption tests;
- full deterministic test suite, Ruff, mypy, dependency scan, public-safety
  scan, Codex Security diff scan, Graphify update, Saveruflo checkpoint, and
  exact-head CI before implementation is considered merge-ready;
- any live run remains a later bounded acceptance and must not be implied by
  this documentation package.

## Rollback

The repository change is documentation only at this stage. Future implementation
work must remain isolated to AppCare-owned backup, readiness, connector, and
test surfaces and can be reverted through the protected review path. No live
database target is modified by this plan alone.
