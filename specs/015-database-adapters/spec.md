# Spec 015: Database backup adapters

## Status

Design approved by Luna and Terra on 2026-08-29. This specification defines
the required AppCare repository behavior and evidence boundaries for database
backup adapters. It does not implement a live adapter, does not grant customer
production authority, and does not by itself change any readiness state.

## Goal

Provide AppCare's typed database backup adapter layer for MariaDB/MySQL and
PostgreSQL under the existing Spec 013 product-readiness governance, Spec 014
transport identity, and the current backup manifest/artifact pipeline.

The slice must establish safe, deterministic logical backup and isolated
restore-rehearsal rules for the `database_backup` capability while defining how
database evidence may contribute to `remote_readback` and `isolated_restore`
without overstating whole-application readiness.

## Non-goals

- arbitrary SQL, shell, or operator-supplied flags;
- direct plaintext credential handling in AppCare records, logs, prompts,
  worker packets, tests, or Git;
- production restore, production schema migration, or customer production write
  authority;
- physical volume snapshots, WAL/binlog/PITR, replication promotion, or
  cluster-wide disaster recovery;
- WordPress-only assumptions, named-customer assumptions, or a second
  readiness/supportability evaluator;
- promoting code-review, fixture, reference, or controlled-live-provider
  evidence to `real_target` readiness.

## User stories

### US1 - Typed target and broker boundary

As AppCare, I need a typed `DatabaseTarget` bound to a validated transport
identity and opaque credential reference so that database operations stay inside
 tenant/application scope and cannot become arbitrary remote execution.

### US2 - Consistent logical backups

As AppCare, I need logical backup policies for MariaDB/MySQL and PostgreSQL so
that bounded supported applications can produce repeatable database artifacts
without silently mixing incompatible consistency semantics.

### US3 - Verified readback and isolated restore

As AppCare, I need checksum-bound artifact verification and restore rehearsal
into an isolated target so that a successful dump is not confused with a usable
recovery point.

### US4 - Honest limitations

As the coordinator, I need unsupported engines, non-transactional tables,
cluster-wide objects, and other consistency limitations to remain explicit so
that AppCare does not claim a stronger recovery guarantee than the verified
adapter actually provides.

### US5 - Truthful readiness integration

As a release reviewer, I need Spec 015 evidence to feed Spec 013's existing
capability registry with exact evidence classes so that database-adapter design
or fixture passes cannot certify live customer readiness.

## Requirements

### R01. Typed database identity and scope

The adapter MUST require a validated `DatabaseTarget` containing:

- `tenant_id`, `application_id`, and `stack_id`;
- `environment`;
- `engine_family` of `mariadb_mysql` or `postgresql`;
- a typed transport binding referencing a validated Spec 014 target or a
  separately approved equivalent broker identity;
- an approved database identifier and exact logical database name;
- an opaque database credential reference;
- an opaque target reference;
- an approved tool profile and bounded policy values.

Every operation MUST bind to the target's tenant/application identity. A
credential, transport target, database identifier, or evidence item from
another tenant or application MUST fail before any broker execution.

### R02. Strict no-secret broker boundary

Database credentials MUST exist only as opaque references in AppCare state.
Secret values MAY be resolved only inside a protected database broker boundary
at execution time. Secret material MUST NOT enter:

- AppCare database records;
- logs, evidence, manifests, or reports;
- worker packets, prompts, or checkpoints;
- command-line arguments;
- repository files or fixtures.

The broker MAY use process-local environment variables or a process-local
ephemeral credential file under an approved AppCare temporary boundary, but it
MUST delete any such file before returning and MUST never persist it as
evidence.

### R03. Closed execution surface

The public database surface MUST expose typed operations only:

- `database_probe`
- `logical_dump`
- `logical_restore`
- `pre_restore_verify`
- `post_restore_verify`

There MUST be no public method accepting free-form SQL, free-form argv, shell
fragments, or operator-supplied binary paths. Every invocation MUST come from a
closed command registry with versioned template identifiers.

### R04. MariaDB/MySQL logical backup policy

MariaDB/MySQL support MUST use logical dumps only. The approved tool profile
MUST select one closed dump template family using `mariadb-dump` or
`mysqldump`, plus a closed restore template using `mysql` or an approved
compatible client.

The policy MUST:

- dump exactly one approved application database per request;
- include schema and supported logical objects required for bounded restore;
  programmable routines, events, triggers, `DEFINER` directives, and other
  executable context changes are rejected by the bounded restore profile and
  remain an explicit limitation;
- prefer consistent snapshot semantics that do not require unrestricted global
  locks;
- detect unsupported or unsafe conditions such as non-transactional engine
  dependency, mixed-engine consistency risk, dump-tool unavailability, or
  unsafe definer/state requirements;
- fail closed or surface `needs_cleanup` or `blocked_external` rather than
  silently claiming a healthy consistent backup.

### R05. PostgreSQL logical backup policy

PostgreSQL support MUST use logical dumps only. The approved tool profile MUST
select closed templates using `pg_dump`, `pg_restore`, and `psql`.

The default logical format MUST be a single bounded custom archive suitable for
typed restore and verification. The policy MUST:

- dump exactly one approved application database per request;
- include supported database-local schema objects required for bounded restore;
- reject cluster-wide backup tooling such as `pg_dumpall` for this slice;
- treat roles, tablespaces, replication state, WAL/PITR, and other
  cluster-global objects as outside the guaranteed restore scope unless a later
  spec explicitly adds them;
- surface missing extensions, ownership conflicts, or unsupported restore
  prerequisites as explicit blocked or cleanup outcomes.

### R06. Atomic bounded artifact output

Logical dump output MUST be written only into an AppCare-owned staging path and
must not become a visible backup component until the dump command exits
successfully, the byte cap is respected, and the final digest is sealed.

Spec 015 defines these hard maximums:

- logical dump artifact bytes per database: `536870912` bytes;
- stderr bytes per brokered database command: `65536` bytes;
- stdout bytes for non-dump verification commands: `262144` bytes.

The implementation MAY set lower limits per environment or target, but MUST NOT
raise these maxima without a protected spec amendment.

If a dump exceeds the cap, times out, is cancelled, disconnects, or exits with
an error, the staging artifact MUST be deleted and the operation MUST produce an
explicit failed outcome. Partial output MUST never be promoted into the backup
manifest.

### R07. Manifest, checksum, and identity binding

Each successful dump MUST produce deterministic metadata bound to:

- `backup_id`;
- `tenant_id`;
- `application_id`;
- `stack_id`;
- `target_reference`;
- `transport_target_reference`;
- `engine_family`;
- `database_identifier`;
- `logical_database_name`;
- `dump_format`;
- `tool_profile`;
- artifact byte count;
- dump artifact SHA-256;
- manifest digest;
- consistency mode and limitation codes;
- exact source revision and application artifact digest when those identities
  are genuinely available.

Readback verification MUST confirm that the persisted artifact, manifest, and
receipt all bind to the same backup identity. A mismatched checksum, manifest,
receipt digest, target, or database identity MUST fail closed.

### R08. Isolated restore target and post-restore verification

Restore rehearsal MUST target a typed `DatabaseRestoreTarget` in
`development`, `staging`, or `test` only. Production restore is out of scope
for this spec.

The restore target MUST include:

- tenant/application scope;
- engine family;
- isolated restore identity;
- restore transport/broker identity;
- exact restore database name or schema namespace;
- cleanup ownership information;
- verification profile.

Restore MUST happen only into an isolated approved target that does not
overwrite an existing authoritative database. A closed pre-restore empty-target
verification MUST run before mutation. On failure, partial restore state MUST
be cleaned up or durably quarantined with a visible failure code; quarantined
targets cannot be reused until an external reset.

Post-restore verification MUST use closed, typed verification templates only.
Verification MUST confirm:

- restored object presence;
- expected database identity;
- manifest/component identity;
- bounded integrity checks appropriate to the engine family;
- that the restored target is isolated and not production.

### R09. Consistency limitations must remain explicit

The adapter MUST record when a logical backup is not a full guarantee of
production-consistent recovery.

At minimum, explicit limitation handling MUST exist for:

- MariaDB/MySQL non-transactional tables or mixed-engine consistency risk;
- concurrent DDL or state drift detected during dump/restore;
- PostgreSQL roles, tablespaces, cluster-global settings, and other
  non-database-local objects outside spec scope;
- engine-version or extension requirements not present in the restore target;
- application assets stored outside the database.

A limitation MAY support `needs_cleanup` or `blocked_external`, but it MUST NOT
be hidden inside a superficially healthy success label.

### R10. Timeout, cancellation, and output limits

The default bounded limits for this spec are:

- probe timeout: 15 seconds;
- logical dump timeout: 15 minutes;
- logical restore timeout: 20 minutes;
- post-restore verification timeout: 60 seconds.

Cancellation or timeout MUST terminate the underlying process, close the broker
stream, remove incomplete staging output, and produce a deterministic failure
code. Malformed UTF-8, oversized stderr/stdout, or disconnected execution MUST
remain explicit bounded failures.

### R11. Idempotency, concurrency, and restart recovery

Every database backup and restore request MUST carry a durable idempotency key.

The policy MUST enforce:

- at most one active logical dump per exact
  `tenant_id/application_id/database_identifier/environment`;
- at most one active restore rehearsal per exact isolated restore target;
- same idempotency key plus same request identity returns the existing outcome;
- same idempotency key plus different request identity fails closed;
- no automatic replay of a partially completed restore after process restart.

If AppCare restarts during an in-flight dump or restore before authoritative
verification is sealed, the operation MUST enter a visible
`restart_recovery_required` or equivalent blocked state, require cleanup, and
must not claim a healthy result from partial state.

### R12. Spec 013 capability integration

Spec 015 MUST use Spec 013's existing capability registry, evidence classes,
supportability evaluator, downgrade logic, and coordinator approval boundary.
It MUST NOT introduce a second evaluator or readiness truth system.

The database adapter MUST emit authoritative `CapabilityEvidence` only when its
requirements are genuinely satisfied. The integration rules are:

- `database_backup` may become `supported` only after logical dump, readback,
  checksum, manifest, and coordinator verification succeed for the exact scope;
- database readback and restore rehearsal evidence MAY be persisted as scoped
  supporting evidence for `remote_readback` and `isolated_restore`, but MUST
  NOT independently mark the whole-application capabilities supported unless the
  matching non-database components for the same application backup identity are
  also present and verified;
- evidence class MUST remain one of `fixture`, `reference`,
  `controlled_live_provider`, or `real_target`;
- caller input MUST NOT relabel evidence to a stronger class.

### R13. Security-gate alignment

Spec 015 implementation and tests MUST contribute evidence toward:

- S04 credential custody;
- S05 remote execution boundary where the transport broker is used;
- S07 database safety;
- S08 backup integrity;
- S09 restore and recovery safety;
- S17 scheduler/worker boundaries where applicable;
- S21 privacy/logging;
- S23 resource and denial-of-service controls.

This is contribution evidence only. Spec 015 MUST NOT claim the complete
pre-beta security gate passed.

### R14. Explicit readiness outcome

This spec package alone does not promote any live capability. Until repository
implementation exists and real evidence is collected:

- `STACK_GENERIC_LINUX_READY` remains `NO`;
- `CUSTOMER_ONBOARDING_READY` remains `NO`;
- `PILOT_READY` remains `NO`;
- `PAID_SERVICE_READY` remains `NO`;
- `LIVE_CUSTOMER_PRODUCTION_ENABLED` remains `NO`.

Code implementation plus fixture or reference evidence still does not make a
customer-ready service. Live capability remains missing until downstream
implementation, security review, exact-head CI, and the required
`controlled_live_provider` and `real_target` evidence exist.

## Adversarial acceptance matrix

1. Wrong tenant, wrong application, wrong stack, or wrong transport target
   reference fails before broker execution.
2. Revoked, expired, missing, malformed, or cross-tenant credential references
   fail closed without exposing secret material.
3. Free-form SQL, extra argv, unapproved flags, alternate binaries, shell
   metacharacters, or shell wrappers are rejected before execution.
4. MariaDB/MySQL dump on unsupported or unsafe consistency conditions does not
   report a healthy consistent result.
5. PostgreSQL requests that require cluster-global objects outside scope are
   blocked or downgraded honestly.
6. Dump output above `536870912` bytes fails closed and deletes staging output.
7. Oversized stderr/stdout, malformed output, timeout, cancellation, or
   disconnect produces explicit bounded failure.
8. A persisted artifact with mismatched manifest digest, checksum, receipt
   digest, target identity, or database identity fails verification.
9. Duplicate idempotency keys do not create a second authoritative dump or
   restore outcome.
10. Concurrent dump or restore requests for the same exact scope do not race
    into duplicate authoritative results.
11. Restore into production, a non-isolated target, or an existing authoritative
    database is rejected.
12. Partial restore state is cleaned up or visibly quarantined and never
    reported as verified.
13. Post-restore verification failure prevents `database_backup`,
    `remote_readback`, or `isolated_restore` from being promoted.
14. Fixture, reference, or controlled-live-provider evidence cannot be relabeled
    as `real_target`.
15. A worker or model summary cannot self-approve supportability or readiness.
16. Restart during in-flight dump or restore requires explicit recovery and does
    not silently resume a mutable restore step.
17. Wrong-app or wrong-database restore from an otherwise valid artifact fails
    closed.
18. Secret-shaped stderr, manifest metadata, or verification output is rejected
    before it becomes evidence.
19. A successful database dump alone does not make the whole application's
    `remote_readback` or `isolated_restore` capability supported.
20. Merge of this implementation package without accepted live evidence does
    not change any live readiness or production-enabled flag.
