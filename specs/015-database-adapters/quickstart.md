# Spec 015 quickstart

This quickstart describes the intended safe API shape. It is not a production
runbook and it does not provide a credential.

## 1. Register a typed database target

Construct `DatabaseTarget` with:

- exact `tenant_id`, `application_id`, and `stack_id`;
- `engine_family` of `mariadb_mysql` or `postgresql`;
- a validated `transport_target_reference`;
- an approved `database_identifier` and `logical_database_name`;
- an opaque `credential_reference`;
- a closed `tool_profile`;
- bounded byte and timeout policy values.

Reject the target if any value is out of scope, cross-tenant, oversized, or not
normalized.

## 2. Run a logical dump through the broker

Create `DatabaseDumpRequest` with a new `backup_id`, durable
`idempotency_key`, and the validated target. Pass it to the typed database
broker.

The broker may execute only a closed dump template for the target's engine
family. It streams output into an AppCare-owned staging artifact, counts bytes,
computes SHA-256, and deletes incomplete output on failure. There is no
free-form SQL or free-form command mode.

## 3. Seal the artifact into the backup pipeline

Promote the completed database dump only after:

- exit status is successful;
- artifact bytes stay within `536870912`;
- manifest metadata is complete;
- readback verification matches the artifact digest and manifest digest.

Do not report `database_backup` as supported from a dump receipt alone.

## 4. Restore only into an isolated rehearsal target

Construct `DatabaseRestoreTarget` in `development`, `staging`, or `test`. The
target must use an isolated restore database name and exact tenant/application
scope.

Run the closed pre-restore empty-target check, followed by restore and
post-restore verification templates. Restore input is streamed from the
checksum-verified artifact; it is not supplied as a caller-controlled path.
If restore is interrupted, partial, wrong-engine, wrong-target, or
verification-failed, the result is failed or recovery-required and the target
is cleaned up or durably quarantined. A quarantined target cannot be reused
until an external reset.

## 5. Evaluate through Spec 013

Emit Spec 013 `CapabilityEvidence` only from verified results:

- `database_backup` after dump plus readback verification;
- supporting evidence refs for the database portions of `remote_readback` and
  `isolated_restore` when restore rehearsal also passes.

Then evaluate through the existing `ApplicationCapabilityRegistry` and
`SupportabilityEvaluator`. Keep higher readiness states blocked until the rest
of the mandatory capability matrix has real evidence.

## 6. Keep the live boundary honest

Fixture and reference testing are useful engineering evidence, but they are not
customer-readiness proof. Even after code exists, live capability remains
missing until bounded `controlled_live_provider` and later `real_target`
evidence are collected and reviewed.
