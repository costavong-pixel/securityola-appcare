# Spec 015 research and decisions

## Existing repository evidence

- Spec 013 already defines the mandatory capability matrix, evidence classes,
  exact tenant/application/stack scope validation, coordinator approval, and
  fail-closed readiness reporting.
- Spec 014 already defines typed transport identity, closed command registries,
  opaque credential references, output limits, and the no-arbitrary-shell
  boundary AppCare should reuse for database execution.
- The current backup pipeline already enforces canonical manifests, artifact
  SHA-256 digests, isolated restore rehearsal, readback verification, and
  tenant/application-scoped vault lookups.
- The current backup domain is provider-neutral and intentionally avoids live
  cloud or customer mutations without explicit authorized adapters.
- The gap register marks `Database backup adapters` as a P0 missing capability
  and requires MariaDB/MySQL and PostgreSQL backup/restore adapters with
  credential-safe invocation, checksum validation, isolated restore, and
  post-restore integrity checks.
- The pre-beta security gate explicitly requires database safety, backup
  integrity, restore isolation, concurrency handling, size limits, restart
  handling, and honest evidence.

## Decisions

### D1. Reuse transport identity instead of inventing a new remote target

Database operations must bind to a validated transport identity rather than a
fresh host/socket model. The current generic path is the Spec 014 Linux target,
referenced by opaque `transport_target_reference`.

This keeps AppCare's target truth in one place and prevents a second shadow
remote-target model from bypassing host identity and tenant scope checks.

### D2. Use a no-secret database broker

Database credentials must resolve only inside a protected broker boundary. The
broker receives a typed operation and closed tool profile, injects the secret
transiently, and returns only bounded sanitized metadata plus a staged dump
artifact handle.

Direct application-level DSNs, passwords in argv, or credential values in
fixtures/logs/evidence are rejected.

### D3. MariaDB/MySQL uses logical dump semantics only

This slice does not attempt physical backup, filesystem-level hot copies, or
binlog/PITR. The supported path is one logical dump for one approved
application database using a closed `mariadb-dump` or `mysqldump` profile and a
closed `mysql` restore profile.

This aligns with the bounded-support promise and avoids claiming cluster-wide or
host-wide recovery behavior the repo does not yet model.

### D4. PostgreSQL uses a bounded custom archive

The PostgreSQL default is a single custom archive produced by a closed
`pg_dump` profile and restored via `pg_restore`, with `psql` reserved for
bounded post-restore verification templates.

This provides typed restore behavior without introducing free-form SQL or
claiming full cluster capture through `pg_dumpall`.

### D5. Keep artifact output staged and byte-capped

The current backup pipeline already treats artifact integrity as authoritative.
Database adapters therefore stage output under the AppCare backup boundary,
stream SHA-256 while writing, enforce a `536870912` byte cap, and only promote
completed artifacts into the manifest after successful exit.

This keeps partial or oversized dumps from masquerading as valid backup
components.

### D6. Post-restore verification must be template-driven

Restore success is not a healthy result by itself. Verification templates must
be closed and typed per engine family. They may check identity, object presence,
and bounded integrity markers, but they may not expose arbitrary ad hoc SQL.

This preserves AppCare's no-arbitrary-command boundary even during restore
rehearsal.

### D7. Consistency limitations stay visible

Logical dumps do not automatically guarantee complete production-consistent
recovery for every engine shape. Non-transactional MariaDB/MySQL tables,
concurrent DDL, PostgreSQL cluster-global objects, extension prerequisites, and
external file assets must stay explicit limitation codes or blocked states.

This is required by the constitution's product-completeness rule and prevents a
backup receipt from overstating what recovery has been proven.

### D8. Database evidence contributes to, but does not replace, whole-app
restore evidence

Spec 015 can authorize `database_backup` evidence when its own requirements are
met. It may also contribute supporting evidence to `remote_readback` and
`isolated_restore`, but it cannot by itself certify those whole-application
capabilities without matching filesystem and off-site evidence bound to the
same backup identity.

### D9. Restart during mutable restore must fail closed

The current repository already treats restart durability and duplicate delivery
as security-sensitive. Database restore is mutable even in isolated rehearsal,
so restart cannot silently resume a partially applied restore step. The correct
outcome is explicit recovery-required status plus cleanup and rerun.

### D10. The spec package is not live capability evidence

Documentation, design approval, and later repository tests are still not
customer-readiness proof. Controlled live provider and real-target evidence
remain separate evidence classes under Spec 013, and AppCare must continue to
report `STACK_GENERIC_LINUX_READY=NO` and higher readiness levels `NO` until
downstream implementation and live evidence exist.

## Rejected alternatives

- Direct database network access from AppCare application code with a persisted
  DSN: rejected because it expands secret exposure and bypasses transport
  identity controls.
- Free-form SQL verification queries: rejected because they weaken the
  no-arbitrary-command boundary and make evidence non-deterministic.
- Passwords or tokens in command-line arguments: rejected because argv can leak
  through logs, process tables, crash reports, or worker summaries.
- Physical database copies or raw volume snapshots: rejected because they are a
  different capability class with different consistency and restore guarantees.
- Treating a database-only restore as whole-application `isolated_restore`
  support: rejected because AppCare recovery requires matching filesystem,
  configuration, and runtime evidence.
- Promoting fixture or reference test results to live support claims: rejected
  by Spec 013 and the constitution.

## Known live boundary

The repository currently contains backup primitives and read-only transport
identity, but it does not yet contain the live database broker or per-engine
adapter implementation this spec describes. A future implementation may pass
repository tests and still remain `NOT RUN` or `UNVERIFIED` for live capability
until an authorized bounded acceptance collects `controlled_live_provider` and
then `real_target` evidence.
