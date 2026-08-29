# Spec 015 requirements checklist

## Scope and readiness

- [ ] Spec 015 stays within `TARGET=AppCare` and touches only database backup adapter behavior.
- [ ] Spec 013 remains the only capability, supportability, and readiness authority.
- [ ] The spec does not imply `STACK_GENERIC_LINUX_READY=YES` or any higher readiness state.
- [ ] The spec states plainly that code or live capability is not promoted by documentation alone.
- [ ] The spec keeps production restore and production database mutation out of scope.

## Typed identity and credentials

- [ ] `DatabaseTarget` binds tenant, application, stack, environment, engine family, transport identity, database identifier, logical database name, credential reference, and tool profile.
- [ ] Transport identity is reused from the approved AppCare transport boundary rather than replaced by a second shadow target model.
- [ ] Credential values never enter DB records, logs, evidence, manifests, prompts, worker packets, tests, reports, or Git.
- [ ] Secret injection is broker-only and transient.
- [ ] Cross-tenant, cross-application, wrong-engine, expired, revoked, or malformed credentials fail closed.

## Command and broker safety

- [ ] Only typed operations from a closed registry are executable.
- [ ] No arbitrary SQL, free-form argv, shell wrapper, or caller-supplied binary path exists.
- [ ] MariaDB/MySQL and PostgreSQL use closed per-engine tool profiles only.
- [ ] Dump, restore, and verification output remain bounded and sanitized.
- [ ] The broker deletes incomplete staging artifacts on failure, timeout, or cancellation.

## Backup and restore behavior

- [ ] MariaDB/MySQL and PostgreSQL both use logical backup semantics only.
- [ ] Database dump output is staged atomically before promotion into the backup manifest.
- [ ] The logical dump artifact hard cap is `536870912` bytes.
- [ ] Manifest and checksum binding include target, engine family, database identifier, dump format, and tool profile.
- [ ] Readback verification rejects mismatched manifest, checksum, receipt, tenant, application, or database identity.
- [ ] Restore targets are isolated and non-production only.
- [ ] Partial restore cleanup or quarantine is explicit and deterministic.
- [ ] Post-restore verification uses closed templates only.

## Consistency and honesty

- [ ] Known logical-backup limitations are explicit, not hidden in a healthy label.
- [ ] MariaDB/MySQL non-transactional or mixed-engine risk is surfaced honestly.
- [ ] PostgreSQL cluster-global object limitations remain explicit.
- [ ] Database-only success cannot claim whole-application restore support.
- [ ] Fixture, reference, and controlled-live-provider evidence cannot be relabeled as `real_target`.

## Execution policy

- [ ] Probe, dump, restore, and verification timeouts are explicit and finite.
- [ ] Output caps for stderr and non-dump stdout are explicit and finite.
- [ ] Idempotency is durable and same-key different-request reuse fails closed.
- [ ] Same-target concurrency is bounded to one authoritative in-flight dump or restore.
- [ ] Restart during mutable restore requires explicit recovery and cannot silently resume.

## Testing and gate alignment

- [ ] The spec includes a full adversarial matrix for scope, secrets, commands, integrity, restore, concurrency, restart, and evidence class.
- [ ] Security gate mapping covers credential custody, database safety, backup integrity, restore safety, privacy, and resource controls.
- [ ] Downstream implementation tasks require deterministic tests, Codex Security, exact-head CI, Graphify, and Saveruflo.
- [ ] Readiness wording preserves missing live evidence until authorized bounded live receipts exist.
