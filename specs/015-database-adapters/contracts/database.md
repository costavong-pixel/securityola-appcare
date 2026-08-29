# Contract: Database adapters

## Typed contracts

```python
class DatabaseExecutionBroker(Protocol):
    def run(
        self,
        operation: DatabaseOperation,
        *,
        target: DatabaseTarget,
        output_path: Path | None = None,
        cancel_event: object | None = None,
    ) -> DatabaseBrokerResult: ...


class DatabaseBackupAdapter(Protocol):
    def dump(
        self,
        request: DatabaseDumpRequest,
        *,
        broker: DatabaseExecutionBroker,
        now: datetime,
    ) -> DatabaseDumpArtifact: ...

    def restore(
        self,
        request: DatabaseRestoreRequest,
        *,
        now: datetime,
        cancel_event: object | None = None,
    ) -> DatabaseRestoreEvidence: ...
```

`DatabaseTarget` is the required public input. It binds:

- tenant/application/stack scope;
- engine family;
- exact logical database identity;
- transport target reference;
- opaque credential reference;
- closed tool profile;
- bounded limits.

There is no `command: str`, `sql: str`, or caller-supplied binary path field.

## Closed command template families

Allowed template identifiers are versioned and closed. Initial families are:

- `mysql.dump.logical.v1`
- `mysql.restore.logical.v1`
- `mysql.verify.empty.v1`
- `mysql.verify.restore.v1`
- `postgres.dump.logical.v1`
- `postgres.restore.logical.v1`
- `postgres.verify.empty.v1`
- `postgres.verify.restore.v1`

The tool profile may choose between approved compatible binaries within the same
family, such as `mariadb-dump` versus `mysqldump`, but the caller cannot inject
additional flags, SQL text, artifact paths, or executable paths. Restore input
is opened and checksum-verified by the broker, then supplied through stdin;
the artifact path is never placed in restore argv.

## Secret-handling contract

The broker resolves `credential_reference` to a private runtime-only handle;
callers pass only the typed target and never pass a resolved credential to the
adapter or broker API.
Plaintext credentials may exist only in process memory or an ephemeral
AppCare-owned temporary file created inside the broker boundary. They MUST NOT
appear in:

- command-line arguments;
- manifests, evidence, or receipts;
- logs or error strings;
- worker packets or prompts;
- repository files or tests.

## Dump contract

Input:

- validated `DatabaseDumpRequest`
- matching `DatabaseTarget`
- exact `backup_id`
- durable `idempotency_key`

Output:

- staged `DatabaseDumpArtifact`
- deterministic manifest metadata
- explicit consistency mode and limitation codes

Rules:

1. Dump exactly one approved logical database per request.
2. Write only to AppCare-owned staging output.
3. Stream SHA-256 during write and enforce the `536870912` byte cap.
4. Limit stderr to `65536` bytes.
5. Delete incomplete output on timeout, cancellation, disconnect, or non-zero
   exit.
6. For MariaDB/MySQL, reject unsafe programmable-object DDL, `DEFINER`
   directives, database-context changes, and executable-comment ambiguity
   before sealing the manifest. These objects remain an explicit limitation of
   this bounded restore profile.
7. Never report a healthy dump from a partial, oversized, or unsafe artifact.

## Restore contract

Input:

- verified dump artifact bound to one exact tenant/application/database identity
- non-production `DatabaseRestoreTarget`

Output:

- `DatabaseRestoreEvidence`

Rules:

1. Restore only into an isolated target owned by the same tenant/application
   scope.
2. Reject production restore targets and existing authoritative databases.
3. Run a closed pre-restore empty-target verification before mutation, then
   closed restore and post-restore verification templates.
4. Clean up partial restore state or durably quarantine the target on failure;
   quarantined targets cannot be resolved again until an external reset.
5. Bind restore evidence to the same `backup_id`, artifact digest, and manifest
   digest used by the backup flow.

## Engine-family policy

MariaDB/MySQL:

- logical dump only;
- closed `mariadb-dump` or `mysqldump` profile;
- closed `mysql` restore and verification profile;
- unsupported consistency conditions remain explicit.

PostgreSQL:

- logical dump only;
- closed `pg_dump` custom-archive profile;
- closed `pg_restore` and `psql` verification profile;
- cluster-global objects remain outside guaranteed scope unless later specified.

## Failure contract

The adapter returns explicit failed or blocked outcomes for:

- wrong scope or wrong engine;
- credential failure;
- arbitrary-command attempt;
- timeout, cancellation, disconnect, or malformed output;
- artifact cap breach;
- checksum or manifest mismatch;
- wrong-target or wrong-database restore;
- verification failure;
- duplicate or conflicting idempotency use;
- restart recovery required.
