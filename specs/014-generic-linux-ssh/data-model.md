# Spec 014 data model

All records are immutable where practical. Secret values are not fields in
any model.

## LinuxTarget

| Field | Type | Rule |
| --- | --- | --- |
| tenant_id | safe segment | Spec 013 scope binding |
| application_id | safe segment | Spec 013 scope binding |
| environment | development/staging/production | production is read-only in this spec |
| host | IPv4/IPv6 or DNS name | normalized, no userinfo/path |
| expected_hostname | safe DNS name | identity observed from host |
| ssh_port | integer | 1..65535 |
| expected_host_key_fingerprint | SHA256 fingerprint | required, pre-registered |
| credential_reference | opaque reference | no raw value |
| remote_user | safe non-root username | root rejected |
| approved_application_roots | tuple of absolute paths | normalized, non-overlapping |
| approved_service_names | tuple of safe service names | exact allowlist |
| approved_database_identifiers | tuple of safe metadata IDs | no query strings |
| target_reference | safe opaque reference | stable evidence binding |

## CredentialProvider

Protocol methods:

- resolve(reference, tenant_id, application_id) -> ResolvedCredential
- status(reference, tenant_id, application_id) -> CredentialStatus

ResolvedCredential is a private runtime-only handle. It may contain a
protected identity-file reference or agent handle but MUST NOT be serializable
into AppCare evidence. A resolver must enforce tenant/application scope,
active/expiry/revocation state, and custody boundary.

## Typed operations

OperationKind contains:

connection_probe, host_inventory, filesystem_metadata_read,
safe_file_read, service_metadata_read, web_server_metadata_read,
runtime_metadata_read, network_binding_read, storage_metadata_read,
application_root_verification.

Each operation carries only its typed, validated input. There is no
command: str field.

## Remote execution result

RemoteExecutionResult includes:

- operation kind;
- status (passed, partial, permission_denied, timed_out, output_limited,
  host_identity_failed, credential_denied, malformed, failed);
- bounded normalized records;
- sanitized reason code;
- stdout/stderr byte counts only;
- operation ID and target reference;
- observed timestamp.

Raw stdout, stderr, private command arguments, and credential material are not
persisted.

## InventoryRecord

Each normalized record contains:

- tenant_id;
- application_id;
- target_reference;
- stable record_type;
- stable normalized identity key;
- safe scalar metadata;
- source reference such as linux-ssh/host-inventory;
- observed_at;
- evidence_class;
- deterministic evidence_digest.

Record metadata is allowlisted by record type. Unknown keys and unsafe values
are rejected.

## Capability evidence

The adapter emits Spec 013 CapabilityEvidence:

- connect and inventory only;
- tenant/application/stack scope;
- REAL_TARGET for the approved live target;
- FIXTURE for injected tests;
- sanitized evidence reference;
- no credential values;
- source/artifact fields only when a valid exact revision/artifact is
  genuinely available.

All downstream capabilities are absent or explicitly
MISSING_CAPABILITY in Spec 013 evaluation.

## Lifecycle state

Credential metadata states are:

registered → active → expired

or:

registered/active → revoked

Rotation creates a new opaque reference and revokes the old reference. A
rotation event is append-only metadata and never contains the old or new
secret.

