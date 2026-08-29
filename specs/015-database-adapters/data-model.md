# Spec 015 data model

All records are immutable where practical. Secret values are never fields in
the public AppCare data model.

## Enums

| Enum | Values | Rule |
| --- | --- | --- |
| `DatabaseEngineFamily` | `mariadb_mysql`, `postgresql` | exact supported families only |
| `DatabaseDumpFormat` | `sql`, `postgres_custom` | closed per-engine formats only |
| `DatabaseConsistency` | `transactional_snapshot`, `best_effort_logical` | honest consistency state |
| `EvidenceClass` | `fixture`, `reference`, `controlled_live_provider`, `real_target` | Spec 013 evidence classes only |

## DatabaseTransportBinding

| Field | Type | Rule |
| --- | --- | --- |
| `tenant_id` | safe segment | exact transport scope |
| `application_id` | safe segment | exact transport scope |
| `target_reference` | opaque reference | MUST resolve to a validated transport target |
| `host` | validated host | bound to the transport target |
| `ssh_port` | bounded port | bound to the transport target |
| `expected_host_key_fingerprint` | validated fingerprint | strict host identity |
| `evidence_reference` | opaque reference | binds database operations to prior transport evidence |

## DatabaseTarget

| Field | Type | Rule |
| --- | --- | --- |
| `tenant_id` | safe segment | Spec 013 scope binding |
| `application_id` | safe segment | Spec 013 scope binding |
| `stack_id` | safe segment | generic Linux path uses `generic-linux` when applicable |
| `environment` | `development`, `staging`, `production` | source database environment |
| `engine_family` | `DatabaseEngineFamily` | exact supported engine family |
| `database_identifier` | safe segment | approved database identity from inventory |
| `logical_database_name` | safe segment | exact database/schema name to back up |
| `transport` | `DatabaseTransportBinding` | required execution identity |
| `credential` | `DatabaseCredentialReference` | opaque metadata only; no plaintext DSN or password |
| `target_reference` | opaque reference | stable evidence identity |
| `tool_profile` | safe segment | closed command-template profile |
| `approved_database_identifiers` | tuple of safe names | inventory-approved identities |
| `database_user` | validated user | never a secret |
| `database_host` | validated host | loopback or bound transport host only |
| `database_port` | bounded port | engine default or approved port |
| `limits` | `DatabaseLimits` | hard timeout/output/artifact caps |

## DatabaseCredentialMetadata

| Field | Type | Rule |
| --- | --- | --- |
| `reference` | opaque reference | AppCare-visible handle only |
| `tenant_id` | safe segment | exact scope |
| `application_id` | safe segment | exact scope |
| `engine_family` | `DatabaseEngineFamily` | credential family match required |
| `privilege_profile` | safe segment | `backup_read`, `restore_write`, or approved equivalent |
| `issued_at` | timestamp | timezone-aware |
| `expires_at` | timestamp or null | missing or expired fails closed |
| `revoked_at` | timestamp or null | revoked fails closed |
| `version` | integer | monotonic metadata-only rotation |

## DatabaseDumpRequest

| Field | Type | Rule |
| --- | --- | --- |
| `backup_id` | safe segment | binds to backup manifest identity |
| `idempotency_key` | safe segment/string | exact request replay key |
| `target` | `DatabaseTarget` | validated before broker call |
| `requested_at` | timestamp | timezone-aware |
| `job_id` | safe segment | AppCare staging job identity |
| `source_revision` | revision or null | when available must pair with app artifact digest |
| `application_artifact_digest` | sha256 or null | paired with source revision when available |

## DatabaseDumpArtifact

| Field | Type | Rule |
| --- | --- | --- |
| `backup_id` | safe segment | exact backup binding |
| `target_reference` | opaque reference | exact source target |
| `transport_target_reference` | opaque reference | exact execution identity |
| `engine_family` | `DatabaseEngineFamily` | exact engine family |
| `dump_format` | `DatabaseDumpFormat` | per-engine closed format |
| `tool_profile` | safe segment | command-template family |
| `artifact_path` | approved staging path reference | AppCare-owned temporary path only; not evidence |
| `staging_job_id` | safe segment | exact AppCare staging job |
| `artifact_size_bytes` | integer | `<= 536870912` |
| `artifact_sha256` | sha256 | sealed after bounded write |
| `consistency` | `DatabaseConsistency` | honest result |
| `limitation_codes` | tuple of safe segments | explicit known limitations |
| `evidence_class` | `EvidenceClass` | exact provenance only |

## DatabaseArtifactManifest

| Field | Type | Rule |
| --- | --- | --- |
| `backup_id` | safe segment | exact backup identity |
| `tenant_id` | safe segment | exact scope |
| `application_id` | safe segment | exact scope |
| `stack_id` | safe segment | Spec 013 binding |
| `database_identifier` | safe segment | inventory-approved |
| `logical_database_name` | safe segment | exact dumped database |
| `engine_family` | `DatabaseEngineFamily` | exact family |
| `dump_format` | `DatabaseDumpFormat` | exact format |
| `tool_profile` | safe segment | exact template family |
| `artifact_sha256` | sha256 | dump payload digest |
| `artifact_size_bytes` | integer | final bounded size |
| `manifest_digest` | sha256 | canonical manifest digest |
| `source_revision` | revision or null | paired with app artifact digest when genuinely available |
| `application_artifact_digest` | sha256 or null | paired with source revision |
| `evidence_class` | `EvidenceClass` | exact provenance only |
| `created_at` | timestamp | timezone-aware |

## DatabaseRestoreTarget

| Field | Type | Rule |
| --- | --- | --- |
| `tenant_id` | safe segment | exact scope |
| `application_id` | safe segment | exact scope |
| `environment` | `development`, `staging`, `test` | production forbidden |
| `engine_family` | `DatabaseEngineFamily` | must match artifact |
| `transport` | `DatabaseTransportBinding` | approved restore execution identity |
| `isolated_target_reference` | opaque reference | unique restore rehearsal identity |
| `restore_database_name` | safe segment | isolated non-authoritative target |
| `cleanup_owner_reference` | opaque reference | deterministic cleanup/quarantine handle |
| `verification_profile` | safe segment | closed post-restore verification family |

## DatabaseRestoreEvidence

| Field | Type | Rule |
| --- | --- | --- |
| `backup_id` | safe segment | exact backup identity |
| `tenant_id` | safe segment | exact scope |
| `application_id` | safe segment | exact scope |
| `engine_family` | `DatabaseEngineFamily` | must match artifact and target |
| `request` | `DatabaseRestoreRequest` | exact artifact and target request |
| `status` | `DatabaseOperationStatus` | no silent partial success |
| `artifact_digest` | sha256 | exact artifact binding |
| `manifest_digest` | sha256 | exact manifest binding |
| `restored_digest` | sha256 or null | exact restored artifact binding |
| `verification` | `DatabaseVerificationResult` or null | closed pre/post verification result |
| `cleanup_status` | `none`, `cleaned`, `quarantined`, `required` | explicit failure disposition |
| `cleanup_reference` | opaque reference or null | cleanup/quarantine evidence |
| `evidence_class` | `EvidenceClass` | exact provenance only |

## Spec 013 evidence bundle

| Record | Required fields | Invariant |
| --- | --- | --- |
| `DatabaseCapabilityEvidenceBundle` | `database_backup` evidence plus supporting readback/restore evidence refs | no second evaluator |
| `CapabilityEvidence` | tenant, application, stack, capability, status, evidence class, evidence ref, observed_at | exact Spec 013 schema only |

`database_backup` can become authoritative only when dump, readback, manifest,
and checksum verification pass. Database-slice evidence for `remote_readback`
and `isolated_restore` remains supporting evidence until the full application
backup identity includes matching filesystem and database components.
