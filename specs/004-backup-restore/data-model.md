# BETA-04 Data Model

| Record | Required fields | Invariant |
|---|---|---|
| `BackupTarget` | tenant, application, environment, source reference | AppCare-only and tenant-safe |
| `BackupDestination` | provider, namespace, region, retention, credential reference | B2/Glacier namespace and opaque reference only |
| `BackupComponent` | name, kind, source reference, bytes, SHA-256 | unique names and deterministic digest |
| `BackupManifest` | backup ID, target, component digests, key reference, retention | canonical serialization and no raw key |
| `BackupArtifact` | manifest bytes, encrypted payload, artifact digest | vault stores encrypted payload only |
| `BackupJobEvent` | job ID, state, reason, timestamp | append-only state history |
| `RestoreEvidence` | backup ID, target, restored components, RPO/RTO, status | no partial promotion |

## State separation

`verified` means the artifact was read back, decrypted, and component digests
matched. `failed` means the backup is unhealthy regardless of whether an object
exists. `restore_verified` is a separate result and is required for controlled
restore evidence. A scanner/finding-style record is not used for backup
failure reporting.
