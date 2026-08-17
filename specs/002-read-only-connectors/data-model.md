# BETA-02 Connector and Inventory Data Model

## Cross-cutting rules

- Provider names are the closed set `github`, `vercel`, and `supabase`.
- Capability strings are immutable and read-only. Any capability containing `write`, `deploy`, `delete`, `mutate`, `execute`, `sql`, `secret`, or `key` is rejected from the BETA-02 connector boundary.
- Credential records contain an opaque reference and metadata only. Raw token, key, password, cookie, and private-key values are never fields of the model.
- Every persisted AppCare asset has the authenticated tenant and application owner. Provider records are never persisted without those local owners.
- Inventory output is normalized, sorted, de-duplicated, and hashed from canonical safe fields.
- Ownership verification is fail-closed and does not treat a matching display name as proof of ownership.

## Entities

### ProviderSpec

| Field | Type | Rules |
|---|---|---|
| provider | literal | Closed provider set |
| required_capabilities | tuple[str, ...] | Read-only allowlist |
| forbidden_capabilities | tuple[str, ...] | Includes all write/deploy/delete/execute families |

### CredentialMetadata

| Field | Type | Rules |
|---|---|---|
| credential_id | opaque string | Non-secret reference; stable format check |
| provider | provider literal | Must match connector |
| tenant_id | opaque AppCare tenant ID | Credential metadata is never shared across tenants |
| scopes | tuple[str, ...] | Must satisfy provider required capabilities and contain no forbidden capability |
| version | positive integer | Increases on rotation |
| issued_at | UTC datetime | Required |
| expires_at | UTC datetime or null | Past expiry is unusable |
| revoked_at | UTC datetime or null | Any value makes it unusable |

Derived state is `active`, `expired`, `revoked`, or `invalid`.

### ConnectorHealth

| Field | Type | Rules |
|---|---|---|
| provider | provider literal | Never includes a token |
| usable | bool | True only for active credential and complete read scopes |
| credential_status | literal | Stable lifecycle result |
| missing_capabilities | tuple[str, ...] | Safe names only |
| reason | literal | No provider response or credential value |

### ProviderSnapshot

| Field | Type | Rules |
|---|---|---|
| provider | provider literal | Must match connector |
| resource_id | opaque string | Provider account/project/repository identity |
| domains | tuple[str, ...] | Normalized hostnames only; no userinfo/query/fragment |
| records | tuple[RemoteRecord, ...] | Safe fixture/provider metadata |

### RemoteRecord

| Field | Type | Rules |
|---|---|---|
| kind | string | Bounded non-secret category, e.g. repository/project/deployment/table/bucket |
| provider_id | string | Provider-side opaque identifier |
| name | string | Bounded display label |
| locator | string | Safe URL or provider locator; credential-bearing references rejected |
| metadata | mapping | Safe scalar metadata only; secret-shaped keys/values rejected or redacted |

### InventoryAsset

| Field | Type | Rules |
|---|---|---|
| asset_key | SHA-256 string | Derived from provider, kind, provider ID, and canonical locator |
| provider | provider literal | Source provider |
| kind | string | Normalized provider category |
| provider_id | string | Stable source identity |
| name | string | Safe display label |
| locator | string | Canonical safe locator |
| metadata | mapping | Sanitized scalar metadata |

### OwnershipResult

| Field | Type | Rules |
|---|---|---|
| verified | bool | True only for resource/domain match |
| reason | literal | `matched`, `missing_target`, `resource_mismatch`, `domain_mismatch`, or `invalid_target` |
| matched_resource | bool | Safe boolean |
| matched_domain | bool | Safe boolean |

### InventoryResult

Contains normalized `InventoryAsset` values, deterministic `digest`, record count, and `OwnershipResult`. It is safe to serialize and contains no credential material or raw provider payload.

## Relationships and persistence

- A `ReadOnlyConnector` has one `ProviderSpec` and one active tenant-bound `CredentialMetadata` reference at a time.
- A connector produces one `ProviderSnapshot` and many `InventoryAsset` values.
- An `InventoryAsset` may reconcile to one existing AppCare `Asset` under one tenant/application pair.
- Reconciliation is additive and idempotent. It does not delete or update provider state and does not create a local asset for a failed ownership check.
