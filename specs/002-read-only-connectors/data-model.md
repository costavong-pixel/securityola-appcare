# BETA-02 Data Model

## Connector

The existing tenant-owned `Connector` record is extended with:

- `provider`: one of `github`, `vercel`, or `supabase`.
- `kind`: provider resource class such as `repository`, `project`, or `supabase-project`.
- `resource_reference`: opaque provider resource identity; never a credential-bearing URL.
- `owner_reference`: normalized provider owner/account/team/organization identity used for the ownership check.
- `scope_json`: approved capability names only.
- `health_status`, `permission_status`, `ownership_status`: `unknown`, `passed`, or `failed`.
- `last_checked_at`: timestamp of the latest local check.

All fields remain tenant-scoped through the owning application and existing authorization dependency.

## Connector credential metadata

`ConnectorCredential` stores the current non-secret reference for a connector:

- `reference`: opaque secret-service reference, not the provider token.
- `authority`: provider or credential authority label.
- `scopes_json`: requested read-only scopes.
- `status`: `active`, `expired`, `revoked`, `invalid`, or `insufficient_scope`.
- `expires_at`: optional expiry timestamp.
- `fingerprint`: optional non-reversible identifier for rotation/audit correlation.

There is deliberately no token, password, private key, API key, cookie, header, or provider-secret column. The API rejects those field names through strict schemas and rejects credential-shaped values through the shared safety validator.

## Connector check

`ConnectorCheck` is an append-only-ish status history record tied to one tenant and connector:

- `check_kind`: `health`, `permissions`, or `ownership`.
- `status`: `passed`, `failed`, or `unknown`.
- `reason_code`: stable non-sensitive failure classification.
- `evidence_json`: allowlisted booleans, provider names, scope names, and normalized references only.
- `checked_at`: check timestamp.

Raw provider payloads are never persisted, returned, or written to audit metadata.

## Inventory run

`InventoryRun` represents a local reconciliation for a connector and snapshot key:

- `snapshot_key`: caller-selected safe idempotency key, defaulting to `current`.
- `status`: `running`, `succeeded`, or `failed`.
- `asset_count`: normalized active asset count.
- `failure_code`: stable non-sensitive failure classification.
- `started_at` and `finished_at`.

The unique tenant/connector/snapshot-key identity means retries update the same local run rather than creating duplicate inventory records.

## Asset

Existing tenant-owned `Asset` records gain nullable connector inventory fields:

- `connector_id`: owning connector for provider inventory assets.
- `provider` and `provider_reference`: stable provider identity.
- `display_metadata_json`: allowlisted non-secret display metadata.
- `last_seen_at`: latest successful inventory observation.

The stable local identity is `(tenant_id, connector_id, provider_reference)`. Missing assets are marked `retired`; provider deletion is never requested and local history is retained.

## Invariants

1. A connector, credential record, check, inventory run, and asset can be read only by its tenant.
2. A connector must have a valid supported provider profile before a check or inventory request.
3. Check and inventory fail closed when the credential reference is absent, expired, revoked, insufficient, or invalid.
4. Ownership must match the configured resource and owner references plus
   provider-side credential identity before assets are persisted.
5. Provider operations are fixed `GET` descriptors. No database mutation, deploy, delete, arbitrary method, or arbitrary URL is represented by these entities.
