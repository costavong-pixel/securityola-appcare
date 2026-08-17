# Feature Specification: Read-Only Supported-Stack Connectors and Asset Inventory

**Feature Branch**: `codex/beta-02-connectors`

**Created**: 2026-08-17

**Status**: Ready for implementation

**Input**: GitHub issue #3, `[BETA-02] Add read-only GitHub, Vercel, Supabase connectors and asset inventory`.

## User Scenarios & Testing

### User Story 1 - Check a supported connector safely (Priority: P1)

An AppCare operator can represent a GitHub, Vercel, or Supabase connection with only the minimum read permissions needed for inventory. The connection reports a safe health/permission result and refuses to operate when its credential is expired, revoked, or under-scoped.

**Independent Test**: Exercise synthetic provider fixtures for all three providers with complete, missing, expired, and revoked credential metadata. Verify that only the complete read-only fixture is usable and that no credential value appears in the result.

### User Story 2 - Build a repeatable tenant-owned inventory (Priority: P1)

An AppCare operator can collect normalized repositories/projects/deployments/domains and Supabase project/auth/storage/database metadata for one approved application. Repeating the same snapshot produces the same inventory keys and does not create duplicate AppCare assets.

**Independent Test**: Submit the same synthetic snapshots twice, with reordered records and duplicate provider records. Verify a stable digest, stable normalized keys, one tenant-owned AppCare asset per observed item, and no cross-tenant persistence.

### User Story 3 - Verify application/domain ownership without granting write authority (Priority: P1)

Before inventory is accepted, AppCare can compare the expected application/resource identity and approved domain with provider-reported ownership. A missing or mismatched identity fails closed. The connector surface contains no deployment, mutation, deletion, or database-write operation.

**Independent Test**: Verify matching and mismatching resource/domain fixtures and inspect the public connector surface for read-only operations only. Attempted write-shaped inputs are rejected and never reach provider code.

### User Story 4 - Rotate and revoke credential references safely (Priority: P2)

An AppCare operator can register, rotate, expire, and revoke a credential reference without storing or returning the raw credential. A rotated or revoked reference cannot be used by a connector, and diagnostic output contains only provider, opaque reference, scope, version, and status metadata.

**Independent Test**: Register a synthetic metadata record, rotate it, revoke the old version, and verify that old/expired/revoked states fail closed while the active replacement remains usable.

## Requirements

### Functional Requirements

- **FR-001**: The system MUST define explicit read-only capability requirements for GitHub, Vercel, and Supabase and reject any scope containing write, deploy, delete, mutate, or database-execute authority.
- **FR-002**: Each provider connector MUST expose health/permission, read-only inventory, and ownership-verification operations through a provider-neutral contract.
- **FR-003**: Connector health MUST distinguish active, missing-scope, expired, revoked, and invalid credential states using stable non-secret reasons.
- **FR-004**: Credential handling MUST store tenant-bound metadata and an opaque reference only; raw access tokens, private keys, passwords, and API keys MUST never enter connector state, logs, job state, audit metadata, or inventory output.
- **FR-005**: Credential rotation MUST create a new version and invalidate the superseded reference without exposing either raw credential material or a provider write path.
- **FR-006**: Inventory MUST normalize provider records into stable tenant/application-scoped asset keys, de-duplicate repeated records, and produce a deterministic digest independent of input ordering.
- **FR-007**: Inventory persistence MUST be idempotent: repeating an unchanged snapshot MUST reuse existing AppCare assets and MUST NOT delete or mutate provider data.
- **FR-008**: Ownership verification MUST require an expected resource identity or approved domain and MUST fail closed for missing, malformed, or mismatched provider identity.
- **FR-009**: Provider adapters MUST use synthetic/injected transport data in deterministic tests; no customer account, production endpoint, or live credential is required or permitted for this phase.
- **FR-010**: The connector boundary MUST contain no deployment, mutation, deletion, arbitrary SQL, credential-management, or provider-write operation.
- **FR-011**: Connector errors and serialized results MUST redact secret-shaped values and avoid account-existence, credential, or customer-data oracles.
- **FR-012**: All connector and inventory records MUST remain tenant-scoped and must not reference WordPress Security resources, production API state, or shared credentials.

### Key Entities

- **ProviderSpec**: Provider name, minimum read-only capabilities, and forbidden capability families.
- **CredentialMetadata**: Opaque credential reference, provider, scope set, version, issue/expiry/revocation timestamps, and no raw secret.
- **ConnectorHealth**: Safe provider, credential status, permission result, and stable diagnostic reason.
- **ProviderSnapshot**: Synthetic or adapter-produced provider identity, domains, and remote records.
- **InventoryAsset**: Stable normalized provider record with kind, locator, provider identity, and deterministic key.
- **OwnershipResult**: Boolean verification result and non-sensitive reason for an expected resource/domain target.
- **InventoryResult**: Normalized assets, digest, ownership result, and counts for an inventory run.

## Success Criteria

- **SC-001**: 100% of synthetic GitHub, Vercel, and Supabase fixtures with missing, write, expired, revoked, or under-scoped authorization are rejected before inventory data is accepted.
- **SC-002**: Replaying an unchanged fixture at least twice yields identical normalized keys and digest and creates no duplicate tenant-owned AppCare assets.
- **SC-003**: 100% of ownership mismatch and missing-target tests fail closed without exposing provider payloads or credential material.
- **SC-004**: Static and runtime negative tests find no connector operation capable of deploy, mutate, delete, execute SQL, or write to a provider.
- **SC-005**: A repository-wide secret/public-safety scan finds no raw credential value in source, fixtures, logs, job state, or generated evidence.
- **SC-006**: Existing BETA-01 tests plus the full deterministic, security, failure, dependency, Graphify, and exact-head CI gates pass.

## Assumptions

- BETA-02 is an isolated read-only capability and inventory foundation; provider OAuth installation and owner-authorized live transport are later integration gates.
- The existing descriptive `Connector` record remains the tenant-scoped control-plane record; this feature adds a provider-neutral connector service boundary and uses existing `Asset` records for idempotent local inventory persistence.
- Provider permission names can differ by provider. The implementation records internal capability names and maps them to the current provider documentation without granting any write capability.
- Real customer credentials, provider accounts, deployment systems, databases, and domain changes are not needed to prove this phase.

## Out of Scope

- OAuth consent flows, token exchange, secret-vault implementation, live customer API calls, webhooks, scans, remediation, deployment, database queries, storage-object reads, or provider-side mutations.
- Any work in the WordPress Security repositories/runtime or `/var/www/api.securityola.com`.
