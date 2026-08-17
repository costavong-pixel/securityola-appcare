# BETA-02 Read-Only Connector Contract

This phase defines a service-level contract used by AppCare orchestration and deterministic fixtures. It does not add live OAuth, provider account authorization, or public customer endpoints.

## Provider capability registry

`ProviderSpec` exposes:

- `provider`: `github`, `vercel`, or `supabase`;
- `required_capabilities`: immutable read-only capability names;
- `validate_scopes(scopes)`: returns a safe permission result and rejects write-shaped capabilities.

The initial capability mapping is:

| Provider | Minimum read capabilities | Explicitly excluded |
|---|---|---|
| GitHub | `repository.metadata.read`, `repository.contents.read`, `pull_request.metadata.read` | repository/org administration, issues write, contents write, workflow write, deploy, delete |
| Vercel | `project.read`, `deployment.read`, `domain.read`, `team.read` | project/domain write, deployment create/cancel, environment-variable or secret management |
| Supabase | `project.read`, `auth.metadata.read`, `storage.metadata.read`, `database.metadata.read` | SQL/query execution, migrations, project-admin write, storage-config write, secret/key access |

These are AppCare capability names. A future live adapter must map them to the provider's current authorization model and prove the resulting grant before use.

## Connector operations

```python
class ReadOnlyConnector(Protocol):
    provider: ProviderName

    def health(self) -> ConnectorHealth: ...
    def inventory(self) -> ProviderSnapshot: ...
    def verify_ownership(self, target: OwnershipTarget) -> OwnershipResult: ...
```

The protocol deliberately contains no `create`, `update`, `delete`, `deploy`, `execute`, `write`, or arbitrary request operation.

## Credential lifecycle

- `register(metadata)` accepts metadata and an opaque reference only.
- `rotate(tenant_id, old_id, replacement_metadata)` revokes the old version and registers the replacement within the same tenant.
- `revoke(tenant_id, credential_id)` marks the reference unusable within that tenant.
- `health()` returns `expired` or `revoked` without attempting provider access.

## Inventory contract

`collect_inventory(connector, tenant_id, application_id, target)`:

1. checks connector health;
2. verifies the expected resource/domain target;
3. normalizes and de-duplicates provider records;
4. returns a stable digest and safe inventory values;
5. optionally reconciles observed records into tenant-owned AppCare `Asset` rows.

Failed health or ownership checks return a stable error and do not persist inventory.

## Error contract

Safe error reasons are limited to `invalid_provider`, `invalid_scope`, `missing_scope`, `expired_credential`, `revoked_credential`, `invalid_credential`, `missing_target`, `resource_mismatch`, `domain_mismatch`, and `unsafe_record`. Provider response bodies, tokens, authorization headers, and customer data are never included.
