# BETA-02 Connector Contracts

All endpoints are under the existing authenticated `/v1` API and use the existing
tenant authorization boundary. Responses contain identifiers, statuses, counts, and
sanitized metadata only.

## Create a connector

`POST /v1/connectors`

Example safe request:

```json
{
  "application_id": "32-character-app-id",
  "provider": "github",
  "kind": "repository",
  "display_name": "Source repository",
  "resource_reference": "example/appcare",
  "owner_reference": "costavong-pixel",
  "scopes": ["metadata:read"],
  "credential_reference": "vault://appcare/tenant-a/github-read",
  "credential_authority": "appcare-secret-service",
  "credential_expires_at": "2026-09-01T00:00:00Z"
}
```

Only provider-specific read scopes from the server-owned profile are accepted.
Credential values such as `token`, `api_key`, `password`, `private_key`,
`authorization`, and `secret` are not accepted fields. A credential reference
may identify external custody but never contains the credential value.

The existing descriptive connector fields remain compatible for BETA-01 records;
a BETA-02 check fails closed until the required resource, owner, and active scoped
credential metadata are present.

## Read connector state

- `GET /v1/connectors`
- `GET /v1/connectors/{connector_id}`

The response includes provider, scope names, safe references, credential lifecycle
status, and the three latest status fields. It never includes raw provider responses
or secret values.

## Check connector

`POST /v1/connectors/{connector_id}/check`

The server constructs exactly four provider-owned request descriptors: health,
permissions, ownership, and inventory preparation. Every descriptor is `GET`, has
a server-selected path, and is sent through the injected read-only transport. A
missing transport, unavailable provider, expired/revoked credential, permission
mismatch, or ownership mismatch returns a failed status with a stable reason code.
Ownership requires the provider resource owner and the provider-side identity of
the credential to both match the configured owner reference; a caller cannot prove
ownership by self-declaring an owner while the credential identity disagrees.
No raw provider error is returned.

The result has:

```json
{
  "connector_id": "32-character-connector-id",
  "overall_status": "passed",
  "health_status": "passed",
  "permission_status": "passed",
  "ownership_status": "passed",
  "reason_codes": [],
  "checked_at": "2026-08-15T20:00:00Z"
}
```

## Reconcile inventory

`POST /v1/connectors/{connector_id}/inventory`

Request:

```json
{"snapshot_key": "current"}
```

The default key is `current`; callers may use another opaque key for a bounded
repeatable snapshot. A successful response reports the number of local active
assets and their sanitized identifiers. Repeating the same snapshot key is
idempotent. Missing observations retire local assets and do not delete them from
AppCare or the provider.

## Provider request boundary

The adapter contract is intentionally smaller than a generic HTTP client:

```text
ReadOnlyRequest(provider, operation, method="GET", path, query)
ReadOnlyTransport.request(request, credential_reference, scopes)
```

User input cannot set `method`, `path`, headers, command arguments, or a
provider base URL. Production currently uses an unavailable transport; deterministic
tests inject a fixture transport. A future live transport requires a separate
security review, endpoint allowlist, secret-service integration, and release gate.
