# BETA-01 Control Plane API Contract

The contract is intentionally small and development/staging-only. Every endpoint except liveness requires a valid AppCare bearer token and resolves exactly one tenant context before loading data.

## Authentication

### `POST /auth/token`

- Request: local development identity credentials from the isolated fixture/setup path.
- Response: short-lived bearer token metadata without returning password hashes or internal secrets.
- Failure: stable `401` response with no account-existence oracle or secret detail.
- No external identity provider or production credential exchange is allowed in BETA-01.

## Health

### `GET /health/live`

- No authentication required.
- Returns process liveness only.
- Must not query or expose tenant data, credentials, or dependency contents.

### `GET /health/ready`

- No authentication required.
- Verifies the configured isolated development/test persistence boundary and returns a truthful ready/not-ready result.
- Does not connect to production or WordPress Security resources.

## Tenant-scoped resources

The following resource groups use the same authorization contract: applications/assets, findings, connectors, backups, approvals, deployments, and jobs.

- `GET /v1/<resource>` lists only records for the authenticated tenant.
- `POST /v1/<resource>` creates a record with tenant ownership derived from the authenticated context, never from an arbitrary client tenant ID.
- `GET /v1/<resource>/{id}` returns only an owned record; an unowned or unknown ID has the same safe not-found/denied behavior.
- `PATCH` and `DELETE` exist only where the state model permits them; cross-tenant attempts never disclose the target record.
- Connector, backup, approval, and deployment endpoints manipulate descriptive records only and expose no execute, deploy, sync, or provider-write operation.

## Jobs

### `POST /v1/jobs`

Creates a durable queued job record with validated kind, status, retry count, and cost fields. It does not start external work.

### `GET /v1/jobs/{id}`

Returns an owned job and its durable status/cost/retry/failure metadata only.

## Audit

### `GET /v1/audit-events`

Returns sanitized, tenant-scoped append-only events. Pagination is bounded and ordered by occurrence time plus opaque ID.

There is no update or delete endpoint for audit events. Attempts to mutate them through the persistence boundary fail and leave the original event unchanged.

## Error contract

- `401` unauthenticated or invalid token.
- `403` authenticated but not permitted for an operation.
- `404` unowned/unknown resource with no cross-tenant existence disclosure.
- `409` invalid state transition or immutable-record mutation.
- `422` structurally invalid input with field-level details only for safe fields.
- `503` readiness failure without dependency secrets or internal connection strings.
