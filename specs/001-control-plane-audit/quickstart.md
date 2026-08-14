# BETA-01 Control Plane Quickstart

This guide is for the isolated AppCare development checkout only. It does not use production credentials, shared-server services, WordPress Security resources, or external provider writes.

## Prerequisites

- Python 3.12+ and the repository development lock installed.
- A temporary local SQLite database for tests, or an explicitly isolated PostgreSQL database owned by AppCare development.
- No `.env` file or credential-bearing fixture committed to the repository.

## Deterministic gates

From the repository root:

```powershell
python -m pytest -q
ruff format --check appcare scripts tests
ruff check appcare scripts tests
mypy appcare scripts tests
python scripts/check_public_safety.py
python scripts/verify_worker_policy.py
python scripts/check_build_lock.py
pip-audit --strict --requirement requirements-dev.lock
```

## Tenant-isolation scenario

1. Create two fake local tenants and one fake user in each through the test fixture.
2. Authenticate each user and create an application and asset under its own tenant.
3. Read the own-tenant records successfully.
4. Attempt to read, update, and delete the other tenant's records.
5. Verify every cross-tenant attempt is denied or safely not-found and no foreign data appears in the response or logs.

## Restart durability scenario

1. Start the API against a temporary database.
2. Create a job and append an audit event.
3. Stop and restart the API against the same isolated database.
4. Retrieve both records and verify the identifiers, tenant ownership, status, cost/retry fields, and audit hash chain remain unchanged.

## Audit immutability scenario

1. Append an audit event through the service boundary.
2. Attempt an HTTP update/delete (which must not exist) and a direct persistence update/delete in the failure test.
3. Verify the service/database rejects the mutation and the original event remains byte-for-byte unchanged.

## Health/readiness scenario

1. Call `/health/live` with no credentials and verify process liveness.
2. Call `/health/ready` with the isolated persistence available and verify ready.
3. Make the isolated dependency unavailable and verify readiness fails without exposing a connection string while liveness behavior remains truthful.

## No-production-write scenario

1. Inspect the route and service registry for BETA-01.
2. Verify only descriptive connector, backup, approval, and deployment records exist.
3. Verify no provider SDK, production URL, credential, deploy method, socket, or execution route is present.
4. Run the public-safety and secret gates before promotion.
