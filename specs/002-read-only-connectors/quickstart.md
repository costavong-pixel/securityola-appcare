# BETA-02 Quickstart

## Scope

This slice is AppCare-only and offline by default. Do not use WordPress Security
paths, services, databases, secrets, or credentials. Do not supply live provider
tokens to tests or local commands.

## Inspect the branch

```powershell
git status --short
git branch --show-current
git rev-parse HEAD
```

Expected branch: `codex/beta-02-connectors`, based on merged BETA-01 main.

## Run the deterministic checks

```powershell
python -m pytest -q tests/unit/test_connector_profiles.py tests/unit/test_connector_transport.py
python -m pytest -q tests/contract/test_connectors_api.py tests/integration/test_connector_inventory.py tests/integration/test_connector_tenant_isolation.py tests/integration/test_connector_failures.py
python -m pytest -q
ruff check .
mypy
```

The repository's existing scripts remain authoritative for public-safety, worker
policy, build-lock, dependency, and secret checks.

## Safe fixture pattern

Use a fake credential reference such as
`vault://fixture/appcare/github-read`, fake provider responses, and a fixture
transport. Assert that:

- every emitted request has method `GET`;
- no request contains a user-selected host, header, token, or arbitrary method;
- revoked/expired/insufficient credentials fail closed;
- ownership mismatch creates no assets;
- repeated `current` inventory does not duplicate assets;
- provider-shaped secret fields are not returned, logged, audited, or persisted.

Do not run live provider calls from unit or integration tests. DeepSeek remains an
optional bounded implementation worker and is deferred when the required Linux
sandbox is unavailable.
