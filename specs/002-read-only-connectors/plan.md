# Implementation Plan: Read-Only Connectors and Asset Inventory

**Branch**: `codex/beta-02-connectors` | **Date**: 2026-08-15 | **Spec**: [spec.md](spec.md)

## Summary

BETA-02 adds a tenant-scoped, read-only connector boundary for GitHub, Vercel, and
Supabase. A connector records only provider, resource identity, approved capability
metadata, and a non-secret credential reference. Provider adapters emit fixed `GET`
request descriptors through an injected deny-by-default transport, normalize safe
health/permission/ownership evidence, and reconcile provider assets idempotently.
The default application has no live provider transport; tests use deterministic fake
responses. No provider credential value, arbitrary URL, mutation, deletion, deploy,
database write, or secret response is accepted or persisted.

## Technical Context

**Language/Version**: Python 3.12+ (`>=3.12,<3.15`)

**Primary Dependencies**: FastAPI 0.141.1, Pydantic 2.13.4, SQLAlchemy 2.0.52,
psycopg 3.3.4, uvicorn 0.52.3. No provider SDK or new runtime dependency is added
for this bounded slice.

**Storage**: Existing SQLAlchemy metadata on SQLite for tests and PostgreSQL for
deployment. New connector credential metadata, check results, inventory runs, and
asset linkage use the existing database bootstrap path; no live migration or
provider database is touched in BETA-02.

**Testing**: pytest, Ruff, mypy strict mode, deterministic failure/secret tests,
public-safety checks, worker-policy checks, build-lock/hash checks, pip-audit, and
exact-head GitHub Actions.

**Target Platform**: Isolated AppCare web service on the shared server; local
Windows development and Linux CI. WordPress Security paths and services are not
part of the target.

**Project Type**: FastAPI web service with tenant-scoped SQLAlchemy persistence.

**Performance Goals**: Bounded request processing and local inventory reconciliation;
no unbounded provider retries or background network execution. A single inventory
request is capped by the existing API page limits and persists only normalized safe
metadata.

**Constraints**: Provider operations are `GET` only and selected by server-owned
profiles. User input cannot choose an HTTP method, arbitrary provider URL, command,
credential value, or destructive capability. Cross-tenant access returns the same
not-found boundary as other AppCare resources. Tests do not access live providers.

**Scale/Scope**: Three providers, one connector resource per AppCare application,
repeatable inventory snapshots, and the initial GitHub repository, Vercel project /
deployment, and Supabase project / Auth / Storage / database metadata asset classes.

## Constitution Check

*GATE: Must pass before implementation and be re-checked after design.*

- **Security before speed**: PASS — fixed read-only contracts and fail-closed checks
  are preferred over live provider convenience.
- **Deterministic evidence**: PASS — fake transports, explicit check records, and
  exact tests provide evidence without relying on worker summaries.
- **Least privilege and tenant isolation**: PASS — provider profiles, application
  ownership checks, and cross-tenant negative tests are required.
- **No secrets in artifacts**: PASS — only credential references, scope metadata,
  expiry, and fingerprints are stored; raw values are rejected and redacted.
- **Staging/reversibility**: PASS — local inventory reconciliation only retires
  missing assets and cannot mutate provider state.
- **AppCare / WordPress separation**: PASS — all changes are in the AppCare
  checkout; no WordPress resource is read or modified.
- **Third-party skills**: PASS — no provider SDK or unreviewed worker capability is
  introduced; DeepSeek remains optional and sandbox-gated.
- **Codex ownership**: PASS — Codex owns the profile, threat boundary, diff review,
  security disposition, merge, and release decisions.
- **Exact review and CI**: PASS — the final gates include diff inspection, Graphify,
  secret/security/failure tests, independent Codex review, and exact-head CI.

## Project Structure

### Documentation

```text
specs/002-read-only-connectors/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── connectors.md
├── checklists/
│   └── requirements.md
└── tasks.md
```

### Source Code

```text
appcare/
├── connectors/
│   ├── contracts.py       # fixed read descriptors and normalized observations
│   ├── profiles.py        # provider capability allow/deny lists
│   ├── transport.py       # deny-by-default injected transport boundary
│   └── adapters.py        # GitHub, Vercel, and Supabase normalizers
├── models/
│   ├── operations.py      # connector, credential metadata, checks, inventory runs
│   └── resources.py       # connector-linked asset inventory fields
├── services/
│   └── connectors.py      # registration, checks, ownership, reconciliation
└── routes/
    ├── connectors.py      # connector check/inventory endpoints
    ├── operations.py      # existing connector registration/list/detail contract
    └── schemas.py         # strict BETA-02 request/response models

tests/
├── contract/
│   └── test_connectors_api.py
├── integration/
│   ├── test_connector_inventory.py
│   ├── test_connector_tenant_isolation.py
│   └── test_connector_failures.py
└── unit/
    ├── test_connector_profiles.py
    ├── test_connector_transport.py
    └── test_connector_redaction.py
```

**Structure Decision**: Extend the existing single FastAPI/SQLAlchemy AppCare
service. Provider-specific concerns live in `appcare/connectors`; persistence and
HTTP boundaries reuse the existing models, tenant-scope repository, audit sanitizer,
authentication, and application factory. There is no frontend, worker, provider SDK,
or deployment code in this beta slice.

## Complexity Tracking

No constitution violations. The adapter and transport boundary is the smallest
additional structure that prevents provider-specific URL/method expansion from
leaking into the tenant-facing API while keeping tests offline and deterministic.
