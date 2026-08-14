# Implementation Plan: AppCare Control Plane and Tenant-Safe Audit Trail

**Branch**: `codex/beta-01-control-plane` | **Date**: 2026-08-14 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-control-plane-audit/spec.md`

## Summary

Build the smallest durable AppCare web/API control plane that can authenticate a user, enforce tenant ownership on every tenant-scoped record, persist job and audit state across restart, expose truthful health/readiness checks, and model later connector/backup/approval/deployment state without any production write capability. The implementation will use a narrow service/repository boundary so authorization is centralized and testable, a relational schema with explicit tenant ownership, append-only audit writes with database-backed immutability protections, and an in-process development configuration that can be exercised against an isolated local database.

## Technical Context

**Language/Version**: Python 3.12+

**Primary Dependencies**: FastAPI for the minimal HTTP boundary, SQLAlchemy 2.x for the relational model and transaction handling, psycopg 3 for PostgreSQL deployment compatibility, and Pydantic 2.x for validated request/response data. Authentication uses an AppCare-owned token/password boundary with no external provider or production connector in this phase.

**Storage**: PostgreSQL is the target durable store; SQLite is permitted only for isolated automated tests and local development fixtures. No production database or WordPress Security database is used.

**Testing**: pytest, FastAPI test client, isolated temporary SQLite databases, transaction/negative authorization tests, restart durability tests, secret-screening tests, Ruff, mypy, pip-audit, and exact-head GitHub CI.

**Target Platform**: Linux server/container-compatible development and staging runtime; Windows developer checks remain supported for deterministic tests.

**Project Type**: Python web service/API foundation.

**Performance Goals**: Keep control-plane reads/writes bounded and deterministic for the private-beta scale; local health and tenant-scoped CRUD test requests should complete within 500 ms under the fixture workload.

**Constraints**: No production writes, external connector execution, deployment authority, production credentials, WordPress Security resources, unscoped repository queries, mutable audit history, secret-bearing logs, or model-controlled root access. Every tenant-owned operation requires an authenticated tenant context.

**Scale/Scope**: Two or more isolated test tenants, the ten issue-defined entity families, one minimal API process, durable local/test persistence, and a foundation that later beta issues can extend without weakening tenant or approval boundaries.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Security before speed**: PASS. The plan centralizes authorization, fails closed, keeps audit writes append-only, and excludes production capabilities.
- **II. Deterministic evidence before AI claims**: PASS. Each user story has executable negative tests, restart tests, and exact CI gates.
- **III. Least privilege and tenant isolation**: PASS. Tenant ownership is required on all customer records and cross-tenant tests are mandatory.
- **IV. No secrets in artifacts**: PASS. Authentication fixtures use fake/local values, logs and errors are sanitized, and no provider credentials are introduced.
- **V. Staging, backup, and reversibility before production**: PASS. BETA-01 has no production write connector or deployment path.
- **VI. AppCare and WordPress remain separate**: PASS. Only the AppCare repository and isolated local/test storage are in scope.
- **VII. Third-party skills are untrusted**: PASS. Existing pinned tooling is reused; new runtime dependencies require source/version/hash review before adoption.
- **VIII. Codex owns final decisions**: PASS. Codex owns the schema, authorization model, dependency decisions, security review, and merge decision; DeepSeek receives only bounded implementation packets.
- **IX. Exact review and CI evidence is required**: PASS. The independent Codex final review may run in the current Codex agent/app/cloud session or through GitHub Codex review; Codex CLI is optional and not a blocker.

## Phase 0: Research and decisions

- Verify the current supported APIs and security guidance for FastAPI, SQLAlchemy, psycopg, Pydantic, password/token handling, and SQLite/PostgreSQL compatibility.
- Confirm the repository’s existing CI, lock, public-safety, worker, Graphify, and secret-screening contracts remain compatible with runtime dependencies.
- Decide the minimal authentication fixture and token representation that supports deterministic tenant tests without introducing an external identity provider.
- Decide how database-level audit immutability is expressed for PostgreSQL and isolated SQLite tests, with a fail-closed fallback if trigger installation is unavailable.

## Phase 1: Design artifacts

- `data-model.md`: entity fields, tenant ownership, relationships, lifecycle/state rules, indexes, and audit immutability constraints.
- `contracts/`: minimal authentication, health/readiness, tenant resource, job, audit, and descriptive connector/deployment contracts; no production write contract.
- `quickstart.md`: isolated local setup and runnable two-tenant, restart, audit immutability, health/readiness, and no-production-write validation scenarios.
- Update the `SPECKIT` reference in `AGENTS.md` to this plan before implementation.

## Phase 2: Implementation slices

1. Create the application configuration, database/session boundary, migrations/schema bootstrap, and error model with no secrets in defaults.
2. Implement tenant/user authentication and centralized tenant-scoped repository/service helpers.
3. Implement the issue-defined entity records and validated lifecycle/status fields, including job cost/retry/status data.
4. Implement append-only audit recording, sanitized metadata, chained/event integrity fields, and database-level update/delete rejection.
5. Implement health/readiness endpoints and descriptive connector/backup/approval/deployment records without execution methods.
6. Add focused unit/integration/failure tests, then run the complete repository security and dependency gates.

## Project Structure

### Documentation (this feature)

```text
specs/001-control-plane-audit/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── contracts/
├── quickstart.md
├── checklists/requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
appcare/
├── __init__.py
├── api.py                 # application factory and route registration
├── config.py              # validated development/staging settings
├── db.py                  # engine, sessions, schema bootstrap, transaction scope
├── auth/
│   ├── __init__.py
│   ├── service.py         # token/password verification and tenant context
│   └── dependencies.py    # request authentication boundary
├── models/
│   ├── __init__.py
│   ├── base.py
│   ├── identity.py        # tenants and users
│   ├── resources.py       # applications/assets and findings
│   ├── operations.py      # connectors, jobs, backups, approvals, deployments
│   └── audit.py           # append-only audit events and integrity fields
├── repositories/
│   ├── __init__.py
│   └── tenant_scope.py    # tenant-filtered reads and writes
├── services/
│   ├── __init__.py
│   ├── control_plane.py
│   └── audit.py
└── routes/
    ├── __init__.py
    ├── auth.py
    ├── health.py
    ├── resources.py
    ├── jobs.py
    └── audit.py

tests/
├── unit/
│   ├── test_auth.py
│   ├── test_models.py
│   └── test_sanitization.py
└── integration/
    ├── test_tenant_isolation.py
    ├── test_audit_immutability.py
    ├── test_restart_durability.py
    ├── test_health_readiness.py
    └── test_no_production_writes.py
```

**Structure Decision**: Use one AppCare Python service with explicit modules for configuration, database access, authentication, tenant-scoped repositories, services, and routes. The first implementation remains a single deployable unit so the security boundary can be tested end-to-end; later beta issues may split connectors or workers only after their permissions and rollback contracts are defined.

## Complexity Tracking

No constitution violations require justification. The database immutability and central tenant-scope layers are required security controls, not optional architectural complexity.
