# BETA-01 Control Plane Research

**Feature**: AppCare Control Plane and Tenant-Safe Audit Trail
**Revision**: 2026-08-14

## Decision 1: Use a narrow Python HTTP service boundary

- **Decision**: Use FastAPI for the minimal HTTP application and dependency-injected authentication/tenant context.
- **Rationale**: The repository is already Python-based, and the official FastAPI security guidance documents bearer-token and password-flow building blocks without requiring BETA-01 to integrate an external identity provider.
- **Application choice**: BETA-01 uses an AppCare-owned development authentication service with locally generated test identities. OAuth, GitHub/Vercel/Supabase connectors, and production identity integrations remain later-phase work.
- **Source**: https://fastapi.tiangolo.com/tutorial/security/ and https://fastapi.tiangolo.com/tutorial/security/first-steps/

## Decision 2: Use SQLAlchemy 2.x sessions and explicit transactions

- **Decision**: Map the control-plane entities with SQLAlchemy 2.x declarative models and keep transaction scope explicit in a request/service boundary.
- **Rationale**: The official SQLAlchemy 2.0 documentation treats `Session` as the persistence interface and documents explicit begin/commit/rollback framing. ORM events are available for enforcing application-level audit protections and invariant checks.
- **Source**: https://docs.sqlalchemy.org/en/20/orm/session.html, https://docs.sqlalchemy.org/en/20/orm/session_basics.html, and https://docs.sqlalchemy.org/en/20/orm/events.html

## Decision 3: PostgreSQL target with isolated SQLite test fixtures

- **Decision**: PostgreSQL is the deployment target; tests use temporary SQLite databases only, with dialect-specific schema/trigger setup tested separately.
- **Rationale**: Issue #2 requires durable PostgreSQL-oriented data, while a temporary SQLite fixture keeps deterministic tests local and avoids any production or shared-server database access. The model avoids provider-specific SQL except for the narrow audit immutability trigger adapter.
- **Driver**: Use Psycopg 3 for PostgreSQL connectivity; its official documentation covers the current `psycopg` module, parameterized execution, and supported installation modes.
- **Source**: https://www.psycopg.org/psycopg3/docs/basic/usage.html and https://www.psycopg.org/psycopg3/docs/basic/index.html

## Decision 4: AppCare-owned bearer tokens for the foundation

- **Decision**: Accept a bearer token at the HTTP boundary, hash stored token secrets with a one-way password hash, and resolve the token to one user and one tenant before any tenant query. Test fixtures create fake local identities directly; no token values are committed or logged.
- **Rationale**: The foundation needs a real authentication boundary and deterministic cross-tenant tests but does not need to select or operate an external identity provider yet. A narrow token service keeps later provider integration behind one dependency boundary.
- **Rejected alternative**: Hard-coded user headers or an unscoped global test identity were rejected because they would not prove authentication or tenant isolation.

## Decision 5: Append-only audit events with defense in depth

- **Decision**: Audit events are inserted through a dedicated service, never exposed through update/delete routes, include sanitized metadata and a previous-event hash link, and receive database-level update/delete rejection triggers where the dialect supports them.
- **Rationale**: Service-only append rules are not enough against accidental direct writes. The trigger adapter and negative tests provide a second boundary; hash chaining makes silent alteration detectable during verification.
- **Fallback**: If a target database cannot install the immutable trigger, startup fails closed rather than silently weakening the audit guarantee.

## Decision 6: No executable external connector in BETA-01

- **Decision**: Connector, backup, approval, and deployment tables are descriptive state only. No route or service method accepts production credentials, calls a provider, mutates an external system, or grants deployment authority.
- **Rationale**: This keeps the feature within issue #2 and preserves the later ordered connector/deployment gates, staging boundary, and production approval requirements.

## Resolved unknowns

- The initial API can be a small internal/dev surface; a public dashboard is not required for BETA-01.
- Local SQLite is a test fixture, not a production storage recommendation.
- Provider-specific authentication and connector details are deferred rather than left ambiguous.
- Database immutability is a required control with a fail-closed setup path, not an optional enhancement.
