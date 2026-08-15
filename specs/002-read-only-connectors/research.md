# BETA-02 Read-Only Connector Research

**Date**: 2026-08-15
**Scope**: AppCare development/staging control-plane design only. No provider account or live credential was accessed.

## Decision 1: Use provider-specific read-only capability profiles

**Decision**: Every connector declares a provider capability profile and the application rejects any capability outside that profile before a provider request is constructed. The default profiles are:

- GitHub App: repository metadata read. Contents read is a separately named capability and is not implicitly granted. Administration, deployments, Actions/workflows, secrets, variables, webhooks, issues/pull-request writes, and all other write permissions are denied.
- Vercel: project read, deployment read, team read, and current-user read only when required for ownership evidence. Project writes, domains, environment variables, log drains, Edge Config writes, and deployment creation are denied.
- Supabase OAuth/Management API: Auth read, Database read, Organizations read, Projects read, and Storage read only as needed by the inventory contract. All write scopes and Secrets read are denied.

**Rationale**: GitHub recommends selecting the minimum permissions required for an App, and its endpoint documentation maps each REST operation to required permissions. Vercel’s integration scopes distinguish read-only project/deployment access from project, domain, environment-variable, and deployment writes. Supabase’s current OAuth scope table separates read and write categories, and the Secrets read scope can expose project API keys/secrets, so it is outside BETA-02 even though the inventory is read-only.

**Sources**:

- [GitHub: Choosing permissions for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
- [GitHub: Permissions required for GitHub Apps](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps?apiVersion=latest)
- [Vercel: Building integrations with the REST API](https://vercel.com/docs/integrations/create-integration/vercel-api-integrations)
- [Vercel: REST API reference](https://vercel.com/docs/rest-api)
- [Supabase: OAuth app scopes](https://supabase.com/docs/guides/integrations/build-a-supabase-oauth-integration/oauth-scopes)

## Decision 2: Keep live credential custody outside the BETA-02 control-plane records

**Decision**: BETA-02 stores only a non-secret credential reference, provider, scope set, lifecycle status, expiration timestamp, and safe fingerprint. There is no credential-value column, API-key retrieval route, token echo, or provider secret response persistence.

**Rationale**: Supabase documents that personal access tokens carry the user’s privileges and that its Secrets read scope retrieves project API keys and secrets. The control plane therefore records only scoped metadata and delegates any future secret custody to an explicitly approved isolated secret service. Automated tests use fake references and provider fixtures.

**Source**: [Supabase Management API authentication and scopes](https://supabase.com/docs/reference/api/introduction)

## Decision 3: Use narrow adapter contracts with a deny-by-default transport

**Decision**: Provider adapters emit only fixed read request descriptors and normalize provider observations into AppCare assets and check outcomes. The transport contract accepts `GET` requests only, has no generic method or arbitrary URL field, and is injected for deterministic tests. The default development adapter has no live credential or provider transport.

**Rationale**: This keeps provider-specific API details behind a small boundary and makes it impossible for a BETA-02 route to gain deployment, mutation, deletion, or arbitrary command authority by passing a new request method or path from user input.

## Decision 4: Treat provider ownership as an explicit invariant

**Decision**: A connector is bound to one tenant-owned AppCare application and an expected provider resource reference. Health/permission/ownership checks must compare normalized provider resource owner and provider-side credential identity (account/team/organization) with that expected reference before inventory results are persisted. Unknown or ambiguous ownership fails closed.

**Rationale**: Provider authentication alone does not prove that a returned repository, Vercel project, or Supabase project belongs to the AppCare tenant. Ownership evidence is part of the persisted check result but raw provider responses are not.

## Decision 5: Reconcile locally and idempotently without destructive provider actions

**Decision**: Inventory uses a stable `(tenant, connector, provider, provider_reference)` identity. Repeated observations update safe local metadata and `last_seen` state; missing observations retire local assets while preserving their history. The connector never issues delete, deploy, database mutation, sync-write, or credential-rotation calls.

**Rationale**: This supports repeatable baselines and later scanning without turning inventory into a destructive synchronization system.

## Resolved questions and limitations

- Supabase project/database metadata endpoints change over time and some database configuration endpoints can return connection strings. BETA-02 uses only documented read endpoints whose responses are filtered to safe metadata; connection strings, API keys, JWTs, and secrets are never persisted.
- Provider SDK adoption is deferred. The first implementation uses repository-owned contracts and fake transports, so CI does not need provider credentials or network access. A future live transport requires a separate security review and exact provider endpoint allowlist.
- Ownership evidence differs by provider, so the common contract uses a normalized ownership result rather than pretending the providers expose identical fields.
