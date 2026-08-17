# BETA-02 Research and Decisions

## Decision: Keep provider permissions as explicit internal read-only capabilities

**Rationale**: Provider authorization models use different names and granularity. AppCare needs one stable safety contract that can be tested before live credentials are authorized. The connector rejects capabilities outside its immutable provider specification; a future live adapter maps those capabilities to the provider's current grant model.

**Evidence**:

- [GitHub choosing permissions for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app) says apps should select the minimum permissions required and that endpoint documentation defines the required permission level. The initial AppCare mapping is repository metadata/content/pull-request read access only; no issue, workflow, administration, or write permission is allowed.
- [Vercel API integrations](https://vercel.com/docs/integrations/create-integration/vercel-api-integrations) documents separate integration scopes for deployment, project, domain, and team access and notes that updating project/domain resources requires write permissions. AppCare records only project/deployment/domain/team read capabilities in this phase and does not implement update calls.
- [Supabase Management API](https://supabase.com/docs/reference/api/introduction) documents OAuth scopes and endpoint-level fine-grained permissions, requires HTTPS bearer authentication, and distinguishes read endpoints from project/database/storage writes. AppCare uses internal project/auth/database/storage metadata-read capabilities and excludes migration, SQL execution, secret, key, project-admin, and storage-config write capabilities.

## Decision: Metadata-only credential references

**Rationale**: BETA-02 needs expiry, revocation, and rotation behavior but does not need to decide where raw provider secrets live. A metadata registry proves the lifecycle without creating a second secret store or copying the existing OpenCode auth store.

**Alternatives considered**:

- Store provider tokens in the AppCare database: rejected because this phase has no approved vault/custody design and would widen the secret boundary.
- Read provider tokens from `.env` or another user's OpenCode auth store: rejected by the AppCare/WordPress and no-secret rules.
- Implement OAuth now: deferred until owner-controlled provider application/account and callback authorization are explicitly available.

## Decision: Injected snapshots before live transport

**Rationale**: Deterministic tests must not call customer systems, mutate remote state, or depend on network availability. A fixture-backed connector proves permission, ownership, normalization, and idempotence while leaving transport and account authorization as a later controlled integration step.

**Alternatives considered**:

- Add provider SDKs: rejected because they enlarge the dependency and secret surface without being required for BETA-02 acceptance.
- Add unrestricted HTTP requests: rejected because a generic client could reach an unapproved host or expose a write method accidentally.
- Use a fake provider account: rejected because owner-controlled credentials and account authorization are not needed for this phase.

## Decision: Additive local reconciliation

**Rationale**: Replaying inventory must be idempotent, but an inventory run must not delete local evidence or imply provider mutation. Existing `Asset` records are reused when the tenant/application/provider/kind/locator key matches; new observations are inserted; no remote operation exists.

## Unresolved later integration work

- Owner-authorized provider app registrations, callback URLs, account/domain verification, and secret-vault custody.
- Current endpoint-to-scope mappings and response parsers for live GitHub, Vercel, and Supabase APIs.
- Rate-limit, pagination, retry, and live connector audit policy.
