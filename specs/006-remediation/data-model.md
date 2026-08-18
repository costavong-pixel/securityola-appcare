# BETA-06 Remediation Data Model

All records are immutable value objects at the adapter boundary. Text is
bounded and credential-like data is rejected. No record stores customer source
content, raw scanner output, provider credentials, or model prompts.

| Entity | Required fields | Invariants |
| --- | --- | --- |
| `RemediationContext` | tenant, application, job, finding fingerprint, source revision, workspace root | IDs are opaque safe identifiers; target is non-production AppCare; finding is active and tenant/application scoped |
| `RemediationWorkspace` | workspace ID, context IDs, canonical root, state | Root is absolute, canonical, non-symlinked, disposable, and inside the approved AppCare workspace root |
| `FileChange` | relative path, operation, preimage digest, postimage digest, bounded content | Only add/modify; path is relative and allowlisted; content contains no secret-like values |
| `PatchCandidate` | patch ID, context, evidence refs, changes, source revision, patch digest, rollback/reference commit | Evidence is deterministic; at most 100 changes/refs; digest is deterministic; no production authority |
| `GateResult` | gate kind, status, code, evidence ref, attempt count | Status is pass/fail/blocked; unavailable/timeout/failure never means pass |
| `PreviewRequest` | preview ID, patch ID, provider, project reference, environment, skill revision, scope | Provider is closed-set `vercel`; environment is `preview`; project is AppCare-owned; live execution requires explicit reviewed metadata |
| `PreviewResult` | preview ID, status, sanitized URL/reference, smoke/security refs, code | Result is pass/fail/blocked; no credential or bypass secret is present |
| `ApprovalRequest` | approval ID, tenant, patch ID, preview ID, rollback reference, status | Status is pending/approved/rejected/expired; decision actor is same tenant; approval never grants merge/deploy/production authority |

## State transitions

```text
candidate
  -> workspace_created
  -> patch_prepared
  -> patch_validated
  -> gates_passed
  -> preview_ready
  -> approval_pending
  -> approved | rejected | expired
```

Any scope, evidence, path, content, preimage, gate, or preview failure moves
the bounded operation to a sanitized blocked/failed result. A scanner failure
cannot enter `candidate` as a finding. A preview failure cannot enter
`approval_ready`.

## Identity and idempotency

- `patch_id`, `preview_id`, and `approval_id` are deterministic SHA-256-derived
  opaque references from tenant/job/finding/source inputs and do not contain
  customer names or provider secrets.
- Repeating the same request returns the same identity and result when the
  input digest is unchanged.
- Reusing an identity with different content, tenant, or source revision is a
  conflict and is rejected.

## Scope rules

- Forbidden markers include WordPress, Barnd, Shield, `/var/www`, production,
  deploy credentials, `.env`, private keys, and SSH authorization paths.
- Preview provider and project references are allowlisted; arbitrary endpoints,
  repositories, branches, domains, and buckets are not accepted.
- The workspace root is not the repository root and is never the production
  filesystem.
