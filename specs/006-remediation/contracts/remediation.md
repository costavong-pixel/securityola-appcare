# BETA-06 Remediation Contracts

## Context and workspace

`RemediationWorkspaceManager.create(context)` returns an isolated workspace
record or a sanitized boundary error. It accepts no credentials and never
accepts an arbitrary external path. `destroy(workspace)` removes only the
workspace it created; callers may instead mark it disposable for post-review
retention.

## Deterministic patch

`PatchBuilder.build(context, evidence, changes)` returns one immutable patch
candidate. The evidence must contain the finding fingerprint and at least one
deterministic evidence reference. Each change must include its relative path,
operation, preimage digest, postimage digest, and bounded content. Prompts,
model explanations, raw scanner payloads, and shell commands are not accepted.

## Validation and test gates

`PatchValidator.validate(workspace, patch)` checks context, paths, digests,
content, operation type, and workspace containment. `GateRunner.run(patch,
regression_adapter, security_adapter)` runs finite adapters and returns a
sanitized result. Any failure, timeout, unavailable adapter, scope rejection,
or missing evidence blocks promotion.

## Review and preview

`ReviewEvidence.from_patch(...)` records patch/source/evidence/rollback
references and changed-path summaries only. `PreviewAdapter.request(request)`
is a provider-neutral boundary. `FixturePreviewAdapter` is deterministic and
non-live. `UnapprovedVercelPreviewAdapter` always returns a denial until the
provider policy has a reviewed skill revision, bounded scope, and explicit
non-production authorization.

## Approval queue

`ApprovalQueue.request(...)` creates a tenant-scoped pending request after patch
and preview gates pass. `ApprovalQueue.decide(...)` accepts only an actor from
the same tenant and rejects conflicting duplicate decisions. The decision is a
review record; it does not call GitHub, Vercel, DNS, SSH, or any production
system.
