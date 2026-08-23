# BETA-06 Safe Remediation Boundary

BETA-06 issue #7 prepares security fixes without editing customer production.
It follows the BETA-03 deterministic finding/evidence boundary and the BETA-05
durable workflow boundary.

## Accepted scope

- Each remediation job is bound to one AppCare tenant, application, finding,
  source revision, and disposable workspace.
- A patch is generated only from deterministic evidence and an explicit bounded
  file-change description.
- Patch validation rejects traversal, absolute paths, symlinks, forbidden
  WordPress/production/API paths, secret-like content, deletes, renames,
  unrelated files, preimage drift, and broad generated changes.
- Regression and security gates are separate. A failure, timeout, unavailable
  result, or malformed adapter response blocks preview readiness.
- Review evidence contains only opaque IDs, SHA-256 digests, changed paths,
  source/reference commits, gate references, and rollback references.
- The fixture preview adapter is local and non-live. The Vercel adapter fails
  closed until a separate skill/provider review approves a bounded AppCare
  preview execution path.
- The approval queue is an internal record. Approval does not grant merge,
  deployment, DNS, credential, SSH, or production authority.

## Vercel skill decision

The repository has no accepted Vercel skill or live Vercel credential boundary.
The third-party skill register remains `Deferred, not installed`. No Vercel CLI,
SDK, token, project lookup, deployment, preview promotion, or protection bypass
is used in BETA-06. A future live adapter must first record its source/revision,
permissions, secret handling, sandbox, failure behavior, project allowlist, and
preview-protection verification.

Vercel's official documentation describes deployment-generated preview URLs and
separate deployment-protection controls. Those provider capabilities do not
authorize AppCare to call a customer project, so the BETA-06 implementation
keeps the external edge denied by default:

- <https://vercel.com/docs/deployments/overview>
- <https://vercel.com/docs/deployment-protection>
- <https://vercel.com/docs/deployments/promote-preview-to-production>

## Sanitized evidence format

```text
TARGET=AppCare
PATCH_STATUS=PASS|BLOCKED
PATCH_ID=<sha256>
EVIDENCE_REFS=<sha256,...>
SOURCE_REVISION=<git-revision>
REFERENCE_COMMIT=<git-revision>
ROLLBACK_REFERENCE=<git-revision>
CHANGED_PATHS=<relative-appcare-paths>
REGRESSION_GATE=PASS|BLOCKED
SECURITY_GATE=PASS|BLOCKED
PREVIEW=FIXTURE_PASS|DENIED_UNAPPROVED|BLOCKED
APPROVAL=PENDING|APPROVED|REJECTED
SECRETS_EXPOSED=NO
PRODUCTION_TOUCHED=NO
WORDPRESS=UNTOUCHED
```

Never include source file contents, customer vulnerability evidence, provider
URLs/tokens, `.env` values, private keys, raw scanner output, or model prompts
in this evidence.

## Relationship to later betas

BETA-06 stops at safe preparation, deterministic validation, review evidence,
and non-production preview boundaries. BETA-07 owns controlled production
deployment, post-deploy verification, and automatic rollback. No BETA-06 adapter
can promote a preview or merge a branch.
