# BETA-06 Research Decisions

## Remediation boundary

- **Decision**: Keep remediation preparation in an AppCare-owned domain package
  with injected adapters for tests, review evidence, preview, and approval.
- **Rationale**: The existing BETA-03 scanner contracts already distinguish
  deterministic evidence from findings, and BETA-05 already provides bounded
  workflow/action/approval/rollback routing. BETA-06 should add the missing
  patch/workspace safety boundary without creating a second orchestration model.
- **Alternatives considered**: Letting a model write directly into a checkout
  was rejected because it would bypass path, preimage, evidence, and rollback
  validation. A live provider SDK was rejected because no provider credential or
  production authorization is required for this beta.

## Disposable workspaces

- **Decision**: Require an absolute, canonical AppCare workspace root and a
  tenant/application/job child. Reject symlink crossings, parent traversal,
  production markers, WordPress markers, and unrelated server paths.
- **Rationale**: A filesystem boundary is independently testable and prevents a
  patch worker from turning a relative path into a server-wide write.
- **Alternatives considered**: A shared checkout was rejected because concurrent
  jobs and failed patches could contaminate one another. A broad temporary
  directory was rejected because it does not prove AppCare ownership.

## Patch representation

- **Decision**: Represent a patch as a bounded list of add/modify file changes
  with preimage and postimage SHA-256 digests, deterministic evidence refs,
  source revision, patch digest, and rollback/reference commit.
- **Rationale**: Digest-backed changes are reviewable without storing customer
  content in the public repository and allow preimage drift to block a patch.
- **Alternatives considered**: Accepting arbitrary unified diffs or shell patch
  commands was rejected because deletes, renames, symlinks, generated churn,
  and command injection are harder to constrain at the trust boundary.

## Regression and security gates

- **Decision**: Use two explicit bounded adapter protocols. A result other than
  a sanitized pass blocks preview readiness.
- **Rationale**: Regression correctness and security safety are separate claims;
  one cannot substitute for the other. Scanner failures remain failures, not
  findings.
- **Alternatives considered**: Treating a missing test runner as a pass was
  rejected because it would create a false acceptance signal.

## Vercel skill and preview boundary

- **Decision**: Do not install or invoke a third-party Vercel skill in BETA-06.
  Provide a fixture preview adapter and a live adapter that fails closed until a
  separately reviewed AppCare-owned provider boundary is configured.
- **Rationale**: The repository's third-party skill register explicitly marks
  Vercel as deferred/not installed. Official Vercel documentation describes
  preview deployment URLs and deployment protection, including protection for
  preview URLs and separate controls for production; these are provider
  behaviors, not permission for AppCare to access a customer project.
- **Alternatives considered**: Installing an unreviewed skill or using a
  developer's ambient Vercel token was rejected because it would violate the
  no-secret/no-live-provider boundary and make scope non-reproducible.
- **Primary sources**:
  - https://vercel.com/docs/deployments/overview
  - https://vercel.com/docs/deployment-protection
  - https://vercel.com/docs/deployments/promote-preview-to-production

## Approval and rollback

- **Decision**: Approval is an internal tenant-scoped record and must reference
  passed patch/preview evidence plus a rollback/reference commit. It cannot grant
  production or merge authority.
- **Rationale**: BETA-07 owns controlled production deployment and rollback;
  BETA-06 should produce the inputs without silently creating the authority.
- **Alternatives considered**: Treating a queue decision as deployment
  authorization was rejected by the constitution and BETA-05 workflow contract.
