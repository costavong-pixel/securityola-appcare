# Implementation Plan: BETA-06 Safe Remediation Workspace

**Branch**: `codex/beta-06-remediation` | **Date**: 2026-08-18 | **Spec**: [spec.md](spec.md)

**Issue**: #7 | **Target**: AppCare only

## Summary

BETA-06 adds the bounded remediation boundary that follows BETA-03 deterministic
findings and BETA-05 durable orchestration. It creates tenant/job-scoped
disposable workspaces, derives reviewable patches only from deterministic
evidence, validates path/content/preimage/test safety, records rollback
references, and exposes explicit PR, preview, and approval adapters. The live
provider edges remain fail-closed: no customer repository, Vercel account,
production environment, WordPress resource, or credential is used by this beta.

## Technical Context

**Language/Version**: Python 3.12–3.14

**Primary Dependencies**: Existing standard-library AppCare domain modules,
`pytest`, Ruff, mypy, existing BETA-03 scanning contracts, and existing BETA-05
workflow contracts. No new runtime dependency is required.

**Storage**: Disposable filesystem workspaces for patch preparation; sanitized
review/approval records are represented by explicit contracts and can be
connected to the existing tenant-scoped workflow/audit store. No production
database or provider state is used.

**Testing**: Unit and integration tests with synthetic findings, deterministic
file fixtures, failure-injection adapters, public-safety scanning, dependency
audit, and exact-head CI.

**Target Platform**: AppCare development/test checkout and isolated preview
adapter boundary. Production and WordPress paths are prohibited.

**Project Type**: Python AppCare control-plane library and workflow boundary.

**Performance Goals**: A bounded local patch validation run completes without
unbounded retries or external calls; workspace operations are limited to the
declared job root and change set.

**Constraints**: No raw credentials, customer artifacts, `.env` values,
OpenCode auth stores, arbitrary shell execution, production writes, provider
deployment, merge authority, DNS changes, or WordPress access.

**Scale/Scope**: One tenant/application/job per remediation boundary instance;
at most 100 evidence references and 100 changed paths per candidate; all limits
are explicit and testable.

## Constitution Check

*GATE: Must pass before research/design and again after design.*

- **I. Security before speed**: PASS. Every workspace, path, content, test, and
  preview request is validated before mutation or external-adapter invocation.
- **II. Deterministic evidence before AI claims**: PASS. Patch candidates require
  finding/evidence references and an explicit deterministic change description;
  no model explanation can create a patch.
- **III. Least privilege and tenant isolation**: PASS. Contracts bind tenant,
  application, and job identifiers; cross-tenant references fail closed.
- **IV. No secrets in artifacts**: PASS. Credential-like content and secret-key
  metadata are rejected; outputs are sanitized identifiers/digests only.
- **V. Staging, backup, and reversibility before production**: PASS. This beta
  remains non-production and requires source/rollback references before preview
  readiness; production deployment is deferred to BETA-07.
- **VI. AppCare and WordPress remain separate**: PASS. Forbidden markers and
  path checks reject WordPress, `/var/www/api.securityola.com`, and production.
- **VII. Third-party skills are untrusted**: PASS. Vercel is audited as deferred;
  no unreviewed skill or CLI is installed, and live execution is denied.
- **VIII. Codex owns final decisions**: PASS. PR, preview, approval, merge, and
  production capabilities are adapter contracts without worker authority.
- **IX. Exact review and CI evidence**: PASS as an acceptance gate. The issue
  remains open until deterministic gates, security review, exact-head CI,
  Graphify, and Saveruflo evidence are recorded.

## Research Summary

See [research.md](research.md). The key decision is to keep the Vercel provider
edge as an AppCare-owned, fail-closed adapter rather than install a third-party
skill. Official Vercel documentation describes preview deployments and
deployment-protection controls, but those external behaviors are not treated as
authorization for this repository to call a customer project.

## Architecture

```text
Finding + deterministic evidence
              |
              v
      RemediationContext validation
              |
              v
   Disposable WorkspaceManager
              |
              v
      DeterministicPatchBuilder
              |
              v
        PatchValidator
        /            \
       v              v
 RegressionGate  SecurityGate
        \            /
         v          v
       ReviewEvidence + rollback reference
              |
              v
      PreviewAdapter (fixture or denied live)
              |
              v
        Preview verification
              |
              v
        Tenant approval queue
```

### Source layout

```text
appcare/remediation/
├── __init__.py
├── approval.py       # tenant-scoped internal approval queue
├── contracts.py      # immutable remediation, patch, gate, preview records
├── gates.py          # bounded regression/security gate orchestration
├── patches.py        # deterministic patch construction and validation
├── preview.py        # fixture preview and fail-closed provider boundary
└── workspace.py      # symlink/path-safe disposable workspace lifecycle

specs/006-remediation/
├── contracts/remediation.md
├── data-model.md
├── quickstart.md
├── research.md
├── spec.md
└── tasks.md

tests/unit/test_remediation.py
tests/integration/test_remediation_boundaries.py
docs/engineering/BETA-06-REMEDIATION.md
```

### Boundary rules

- The patch builder consumes an immutable `Finding`, its evidence references,
  and a bounded `FileChange` tuple. It does not accept prompts or raw scanner
  output.
- Workspace paths are canonicalized without following symlinks. The workspace
  manager rejects root/production/WordPress/API paths and all child traversal.
- The patch validator permits only add/modify operations under explicitly
  allowlisted AppCare source prefixes and rejects secrets, credentials, `.env`,
  private keys, deletes, renames, and generated broad diffs.
- Gate adapters return sanitized `GateResult` values. Missing, timed-out, or
  failed gates block promotion; a scanner failure is never converted into a
  finding or remediation request.
- Preview requests require a passed patch, non-production environment,
  AppCare-owned project reference, reviewed skill metadata, and bounded scope.
  The fixture adapter demonstrates the flow; the live adapter denies execution
  until a separate reviewed provider boundary exists.
- Approval decisions are tenant-scoped and record-only. They do not authorize
  merge, deploy, DNS, credential access, or production writes.

## Dependency and Skill Decision

No runtime dependency is added. The existing long-run DeepSeek worker pin
remains OpenCode `1.18.16`; system/multi-agent OpenCode remains `1.18.18`.
Vercel remains deferred/not installed. A future live adapter must separately
record the skill source/revision, permissions, secret handling, sandbox,
failure behavior, and preview protection configuration before it is enabled.

## Test Strategy

- Valid finding/evidence produces one stable patch identity.
- Suppressed findings, scanner failures, missing evidence, cross-tenant input,
  forbidden paths, symlinks, traversal, secrets, malformed changes, deletes,
  renames, and preimage drift fail closed.
- Regression and security gate failures/unavailability block promotion.
- Fixture preview succeeds only for a non-production AppCare project and records
  sanitized smoke/security evidence.
- Unreviewed/live Vercel execution makes no external call and returns a stable
  denial code.
- Approval queue rejects cross-tenant and duplicate/conflicting decisions.
- All new source paths pass Ruff, mypy, pytest, public-safety, dependency audit,
  Codex Security review, Graphify, Saveruflo, and exact-head CI.

## Complexity Tracking

No constitution violations require justification.
