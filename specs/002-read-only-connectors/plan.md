# Implementation Plan: Read-Only Supported-Stack Connectors and Asset Inventory

**Branch**: `codex/beta-02-connectors` | **Date**: 2026-08-17 | **Spec**: [spec.md](spec.md)

## Summary

Add a small provider-neutral connector boundary that can prove read-only permissions and ownership against injected provider snapshots, without requiring live customer credentials. The boundary will model credential metadata and rotation state, normalize GitHub/Vercel/Supabase inventory into deterministic assets, and optionally reconcile those assets into the existing tenant-scoped `Asset` table without deleting anything externally.

## Technical Context

**Language/Version**: Python 3.12+

**Primary Dependencies**: Existing Python standard library, SQLAlchemy 2.x models, and existing AppCare sanitization helpers. No new runtime dependency or provider SDK is required.

**Storage**: Existing isolated AppCare database for local asset reconciliation. Raw provider credentials are not stored; only an in-memory/provider-vault-neutral metadata contract is introduced.

**Testing**: pytest, deterministic synthetic provider snapshots, public-surface inspection, tenant-isolation persistence tests, Ruff, mypy, public-safety checks, pip-audit, and exact-head GitHub CI.

**Target Platform**: AppCare development/staging only. No live provider call is made by tests or setup.

**Constraints**: Read-only provider capability; no deploy, mutation, deletion, SQL execution, OAuth, secret printing, customer production access, WordPress access, or production API changes. Existing BETA-01 tests and boundaries must remain green.

**Scale/Scope**: Three provider specifications, one common connector contract, one synthetic snapshot adapter, deterministic normalization/reconciliation, and focused tests for the issue acceptance criteria.

## Constitution Check

- **I. Security before speed**: PASS. The public connector contract is read-only and credential metadata excludes raw secrets.
- **II. Deterministic evidence before AI claims**: PASS. Provider behavior is exercised through synthetic snapshots, negative states, stable digests, and source inspection.
- **III. Least privilege and tenant isolation**: PASS. Provider capabilities are allowlisted per provider and local reconciliation requires tenant/application ownership.
- **IV. No secrets in artifacts**: PASS. Fixtures use opaque fake references only; sanitization and public-safety tests reject secret-shaped values.
- **V. Staging, backup, and reversibility before production**: PASS. No live provider or deployment operation is introduced.
- **VI. AppCare and WordPress remain separate**: PASS. Only the isolated AppCare checkout and local test database are in scope.
- **VII. Third-party skills are untrusted**: PASS. No new skill or runtime SDK is installed.
- **VIII. Codex owns final decisions**: PASS. Codex owns capability definitions, threat boundaries, tests, and final review; DeepSeek is bounded to implementation.
- **IX. Exact review and CI evidence is required**: PASS. Full gates, security scan, Graphify, checkpoint, and exact-head CI remain required.

## Design Decisions

### 1. Provider capability registry

`appcare/connectors/providers.py` will define immutable `ProviderSpec` records for `github`, `vercel`, and `supabase`. Required capabilities are read-oriented strings. A shared validator rejects any capability containing write/deploy/delete/mutate/execute semantics and rejects unknown providers.

### 2. Metadata-only credential registry

`appcare/connectors/credentials.py` will define immutable metadata and a small registry for active/revoked/expired versions. The registry accepts opaque references only. It never accepts a raw secret parameter, and `rotate()` revokes the old version before making the replacement available.

### 3. Injected read-only connector

`appcare/connectors/base.py` will define the read-only interface and a fixture-backed implementation. The interface contains health, permission, inventory, and ownership methods only. Provider classes will reuse the common implementation with provider-specific specs and snapshot validation.

### 4. Deterministic inventory

`appcare/inventory/service.py` will canonicalize safe remote records, de-duplicate by provider/kind/locator, sort records, calculate a SHA-256 digest, and reconcile only into the existing AppCare `Asset` table. Reconciliation is tenant-filtered and additive; it never deletes or writes to a provider.

### 5. Ownership verification

Ownership checks will require at least one expected resource identifier or approved domain. Domain matching will be exact or a deliberate subdomain of the normalized expected domain; malformed URLs, userinfo, and missing provider identity fail closed.

## Project Structure

```text
appcare/
├── connectors/
│   ├── __init__.py
│   ├── base.py
│   ├── credentials.py
│   ├── providers.py
│   └── types.py
└── inventory/
    ├── __init__.py
    └── service.py

tests/
├── unit/test_connectors.py
├── integration/test_read_only_connectors.py
└── integration/test_asset_inventory.py

specs/002-read-only-connectors/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── contracts/api.md
├── quickstart.md
├── checklists/requirements.md
└── tasks.md
```

## Complexity Tracking

No constitution violations require justification. The additional capability and credential metadata types are the minimum boundary needed to prevent provider write authority and raw-secret handling from leaking into later beta phases.

## Reconciliation with PR #16

The previously reviewed PR #16 GET-only transport, provider profiles, adapter,
tenant-scoped service, route, model, and API contract remain in this branch.
The fixture-backed contract and deterministic inventory layer in this plan is
an additional lower-level validation boundary; it does not remove or weaken
the existing API/service boundary.
