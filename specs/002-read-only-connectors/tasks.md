# Tasks: Read-Only Supported-Stack Connectors and Asset Inventory

**Input**: Design documents from `specs/002-read-only-connectors/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/api.md`, and `quickstart.md`

**Tests**: Required by the BETA-02 acceptance criteria. Negative and secret-safety tests precede implementation where practical.

## Phase 1: Setup and contract tests

- [x] T001 [P] Add provider capability and credential lifecycle contract tests in `tests/unit/test_connectors.py`.
- [x] T002 [P] Add read-only public-surface, health, permission, revocation, and expiry tests in `tests/integration/test_read_only_connectors.py`.
- [x] T003 [P] Add deterministic normalization, ownership, idempotence, tenant, and no-persist-on-failure tests in `tests/integration/test_asset_inventory.py`.

## Phase 2: Connector boundary

- [x] T004 Create immutable provider and connector result types in `appcare/connectors/types.py`.
- [x] T005 Implement metadata-only credential registration, rotation, expiry, and revocation in `appcare/connectors/credentials.py`.
- [x] T006 Implement provider read-only capability specifications and scope validation in `appcare/connectors/providers.py`.
- [x] T007 Implement the fixture-backed read-only connector protocol and provider adapters in `appcare/connectors/base.py` and `appcare/connectors/__init__.py`.

## Phase 3: Inventory and local reconciliation

- [x] T008 Implement safe record canonicalization, stable keys, deterministic digest, and ownership verification in `appcare/inventory/service.py`.
- [x] T009 Implement additive tenant/application-scoped reconciliation to existing `Asset` rows in `appcare/inventory/service.py`.
- [x] T010 Export the inventory service contract in `appcare/inventory/__init__.py` and add package documentation without provider secrets.

## Phase 4: Documentation and integration validation

- [x] T011 [P] Update `README.md`, `DEVELOPMENT.md`, `ARCHITECTURE.md`, and `SECURITY.md` with the BETA-02 read-only boundary, capability mapping, and deferred live-transport gate.
- [x] T012 [P] Update `AGENTS.md` and `BETA_LOOP.md` to reference the BETA-02 spec and preserve WordPress/production boundaries.
- [x] T013 Run focused connector/inventory tests and fix failures without adding provider SDKs or credentials.
- [x] T014 Run full pytest, Ruff, mypy, public-safety, worker-policy, build-lock, pip-audit, and diff checks.
- [ ] T015 Run Codex Security scan, independent final review, exact-head GitHub CI verification, Graphify impact update, and Saveruflo checkpoint for BETA-02.

## Dependencies and execution order

- Tests T001–T003 define the acceptance boundary and can be written in parallel.
- T004–T007 depend on the contract tests and are sequential where they touch connector types.
- T008–T010 depend on the connector result types and existing BETA-01 models.
- T011–T012 can run after the API boundary is stable.
- T013–T015 are sequential final gates; no issue close, merge, push, or deployment is authorized by these tasks.

## MVP scope

The BETA-02 MVP is T001–T010: deterministic read-only provider contracts, credential lifecycle metadata, ownership checks, stable inventory, and idempotent local asset reconciliation. T011–T015 close the evidence and safety gates.

## Current gate state

T001–T014 are complete. T015 has complete local security, review, Graphify,
and Saveruflo evidence. The current BETA-02 changes remain uncommitted in the
isolated workspace, so exact-head GitHub CI for this diff and the protected
owner merge gate are intentionally pending; the baseline `main` head and its
`quality` check were verified separately.
