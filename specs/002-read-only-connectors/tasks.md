# Tasks: Read-Only Connectors and Asset Inventory

**Input**: Design documents from `specs/002-read-only-connectors/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`,
`contracts/connectors.md`, and `quickstart.md`.

## Phase 1: Setup and foundation

- [ ] T001 Record the BETA-02 scope, exact base, and no-WordPress boundary in the task packet at `.codex/tasks/appcare-beta02-implementation.json`
- [ ] T002 [P] Add connector package exports and fixed provider capability profiles in `appcare/connectors/profiles.py`
- [ ] T003 [P] Add fixed GET request descriptors, normalized observations, and transport protocol in `appcare/connectors/contracts.py` and `appcare/connectors/transport.py`
- [ ] T004 [P] Add provider adapters and registry with unavailable default transport in `appcare/connectors/adapters.py`

## Phase 2: Persistence and service foundation

- [ ] T005 [P] Extend the Connector and Asset models with safe BETA-02 metadata in `appcare/models/operations.py` and `appcare/models/resources.py`
- [ ] T006 [P] Add ConnectorCredential, ConnectorCheck, and InventoryRun models and exports in `appcare/models/operations.py` and `appcare/models/__init__.py`
- [ ] T007 Implement safe connector response construction and registration validation in `appcare/services/connectors.py`
- [ ] T008 Implement fail-closed health, permission, ownership, and idempotent local inventory reconciliation in `appcare/services/connectors.py`

## Phase 3: User Story 1 - Safe connector checks (Priority: P1)

**Goal**: A tenant can register a supported read-only connector and obtain
health, permission, and ownership results without exposing credentials or
crossing tenant boundaries.

**Independent test**: Contract and integration tests create two tenants,
attempt foreign access, exercise valid and invalid scoped credential metadata,
and verify all provider requests are fixed `GET` descriptors.

### Tests for User Story 1

- [ ] T009 [P] [US1] Test provider allowlists, write/secret scope rejection, and safe references in `tests/unit/test_connector_profiles.py`
- [ ] T010 [P] [US1] Test deny-by-default transport and fixed request descriptors in `tests/unit/test_connector_transport.py`
- [ ] T011 [P] [US1] Test strict connector registration, credential redaction, check responses, and no mutating OpenAPI surface in `tests/contract/test_connectors_api.py`
- [ ] T012 [US1] Test connector/check cross-tenant denial and expired/revoked/insufficient credential failure in `tests/integration/test_connector_tenant_isolation.py` and `tests/integration/test_connector_failures.py`

### Implementation for User Story 1

- [ ] T013 [US1] Extend strict connector request/response schemas and add check/inventory response schemas in `appcare/routes/schemas.py`
- [ ] T014 [US1] Update existing connector registration/list/detail routes to use safe BETA-02 metadata in `appcare/routes/operations.py`
- [ ] T015 [US1] Add tenant-scoped check and inventory endpoints in `appcare/routes/connectors.py`
- [ ] T016 [US1] Register the connector router and injectable registry in `appcare/api.py`

## Phase 4: User Story 2 - Repeatable asset inventory (Priority: P2)

**Goal**: A passed connector can reconcile normalized provider assets into the
tenant's local inventory repeatedly, retiring missing local assets without
provider mutation.

**Independent test**: A fake transport returns the same observations twice,
then omits one asset, and tests verify stable asset identity, no duplication,
safe metadata, and retirement.

### Tests for User Story 2

- [ ] T017 [P] [US2] Test repeatable inventory, stable asset identities, and retirement in `tests/integration/test_connector_inventory.py`
- [ ] T018 [P] [US2] Test ownership mismatch and malformed/provider-secret-shaped observations fail closed in `tests/integration/test_connector_failures.py`
- [ ] T019 [P] [US2] Test connector-linked asset response redaction in `tests/unit/test_connector_redaction.py`

### Implementation for User Story 2

- [ ] T020 [US2] Add connector-linked asset response fields and safe allowlisted metadata persistence in `appcare/models/resources.py`, `appcare/routes/schemas.py`, and `appcare/services/connectors.py`
- [ ] T021 [US2] Add inventory run persistence, idempotent snapshot handling, and audit events without raw payloads in `appcare/services/connectors.py`
- [ ] T022 [US2] Connect inventory responses to the existing asset list/detail routes in `appcare/routes/resources.py`

## Phase 5: User Story 3 - Documentation and release evidence (Priority: P3)

- [ ] T023 [P] [US3] Document provider scopes, credential custody, transport restrictions, and fixture-only execution in `specs/002-read-only-connectors/research.md`, `data-model.md`, `contracts/connectors.md`, and `quickstart.md`
- [ ] T024 [P] [US3] Update BETA-MASTER and issue #3 with the exact branch, evidence, and optional DeepSeek deferment after implementation
- [ ] T025 [US3] Run focused tests, full deterministic/security/dependency/secret gates, and inspect the complete diff
- [ ] T026 [US3] Run Graphify impact update, fresh Codex Security exact-diff validation, independent Codex final review, exact-head CI, and Saveruflo checkpoint

## Dependencies and execution order

- T001 precedes all implementation work.
- T002-T004 can proceed in parallel and precede service work.
- T005-T006 precede T007-T008.
- T007-T008 precede T013-T016.
- US1 must pass before US2 inventory is accepted.
- T017-T022 depend on the adapter, model, service, and route foundation.
- T025-T026 are release gates after all code and tests are complete.

## Implementation strategy

1. Keep live provider access disabled and prove the read-only boundary with fake
   transports.
2. Implement and test US1 first: supported profiles, tenant scope, credential
   safety, and check failure behavior.
3. Add US2 local reconciliation only after US1 passes.
4. Finish with direct diff inspection, security scan, exact-head CI, and checkpoint.
