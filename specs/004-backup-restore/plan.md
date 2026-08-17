# Implementation Plan: BETA-04 Backup and Restore Testing

**Branch**: `codex/beta-04-backup-restore`  
**Base**: protected `main` at `22196c9bface2cfeff1b049bb9e9890520ce38c6`  
**Spec**: [spec.md](spec.md)

## Technical context

- Python 3.12–3.14, existing AppCare SQLAlchemy/FastAPI foundation.
- Domain contracts live under `appcare/backups/`; no production route or
  provider SDK is added in this slice.
- AES-GCM envelope encryption is injected through a key-custody boundary; raw
  keys never enter manifests, logs, fixtures, or checkpoints.
- An isolated filesystem/in-memory vault is test-only. B2 and Glacier are
  validated destination descriptors, not live adapters.
- Restore uses a staging directory and atomic promotion so partial content is
  never reported as a successful restore.
- All tests use synthetic data only.

## Constitution check

| Principle | Design response | Status |
|---|---|---|
| Security before speed | Validate target, vault namespace, retention, encryption, and checksums before healthy status. | PASS |
| Fail closed | Upload, credential, checksum, duplicate, and restore failures remain unhealthy states. | PASS |
| Tenant isolation | Target and restore destination carry tenant/application identity and reject mismatches. | PASS |
| No secrets | Only opaque credential references are accepted; raw keys are process-local and never serialized. | PASS |
| Reversibility | Restore is staged and atomically promoted; no production or remediation writes exist. | PASS |
| AppCare boundary | Paths and destination namespaces reject WordPress/production-server markers. | PASS |
| Third-party skills | Candidate backup skills were not present on the AppCare skill path; no unreviewed skill was installed. | PASS |
| External provider honesty | B2/Glacier remain unconfigured descriptors until owner-controlled credentials and policy are available. | PASS |

## Design decisions

1. **Provider-neutral vault protocol**: storage and cloud credentials are
   injected rather than embedded in the backup domain.
2. **Encrypted envelope before storage**: the vault receives only an encrypted
   payload plus a sanitized manifest and digest.
3. **Immutable retention is a state transition**: an early delete is rejected
   and recorded; it is not silently treated as cleanup.
4. **Restore is two-phase**: decrypt and validate into a staging directory,
   then atomically promote only after all components pass integrity checks.
5. **Test evidence is deliberately bounded**: controlled-test-app evidence is
   labeled as such and cannot be promoted to live-provider or production
   recovery evidence.

## Project structure

```text
appcare/backups/
├── __init__.py       # public contracts and coordinator exports
├── contracts.py      # targets, manifests, destinations, vault protocols
├── crypto.py         # injected AES-GCM envelope boundary
├── models.py         # jobs, artifacts, receipts, restore evidence
├── pipeline.py       # backup, verify, restore, and failure state machine
└── stores.py         # isolated test vaults and unavailable cloud boundary
tests/unit/test_backups.py
tests/integration/test_backups.py
```

## Verification strategy

- Unit-test target/path/namespace validation, canonical manifest hashing,
  encryption boundary, state transitions, and retention decisions.
- Integration-test a synthetic Git/database/storage/config snapshot through
  encrypted storage and isolated restore.
- Inject interrupted upload, corruption, revoked credential, duplicate job,
  large component, partial restore, retention expiry, and locked-delete cases.
- Run full tests, Ruff, mypy, public-safety, worker-policy, build-lock,
  dependency, Codex Security, independent Luna, Graphify, Saveruflo, and
  exact-head CI gates before closing issue #5.

## External gate

Actual B2/Glacier uploads require owner-controlled credentials and a confirmed
vault/account policy. Until that gate is supplied, the repository must not
claim live off-site backup health; the controlled rehearsal remains useful and
safe to run.
