# BETA-03 Scanning Foundation Quickstart

## Scope

This guide validates the deterministic, synthetic scanning foundation. It does not contact live applications, provider accounts, production, WordPress, or remediation systems.

## Prerequisites

- Python development dependencies from `requirements-dev.lock`
- Repository checked out on `codex/beta-03-scanning`
- No credentials or `.env` files required

## Run the focused scenarios

```bash
python -m pytest tests/unit/test_scanning.py tests/integration/test_scanning.py -q
```

Expected results include:

- vulnerable fixture → normalized finding with deterministic evidence and fingerprint
- duplicate fixture → one deduplicated finding with retained provenance
- false-positive fixture → suppressed finding with retained evidence and reason
- malformed and scanner-failure fixtures → scanner failure and zero findings
- out-of-scope fixture → fail-closed boundary result and no persisted evidence

## Run the full gates

```bash
python -m pytest -q
ruff format --check appcare scripts tests
ruff check appcare scripts tests
mypy appcare scripts tests
python scripts/check_public_safety.py
python scripts/verify_worker_policy.py
python scripts/check_build_lock.py
pip-audit --strict --requirement requirements-dev.lock
```

See [data-model.md](data-model.md) for entity invariants and [contracts/scanning.md](contracts/scanning.md) for the adapter and pipeline contract.
