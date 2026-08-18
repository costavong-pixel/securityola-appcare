# BETA-06 Quickstart

Run from the isolated AppCare checkout. These commands use synthetic fixtures
only and do not contact GitHub, Vercel, AWS, Backblaze, production, WordPress,
or the shared server.

## Prerequisites

```powershell
git status --short
git branch --show-current
git rev-parse HEAD
```

Expected branch: `codex/beta-06-remediation`. The checkout must be clean before
the bounded worker path is used.

## Deterministic validation

```powershell
pytest -q tests/unit/test_remediation.py tests/integration/test_remediation_boundaries.py
ruff format --check appcare/remediation tests/unit/test_remediation.py tests/integration/test_remediation_boundaries.py
ruff check appcare/remediation tests/unit/test_remediation.py tests/integration/test_remediation_boundaries.py
mypy appcare/remediation
python scripts/check_public_safety.py
```

The tests must prove that valid synthetic evidence produces one bounded patch,
while unsafe paths, secrets, symlinks, cross-tenant input, missing evidence,
scanner failures, failing gates, unapproved preview execution, and cross-tenant
approval are rejected.

## Full repository gates

```powershell
pytest -q
ruff format --check appcare scripts tests
ruff check appcare scripts tests
mypy appcare scripts tests
python scripts/check_public_safety.py
python scripts/verify_worker_policy.py
pip-audit --strict --requirement requirements-dev.lock
```

No command in this guide authorizes a live preview, production promotion, merge,
DNS change, SSH action, credential read, or WordPress access.
