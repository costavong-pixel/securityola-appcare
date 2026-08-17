# BETA-02 Quickstart

Run from the isolated AppCare checkout as `appcare-ai` or another non-production AppCare development identity. Do not provide real provider credentials and do not run this against a customer account.

## Focused verification

```bash
python -m pytest -q tests/unit/test_connectors.py \
  tests/integration/test_read_only_connectors.py \
  tests/integration/test_asset_inventory.py
```

The fixtures use opaque references such as `credential-ref-fixture-01`; they do not contain tokens or keys.

## Required scenarios

1. GitHub, Vercel, and Supabase complete read-only capability sets report healthy.
2. A write-shaped, missing, expired, revoked, or malformed capability set reports unusable without exposing the reference.
3. Matching resource/domain ownership produces inventory; a mismatch persists nothing.
4. Replaying the same reordered snapshot produces the same digest and stable local AppCare asset IDs.
5. Inventory output and connector diagnostics contain no credential-like strings.
6. The connector module exposes health, inventory, and ownership operations only; no provider mutation/deployment/database-write operation is present.

## Full BETA-02 gate

```bash
python -m pytest -q
ruff format --check appcare scripts tests
ruff check appcare scripts tests
mypy appcare scripts tests
python scripts/check_public_safety.py
python scripts/verify_worker_policy.py
python scripts/check_build_lock.py
pip-audit --strict --requirement requirements-dev.lock
git diff --check
```

No command in this quickstart authorizes OAuth, connects to GitHub/Vercel/Supabase, deploys, writes a provider database, changes DNS, or touches WordPress Security.
