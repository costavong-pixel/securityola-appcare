# BETA-04 Requirements Checklist

## Functional

- [x] Provider-neutral backup source and vault contracts exist.
- [x] Encrypted artifact and manifest checksums are verified on read-back.
- [x] B2 and Glacier destination descriptors are safe and immutable-retention aware.
- [x] Controlled test app restores into a fresh isolated destination.
- [x] Job history, failure state, retention, RPO, and RTO evidence are recorded.

## Safety

- [x] Raw credentials, keys, `.env`, customer data, WordPress, and production paths are excluded.
- [x] Failed backups are never reported healthy.
- [x] Partial restore cannot be promoted.
- [x] Locked backup deletion fails closed.

## Verification

- [x] Deterministic BETA-04 unit/integration/failure tests pass.
- [ ] Ruff, mypy, public-safety, worker-policy, build-lock, and dependency gates pass on the final committed head.
- [ ] Codex Security and independent Luna review pass on exact committed head.
- [ ] Exact-head GitHub CI passes before merge.
