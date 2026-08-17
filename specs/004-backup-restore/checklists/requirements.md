# BETA-04 Requirements Checklist

## Functional

- [ ] Provider-neutral backup source and vault contracts exist.
- [ ] Encrypted artifact and manifest checksums are verified on read-back.
- [ ] B2 and Glacier destination descriptors are safe and immutable-retention aware.
- [ ] Controlled test app restores into a fresh isolated destination.
- [ ] Job history, failure state, retention, RPO, and RTO evidence are recorded.

## Safety

- [ ] Raw credentials, keys, `.env`, customer data, WordPress, and production paths are excluded.
- [ ] Failed backups are never reported healthy.
- [ ] Partial restore cannot be promoted.
- [ ] Locked backup deletion fails closed.

## Verification

- [ ] Deterministic unit/integration/failure tests pass.
- [ ] Ruff, mypy, public-safety, worker-policy, build-lock, and dependency gates pass.
- [ ] Codex Security and independent Luna review pass on exact committed head.
- [ ] Exact-head GitHub CI passes before merge.
