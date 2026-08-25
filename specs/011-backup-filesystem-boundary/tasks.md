# AppCare Backup Filesystem Boundary Tasks

- [x] Define canonical roots, path-segment validation, provider prefixes, and
  protected-source checks.
- [x] Create the dedicated non-login appcare-backup identity and required
  AppCare-only VPS directories.
- [x] Integrate filesystem vault snapshots/manifests with tenant/application
  scope and canonical paths.
- [x] Derive restore rehearsal roots from the canonical boundary.
- [x] Add traversal, symlink, protected-path, tenant-isolation, and production
  restore tests.
- [ ] Run final static, deterministic, security, Graphify, Saveruflo, and
  exact-head CI gates.
