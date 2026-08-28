# Spec 014 requirements checklist

## Scope and readiness

- [x] Generic Linux/SSH is reusable and not tied to a named host, provider, or WordPress.
- [x] Spec 013 remains the only capability/supportability/readiness authority.
- [x] Only CONNECT and INVENTORY can become supported from this slice.
- [x] Downstream capabilities remain missing until later specifications.
- [x] No readiness tier or global production flag is enabled by this feature.

## Identity and credentials

- [x] LinuxTarget binds tenant, application, environment, host, port, key fingerprint, credential reference, user, roots, services, and database IDs.
- [x] Remote user is non-root by default and root is rejected.
- [x] Credential material never enters DB, logs, evidence, prompts, tests, reports, Git, or command arguments.
- [x] Expired, revoked, missing, malformed, and cross-tenant credentials fail closed.
- [x] Rotation is opaque metadata only.

## SSH and command safety

- [x] Fingerprint is mandatory and pre-registered.
- [x] Host-key mismatch fails before remote command execution.
- [x] No TOFU or insecure strict-host-key fallback exists.
- [x] Known-hosts state is AppCare-owned and target-scoped.
- [x] Only typed operations from a closed registry are executable.
- [x] No arbitrary shell, sudo, systemd unit, path, redirect, pipe, glob, or model command exists.
- [x] All operations have bounded timeout, output, records, and sanitized errors.

## Filesystem and inventory

- [x] Paths stay under approved application roots or explicit metadata allowlists.
- [x] Traversal, absolute escape, encoded traversal, symlink escape, and race/revalidation failures are rejected.
- [x] Secret-bearing files and unsafe system paths are denied.
- [x] Inventory is normalized, deterministic, scoped, hashed, and sanitized.
- [x] Partial/permission-denied inventory is explicit and never auto-escalates.

## Spec 013 and testing

- [x] CapabilityEvidence is emitted only for CONNECT/INVENTORY.
- [x] Evidence class cannot be upgraded by caller input.
- [x] Fixture-only evidence cannot certify a real target.
- [x] Adversarial tests cover host key, credentials, tenant isolation, commands, paths, symlinks, output, timeout, malformed data, replay, and secret leakage.
- [ ] Live acceptance is read-only and requires an existing trust anchor.
- [x] Shared WordPress/plugin namespaces and customer production remain untouched.

