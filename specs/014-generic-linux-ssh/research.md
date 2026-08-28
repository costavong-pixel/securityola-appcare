# Spec 014 research and decisions

## Existing repository evidence

- Spec 013 already defines EvidenceClass, CapabilityEvidence,
  ApplicationCapabilityRegistry, SupportabilityEvaluator, exact scope
  validation, coordinator binding, and fail-closed readiness.
- Existing connectors are fixed-request, read-only, fixture-backed adapters.
  Their UnavailableTransport default is intentional and must remain safe.
- Existing credential metadata is opaque and lifecycle-aware. Spec 014 must
  not make credential values part of that model.
- AppCare is a Python 3.12+ FastAPI/SQLAlchemy application with strict Ruff
  and mypy settings. The transport is library-neutral behind protocols so
  deterministic tests do not require a network or a customer key.
- The existing architecture explicitly forbids unrestricted model-controlled
  root SSH and separates AppCare from WordPress/plugin infrastructure.

## Decisions

### D1. OpenSSH subprocess boundary

Use a shell-free subprocess runner for the optional live adapter rather than
adding a new network library solely for this slice. The runner receives a
fully-built argv tuple from a closed operation registry. OpenSSH's strict host
verification is combined with an AppCare-owned known-hosts file populated only
after a pre-registered fingerprint match.

This keeps credential material outside Python records and avoids creating an
implicit arbitrary remote execution API. The subprocess implementation is
behind a protocol and is not used by unit tests.

### D2. Fingerprint verification

Accept canonical SHA256:<unpadded-base64> fingerprints. A host public key
obtained for verification is parsed locally and hashed from its wire-format
key blob. Verification requires exactly one supported key matching the
pre-registered fingerprint before the key can be used in a strict known-hosts
file. A mismatch is a security failure, not a retry condition.

### D3. Explicit path allowlists

Application roots are configured per target and validated as absolute,
normalized, root paths. System metadata paths are an explicit constant
allowlist. No caller can supply a free-form remote path to a collector.
Safe-file reads allow only a validated path beneath an approved root and
regular files below the byte cap.

### D4. Normalized records, not raw output

Remote output is parsed into small scalar records with stable field order.
Output, error, filenames, and provider messages are sanitized before they
become evidence. Raw stdout/stderr remains transient and is never included in
receipts.

### D5. Partial inventory is honest

The transport reports a complete SUPPORTED inventory only when required typed
observations are safe and present. Optional permissions or unsupported
metadata produce an explicit partial result. The connector never escalates
privileges to turn partial evidence into success.

### D6. Readiness integration

The adapter creates evidence only for connect and inventory, then delegates
supportability to Spec 013. The presence of a Linux target does not make
backup, deploy, rollback, or monitoring supported.

## Rejected alternatives

- Paramiko/AsyncSSH as a new hard dependency: unnecessary for the typed,
  protocol-driven slice and would expand dependency/security review.
- ssh-keyscan trust-on-first-use: rejected because a discovered key is not
  trusted until it matches the pre-registered fingerprint.
- shell=True, sh -c, bash -c, or concatenated model commands: rejected.
- automatic sudo: rejected; later privileged brokers need a separate spec.
- using the WordPress/plugin SSH key or service account: rejected by the
  shared-server boundary.

## Known live boundary

The internal pilot target video.slabfranchise.com at
64.44.115.21/slab-prompt-ola is read-only acceptance scope only. Before SSH,
its host-key fingerprint and credential reference must already be available
through authorized AppCare custody. If not, the implementation can still be
reviewed and merged, but live CONNECT/INVENTORY must remain NOT_RUN/blocked
rather than bypassing verification.

