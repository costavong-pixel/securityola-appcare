# Spec 015 security and threat contract

## Threats

The database source, transport path, broker environment, dump tools, restore
tools, and restore target can influence output bytes, timing, schema objects,
error strings, and mutable state. Threats include:

- plaintext credential leakage;
- cross-tenant or cross-application execution;
- arbitrary SQL or argv injection;
- shell wrapper escape;
- tool substitution or profile drift;
- oversized output, truncation, timeout, and disconnect behavior;
- manifest or checksum substitution;
- wrong-engine, wrong-database, or wrong-target restore;
- partial restore state reported as success;
- restart replay of mutable restore work;
- same-target concurrency races;
- fixture/reference evidence promoted to live evidence;
- worker self-approval or coordinator bypass;
- denial-of-service through large dumps or repeated retries.

## Required controls

- exact typed scope binding for target, transport identity, credential, and
  evidence;
- no-secret broker with opaque credential references only;
- closed command templates and no free-form SQL or shell execution;
- streamed SHA-256 plus hard byte caps for dump and verification output;
- deterministic manifest and receipt binding;
- isolated non-production restore targets only;
- explicit partial-restore cleanup or quarantine;
- durable idempotency and same-target single-flight rules;
- restart recovery-required state for interrupted mutable restore work;
- evidence-class integrity and coordinator-only authoritative approval;
- sanitized errors and rejection of secret-shaped output;
- explicit limitation codes for unsupported consistency guarantees.

## Security gate mapping

- S04: credential custody, rotation metadata, and no secret persistence.
- S05: transport-broker execution identity and closed remote execution boundary.
- S07: database safety, engine-family controls, no arbitrary SQL, and restore target validation.
- S08: manifest/checksum/readback integrity, wrong-app restore rejection, and duplicate handling.
- S09: isolated restore target, partial cleanup, post-restore verification, and no production overwrite.
- S17: restart durability, worker separation, idempotency, and concurrency control.
- S21: sanitized evidence, no secret-shaped output, and no credential leakage in diagnostics.
- S23: byte caps, timeout limits, cancellation handling, and retry/concurrency bounds.

This mapping contributes security evidence only. It does not mark the full
pre-beta security gate passed, and it does not authorize customer beta
readiness.
