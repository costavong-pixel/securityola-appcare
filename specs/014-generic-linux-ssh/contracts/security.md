# Spec 014 security and threat contract

## Threats

The target host controls DNS responses, SSH negotiation inputs after host-key
verification, filesystem contents, service metadata, filenames, output size,
encoding, timing, and disconnect behavior. Threats include MITM, host-key
replacement, DNS/IP substitution, credential theft, shell/argument injection,
symlink and TOCTOU escapes, output secret exfiltration, resource exhaustion,
malicious service/database metadata, tenant crossover, replay, unsafe sudo,
worker compromise, and fixture-to-live evidence confusion.

## Required controls

- pre-registered key fingerprint and strict host-key verification;
- no TOFU, no insecure host-key option, and no automatic retry on mismatch;
- opaque credential custody with tenant scope and lifecycle enforcement;
- static typed command registry and shell-free argv;
- strict input/path/service/database validators;
- allowlisted roots and exact metadata paths;
- bounded reads/output/records/timeouts;
- symlink and final-path revalidation;
- sanitized errors and secret-shaped output rejection;
- immutable scope-bound evidence and exact evidence class;
- replay/duplicate protection;
- no privilege escalation or arbitrary sudo;
- no worker/model authority over execution or readiness.

## Security gate mapping

- S04: credential reference, custody and rotation metadata.
- S05: SSH fingerprint, command registry, runner and identity binding.
- S06: approved roots, safe-file reads, symlink/TOCTOU checks.
- S11: no AI/model command control and fail-closed operation registry.
- S17: bounded operation IDs, replay handling and worker separation.
- S21: output sanitization and no raw secrets in evidence/logs.
- S23: timeout, byte, record and disconnect limits.

This mapping is contribution evidence only. It does not mark the complete
pre-beta security gate as passed.

