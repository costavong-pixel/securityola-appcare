# Spec 014: Generic Linux / SSH transport and inventory

## Status

Implemented on the dedicated codex/spec-014-generic-linux-ssh branch pending
protected-merge verification. This specification is subordinate to Spec 013
product-readiness governance and does not grant customer production authority.

## Goal

Provide AppCare's first reusable customer transport for a tenant- and
application-scoped Linux host over strict SSH. The slice establishes safe
CONNECT and INVENTORY evidence only. It must work for generic Linux
applications and must not contain assumptions for GreenCloud, a named pilot
site, WordPress, or any single hosting layout.

## Non-goals

- arbitrary shell execution or model-controlled commands;
- root-shell automation, unrestricted sudo, mutation, deployment, restart, or
  firewall changes;
- database queries, database backup, filesystem backup, scanning, staging,
  rollback, monitoring, or credential-secret retrieval;
- automatic trust-on-first-use, DNS-driven trust, or host-key bypasses;
- customer production onboarding;
- a second supportability or readiness truth system;
- copying private keys, passwords, tokens, or provider secrets into AppCare
  records, logs, evidence, tests, prompts, or Git.

## Requirements

### R01. Target identity and scope

The transport MUST require a validated LinuxTarget containing:

- tenant_id, application_id, and environment;
- the connection address and the application hostname identity;
- SSH port;
- a pre-registered expected host-key fingerprint;
- an opaque credential reference and non-root remote user;
- approved application roots;
- approved service names;
- approved database identifiers.

Every operation MUST bind to the target's tenant/application identity. A
target or credential from another tenant MUST fail before network execution.

### R02. Strict host identity

The transport MUST verify a pre-registered fingerprint before the first remote
command. Missing, malformed, mismatched, changed, or cross-target fingerprints
MUST fail closed. Customer mode MUST NOT use trust-on-first-use,
StrictHostKeyChecking=no, an empty known-hosts file, or a fallback key.
Known-hosts material MUST be AppCare-owned, target-scoped, and temporary or
durable only under an approved AppCare namespace.

Address, hostname, reverse identity, and expected application identity MUST be
bound consistently. A host substitution or identity mismatch MUST be reported
as a security failure.

### R03. Typed read-only operations

The public transport surface MUST expose typed operations:

ConnectionProbe, HostInventory, FilesystemMetadataRead, SafeFileRead,
ServiceMetadataRead, WebServerMetadataRead, RuntimeMetadataRead,
NetworkBindingRead, StorageMetadataRead, and ApplicationRootVerification.

There MUST be no public operation accepting a free-form command string,
run_shell, model output, arbitrary sudo target, arbitrary systemd unit, or
arbitrary remote path. Commands MUST be selected from a closed registry of
trusted templates and executed with shell=False/exec-style local argv.

### R04. Capability classes

Spec 014 MAY enable only the read-only classes required by CONNECT and
INVENTORY: INVENTORY_READ, FILESYSTEM_READ, and MONITORING_READ metadata
where the latter is needed only to observe a binding. The following remain
denied and unimplemented for this slice:

DATABASE_BACKUP, STAGING_CONTROL, DEPLOYMENT_CONTROL, PRODUCTION_WRITE, and
all mutation classes.

Capability statuses MUST be produced as follows:

- connect: SUPPORTED only after successful real connection evidence;
- inventory: SUPPORTED only after complete safe normalized inventory
  evidence;
- source_revision, filesystem_backup, database_backup, security_scan,
  staging, deploy, rollback, and monitoring: MISSING_CAPABILITY until their
  later specifications provide evidence.

The result MUST be fed to Spec 013's existing capability registry and
SupportabilityEvaluator; Spec 014 MUST NOT define another supportability
evaluator.

### R05. Credential boundary

Application records and evidence MUST contain only an opaque credential
reference and safe lifecycle metadata. A strict provider interface MAY resolve
the reference to private runtime material at the transport boundary, but the
material MUST never enter the database, logs, worker packets, model prompts,
test fixtures, reports, command arguments, or Git. Missing, expired, revoked,
wrong-tenant, and unsupported credential references MUST fail closed.

Spec 014 MUST support metadata transitions for register, active, expire,
revoke, and rotate-reference. It MUST not create plaintext credential files as
a shortcut.

### R06. Remote path safety

Filesystem operations MUST require an approved application root or one of a
small, explicit system metadata path allowlist. They MUST reject absolute
paths outside the allowlist, .., backslashes, control characters, shell
metacharacters, encoded traversal, symlink escape, unexpected file types, and
cross-tenant roots. Symlink resolution and final path verification MUST occur
under the approved root; a revalidation failure MUST fail closed.

The default system metadata allowlist is limited to safe metadata such as
/etc/os-release and /etc/hostname, plus explicitly configured read-only
web-server metadata files. Secret-bearing paths, including .env, private
keys, password files, /etc/shadow, arbitrary /root, arbitrary /home, and
arbitrary /var/lib, MUST be denied.

### R07. Safe file and output limits

Every operation MUST enforce connection and command timeouts, bounded stdout
and stderr bytes, bounded records, regular-file checks, binary
classification, and sanitized failure output. Malformed UTF-8, oversized
output, disconnects, and timeout failures MUST be explicit bounded failures;
they MUST NOT be converted to partial success without a visible reason.

### R08. Inventory coverage

Where permitted and available, normalized inventory MUST cover OS/version,
kernel metadata, hostname, application identity, web server/vhost metadata,
runtime versions, process manager, approved services, relevant listeners,
database type/identity metadata, root owner/group/modes, storage metadata,
Git presence/status, deployment layout, backup-directory metadata,
persistent/uploads/temp/cache directories, TLS certificate metadata, relevant
cron/systemd timer presence, and a discoverable health endpoint.

Unavailable non-critical observations MUST produce INVENTORY_PARTIAL or
PERMISSION_DENIED; they MUST not trigger privilege escalation.

### R09. Deterministic evidence

All observations MUST be converted to deterministic records containing tenant
binding, application binding, target binding, stable normalized identity,
sanitized source reference, timestamp, evidence digest, and evidence class
(REAL_TARGET for the live acceptance, FIXTURE only for test doubles).
Raw provider output MUST NOT be persisted as evidence.

### R10. Fail-closed lifecycle and replay behavior

Duplicate/replayed operation identifiers MUST not create a second authoritative
result. A revoked/expired credential, changed fingerprint, stale target
identity, mismatched target, or stale evidence MUST fail closed. A worker
claim, fixture boolean, or caller-provided status MUST never independently
authorize readiness.

### R11. Security-gate alignment

Implementation and tests MUST provide evidence toward S04 credential custody,
S05 SSH/remote execution, S06 filesystem/archive safety, S11 remediation
command safety, S17 scheduler/worker boundaries where applicable, S21
privacy/logging, and S23 resource/DoS controls. Spec 014 MUST NOT declare the
complete pre-beta security gate passed.

### R12. Coordinator approval

The Luna coordinator MUST inspect actual implementation/configuration and
positive and negative evidence for each P0 function F014-01 through F014-20.
Worker output or a passing fixture suite alone MUST never create a coordinator
approval. Any rejected or blocked function blocks live acceptance and
customer readiness.

## Acceptance scenarios

1. A valid target with a matching pre-registered key can run a bounded
   connection probe and inventory.
2. A missing, malformed, wrong, or changed host key fails before a remote
   command.
3. A target from tenant A cannot use tenant B's credential, root, key, or
   evidence.
4. No operation can accept or execute an arbitrary shell string.
5. Traversal, symlink escape, unsafe service/database identifiers, secret-shaped
   output, and oversized output are rejected or safely bounded.
6. Fixture evidence cannot be relabeled as REAL_TARGET.
7. A real read-only acceptance against the authorized internal target is
   attempted only when its trust anchor already exists; no file, database,
   service, DNS, firewall, SSL, or production mutation occurs.
8. Spec 013 evaluates CONNECT/INVENTORY evidence while downstream capabilities
   remain missing and STACK_GENERIC_LINUX_READY=NO.

## Explicit release outcome

This feature can be merged with no live-target receipt if the implementation
and repository gates pass, but the live connector remains unavailable until
the pre-registered trust anchor and authorized custody are present. It MUST
never set CUSTOMER_ONBOARDING_READY, PILOT_READY, PAID_SERVICE_READY, or
LIVE_CUSTOMER_PRODUCTION_ENABLED to true.

