# Spec 014 implementation plan

## Scope

Implement a reusable, read-only Linux/SSH transport under the existing
AppCare connector and readiness boundaries. Preserve the existing fixture
connector API and add a clearly separate typed Linux target API. Do not alter
production APIs, databases, or external target infrastructure.

## Design slices

### Slice A: contracts and validation

Add immutable target, operation, command, result, credential-provider, and
inventory-record contracts. Reuse Spec 013 validators and evidence classes
where possible. Add strict validators for target identity, fingerprints,
approved roots, service/database identifiers, operation IDs, and safe
references.

### Slice B: trusted command registry

Create a closed operation-to-command registry. Commands are static templates
with individually validated trusted arguments. The registry does not expose a
free-form command method. Read-only capability classes are explicit; mutation
classes are denied.

### Slice C: execution boundary

Implement a shell-free local process runner for the OpenSSH client behind a
protocol so tests can inject a deterministic fake runner. Verify a registered
host key before connection, write a target-scoped known-hosts file only inside
the AppCare boundary, and invoke SSH with strict options, timeouts, identity
reference, and bounded output. Never emit private credential material.

### Slice D: typed inventory

Implement typed collectors for connection, host, web-server, runtime, service,
network, storage, file metadata, safe file reads, and application-root
verification. Each collector maps bounded remote output to a safe normalized
record. Partial/permission-denied observations remain explicit.

### Slice E: Spec 013 evidence adapter

Convert a successful typed connection/inventory result into exactly scoped
CapabilityEvidence for connect and inventory. Register it through
ApplicationCapabilityRegistry and evaluate it using the existing
SupportabilityEvaluator. Do not mark unsupported downstream capabilities as
passed.

### Slice F: lifecycle and security tests

Add positive, negative, failure, replay, tenant-isolation, secret-redaction,
output-limit, path/symlink, and command-registry tests. Use fake runner output
for deterministic tests; reserve live access for the one bounded acceptance
after all repository gates.

## Trust boundaries

1. AppCare coordinator and repository code are trusted implementation inputs.
2. Worker/model text is untrusted and cannot select commands.
3. Target metadata is untrusted until strict validation succeeds.
4. Credential references are opaque; only a protected provider boundary may
   resolve a secret for the SSH subprocess.
5. SSH host identity is trusted only after matching the pre-registered
   fingerprint.
6. All remote bytes and filenames are untrusted output.
7. Normalized evidence is trusted only after scope, provenance, sanitization,
   digest, and exact evidence-class validation.
8. Spec 013 remains the sole readiness/supportability authority.

## Data flow

validated LinuxTarget
→ CredentialProvider.resolve(reference)
→ pre-registered host-key verification
→ typed OperationRegistry
→ bounded SSH runner
→ sanitized observation
→ deterministic InventoryRecord
→ CapabilityEvidence
→ ApplicationCapabilityRegistry
→ SupportabilityEvaluator

No write, deployment, backup, database query, or production authorization is
present in this flow.

## Verification

- focused unit tests for each validator and operation builder;
- integration tests with an injected fake runner;
- negative tests for every listed adversarial condition;
- full tests, Ruff, mypy, dependency audit, secret scan;
- Graphify update and impact query;
- Codex Security diff scan over every changed source file;
- exact-head CI on the PR head;
- final Graphify and Saveruflo checkpoint (or explicit unavailable status).

## Rollback

The repository change is isolated to the Spec 014 branch and can be reverted
through the protected PR process. No live target is modified. No remote file,
database, service, or credential is changed by the connector.

