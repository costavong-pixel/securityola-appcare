# Spec 014 quickstart

This quickstart describes the safe API shape. It is not a production
deployment instruction and does not provide a credential.

## 1. Register a target

Construct LinuxTarget with a tenant/application scope, an approved non-root
user, exact approved roots, exact service/database metadata identifiers, an
opaque credential reference, and a pre-registered
SHA256:<fingerprint>. Reject the target if any value is not normalized.

Do not infer the fingerprint from the first connection. Do not pass a private
key or password to the application model.

## 2. Run typed inventory

Create a typed client with:

- the target;
- an injected or protected CredentialProvider;
- the closed OperationRegistry;
- bounded runner configuration;
- an AppCare-owned known-hosts location.

Call connect() and inventory() only. There is no free-form command method.
The result contains normalized records and safe status codes.

## 3. Evaluate through Spec 013

Convert successful results to scoped CapabilityEvidence for connect and
inventory, add them to ApplicationCapabilityRegistry, and call the existing
SupportabilityEvaluator. Inspect its missing capability results. Do not mark a
target supported by asserting a boolean.

## 4. Negative behavior

The following must fail without remote mutation:

- fingerprint omitted or changed;
- revoked/expired/cross-tenant credential reference;
- unapproved root, path traversal, symlink escape, or secret path;
- unknown service/database identifier;
- command injection characters;
- oversized output or timeout;
- fixture relabeled as live evidence.

## 5. Live acceptance

Only after implementation/security/CI gates pass, the coordinator may perform
one bounded read-only acceptance against an already-authorized internal
target. If the fingerprint is not already present in safe custody, stop before
SSH and report the missing trust anchor. Never disable host-key checks to make
the acceptance run.

