# SecurityOla WordPress Security Review Backlog

**TARGET=WordPress Security**

Purpose: maintain the security-assurance work that remains separate from Paddle/commercial approval.

This document is intentionally public-safe. Do not add credentials, production access instructions, IP addresses, private infrastructure paths, customer vulnerability evidence, exploit payloads against live systems, or private Paddle/account information.

## Status legend

- `PASS` — deterministic evidence exists for the stated boundary.
- `PARTIAL` — some evidence exists, but the complete boundary is not yet proven.
- `UNREVIEWED` — no current evidence sufficient for sign-off.
- `BLOCKED` — external/owner-controlled requirement prevents completion.

A PASS applies only to the exact boundary tested. It is never a claim that the whole product is secure.

## Current known evidence — 2026-08-27

| Area | Status | Evidence / note |
|---|---|---|
| Public TLS | PASS | Deployment validation reported TLS pass for public SecurityOla surfaces. |
| Public secret scan | PASS | Deployment validation reported no public secret exposure. |
| Public responsive/viewport check | PASS | Deployment validation reported responsive static check pass. |
| Production API health | PASS | `api.securityola.com/v1/health` returned HTTP 200 during deployment validation. |
| Marketing-site patch isolation from API | PASS for last deployment | Deployment report recorded API unchanged. Must be re-verified after every public-site change. |
| Paddle sandbox checkout | PASS for existing flow | Existing sandbox checkout was reported valid. This does not prove live-domain approval or all payment-security controls. |
| Paddle Live domain approval | BLOCKED | `action_required`; commercial/compliance track, not a security sign-off. |
| Payment integration security review | UNREVIEWED | Requires dedicated review below. |
| WordPress plugin/update trust review | UNREVIEWED | Requires dedicated review below. |
| End-to-end tenant/site authorization | UNREVIEWED | Requires dedicated review below. |
| Remediation safety | UNREVIEWED | Requires dedicated review below. |
| Backup/recovery security | UNREVIEWED | Requires dedicated review below. |
| Supply-chain security | UNREVIEWED | Requires dedicated review below. |

## P0 — required before live payment/production expansion

### P0.1 Paddle checkout trust boundary

Review and prove:

- Paddle API secret never appears in browser-delivered code, logs, HTML, JavaScript bundles or public configuration.
- Browser uses only Paddle-supported public/client-side tokens/configuration.
- Product/price/entitlement mapping cannot be altered by trusting a client-supplied price, quantity, plan or entitlement field without server-side verification.
- A customer cannot buy a cheaper product/price and receive a more valuable SecurityOla entitlement through parameter tampering.
- `_ptxn` and all checkout query parameters are treated as untrusted input.
- `_ptxn` cannot produce open redirect, DOM injection, script injection, unsafe URL navigation or unintended checkout state.
- Live checkout cannot launch from an unapproved domain.
- Sandbox and production environments are separated and cannot be confused by a client-controlled flag.
- Refund/cancellation events cannot grant or preserve entitlements incorrectly.
- Duplicate/replayed payment events are idempotent.

Required evidence:

- architecture/data-flow diagram;
- client/server config inventory;
- negative tests for tampered product/price/entitlement inputs;
- sandbox replay/idempotency tests;
- public-secret scan;
- exact production configuration review without committing secrets.

### P0.2 Paddle webhook security

Review and prove:

- webhook signature verification follows Paddle's current documented scheme;
- verification uses the exact raw body required by the signature algorithm;
- timestamp/age validation prevents stale replay where supported;
- duplicate webhook delivery is idempotent;
- event ordering does not incorrectly re-enable revoked/refunded access;
- unknown event types fail safely;
- malformed payloads do not leak secrets or stack traces;
- webhook endpoint is rate-limited/abuse-resistant without blocking legitimate Paddle retries;
- webhook secrets have defined rotation/revocation procedures;
- logs redact sensitive buyer/payment data not needed for operations.

### P0.3 Public checkout/browser security headers

Review:

- Content-Security-Policy permits only required origins and remains compatible with Paddle.js;
- no unsafe wildcard expansions are added merely to make checkout work;
- HSTS is appropriate and consistently deployed;
- frame/embedding policy is compatible with Paddle while preventing unwanted framing elsewhere;
- Referrer-Policy is appropriate;
- Permissions-Policy is appropriately restrictive;
- MIME sniffing is disabled where applicable;
- cookies use Secure/HttpOnly/SameSite according to purpose;
- CORS uses explicit required origins and methods, not broad `*` with credentials;
- error pages do not disclose environment/configuration details.

Historical note: a previous public-site visual failure was caused by CSP omitting `style-src 'self'`. Future CSP hardening must therefore include browser validation, not only static header inspection.

### P0.4 API authentication and authorization

Review the WordPress Security API independently from AppCare.

Prove:

- application/runtime identity is isolated from AppCare even if both share physical infrastructure;
- authentication fails closed;
- every customer/site request is tenant/site scoped;
- no insecure direct object reference allows cross-customer reads or writes;
- site registration/ownership verification cannot be bypassed by changing identifiers;
- license entitlement is checked server-side;
- revoked/expired licenses cannot continue privileged operations;
- API keys/tokens have purpose, scope, expiry/rotation/revocation rules;
- rate limits and abuse controls exist for authentication, scanning, update and expensive operations;
- errors do not echo secrets or sensitive submitted values.

### P0.5 One-installation / one-site credential binding

This is a specifically important SecurityOla requirement.

Review and prove:

- a credential issued to installation/site A cannot be copied to installation/site B and remain valid as an equivalent identity;
- credentials are bound to the intended tenant/site/installation using a cryptographically sound mechanism;
- credential rotation invalidates old material according to policy;
- revocation is effective promptly;
- replay is prevented for signed requests where applicable;
- server validates tenant/site identity independently of client claims;
- cloning a WordPress filesystem/database does not silently clone an indefinitely valid privileged identity.

If an Ed25519 or other per-installation signing design is used, review key generation, storage, server registration, rotation, revocation, replay defense and recovery as one complete protocol rather than isolated functions.

### P0.6 Private update trust

Review and prove:

- update packages are authenticated before installation;
- package hash/signature covers the exact bytes installed;
- update metadata cannot redirect customers to an attacker-controlled package URL;
- rollback/downgrade rules are explicit;
- compromised CDN/object storage alone cannot silently publish trusted code if signing is intended to be the root of trust;
- signing keys are separated from ordinary web runtime credentials;
- key rotation/revocation/recovery is documented and tested;
- update checks do not leak license secrets in URLs/referrers/logs.

### P0.7 File/scanner safety boundary

Review all paths that inspect WordPress files, uploads, archives, database content or suspicious code.

Test for:

- path traversal;
- symlink escape;
- ZIP/tar traversal if archives are inspected;
- decompression bombs/resource exhaustion;
- regex/analysis denial of service;
- unsafe deserialization;
- command/shell injection;
- PHP/template evaluation during scanning;
- SSRF through URLs discovered in WordPress content/configuration;
- arbitrary file read outside the authorized WordPress root;
- arbitrary file write/delete outside approved remediation scope;
- unsafe temporary-file permissions;
- TOCTOU problems between scan, approval and remediation;
- cross-tenant scan result leakage.

Scanner output is evidence/findings, not automatic proof that a file is malicious.

### P0.8 Remediation/write safety

Before any automated or assisted production repair:

1. preserve evidence;
2. create a valid backup/snapshot;
3. reproduce/test in staging or isolation where feasible;
4. show the proposed change/diff;
5. require the correct approval boundary;
6. apply the minimum change;
7. verify production outcome;
8. roll back automatically/manual-fast if verification fails;
9. append an audit record.

Prove that scan findings alone cannot silently trigger destructive production changes.

## P1 — required before wider public scale

### P1.1 Backup/recovery security

Review:

- tenant-isolated backup namespaces;
- encryption at rest and in transit;
- backup credential scope;
- restore authorization stronger than ordinary read access where appropriate;
- archive traversal and overwrite safety;
- restore target verification;
- ransomware/attacker resistance, including whether compromise of the application runtime can also destroy all backups;
- retention/deletion policy;
- restore drills with evidence;
- secret redaction from exported diagnostic bundles where applicable.

### P1.2 Database and WordPress-content handling

Review:

- SQL injection across all custom queries;
- safe parameter binding;
- bounded handling of very large options/posts/logs;
- serialized WordPress data handling without unsafe object instantiation;
- secrets accidentally captured in scan/report output;
- PII minimization;
- cross-tenant report isolation;
- retention/deletion controls.

### P1.3 WordPress privilege and CSRF/XSS review

Review plugin/admin surfaces for:

- capability checks on every privileged action;
- nonce/CSRF protection;
- stored/reflected/DOM XSS;
- output escaping by context;
- unsafe HTML in scan findings/logs;
- authenticated privilege escalation;
- REST route permission callbacks;
- AJAX action authorization;
- settings sanitization/validation;
- file upload restrictions;
- multisite/network-admin boundaries if supported.

### P1.4 License and entitlement lifecycle

Review:

- activation limit enforcement;
- concurrent activation races;
- deactivation/revocation correctness;
- refund/chargeback effect on access;
- failed renewal grace-period rules if subscriptions exist;
- offline/cache behavior and maximum stale entitlement lifetime;
- clock-skew/time validation;
- customer transfer/migration process;
- abuse controls for repeated activation attempts.

### P1.5 Observability without data leakage

Define:

- security event taxonomy;
- minimum necessary production logs;
- secret/PII redaction rules;
- tenant identifiers safe for operations;
- alert thresholds for auth abuse, webhook failures, update verification failures, scan failure spikes and remediation rollback;
- log retention and access controls;
- immutable/high-integrity audit trail for critical actions where feasible.

### P1.6 Privacy/data governance

Document:

- what data leaves the customer's WordPress site;
- what remains local;
- whether file contents/snippets are transmitted;
- whether database/post content is transmitted;
- retention duration;
- subprocessors/providers;
- deletion/export process;
- whether any data is used for model training;
- consent/legal basis where applicable;
- support-report data minimization.

Public privacy statements must match actual telemetry/data flow.

## P2 — resilience and mature operations

### P2.1 Supply-chain security

Maintain:

- locked/pinned dependencies where appropriate;
- dependency vulnerability monitoring;
- SBOM or equivalent inventory;
- provenance for build/release artifacts;
- protected release process;
- code-review requirement for sensitive changes;
- third-party skill/tool inspection before trust;
- separation between developer automation credentials and production release credentials.

### P2.2 Secrets and key lifecycle

Inventory every secret/key class without committing values:

- Paddle webhook secret;
- Paddle server API credentials;
- public Paddle client token/config;
- update-signing keys;
- per-installation/site keys;
- database credentials;
- mail/provider credentials;
- backup credentials;
- deployment credentials.

For each define owner, location class, scope, rotation, revocation, backup/recovery, auditability and blast radius.

### P2.3 Incident response

Create playbooks for at least:

- leaked payment/webhook credential;
- leaked API credential;
- compromised update-signing key;
- malicious/incorrect plugin update;
- cross-tenant authorization defect;
- destructive remediation bug;
- backup failure;
- suspected customer-site compromise;
- Paddle webhook outage;
- public-site/checkout outage.

Playbooks must identify containment, evidence preservation, customer impact assessment, rotation/revocation, rollback/recovery, notification decision and post-incident review.

### P2.4 Disaster recovery and availability

Define and test:

- RPO/RTO by component;
- API recovery;
- database recovery;
- update service recovery;
- checkout/public-site recovery;
- backup-system recovery;
- DNS/TLS recovery;
- dependency/provider outage behavior;
- degraded-mode behavior that fails safe for security-sensitive operations.

## Payment/compliance track is separate

The Paddle approval record is:

`docs/compliance/PADDLE-APPROVAL-2026-08-27.md`

Passing Paddle review must never automatically change any item in this file to PASS.

Likewise, a security PASS does not imply Paddle/commercial approval.

## Required evidence format for each review item

When closing an item, record:

- date;
- exact component/version/commit deployed or tested;
- scope/boundary;
- deterministic test commands or test case IDs;
- negative/adversarial tests;
- result;
- known residual risk;
- reviewer/approval gate;
- whether production changed;
- rollback status if production changed.

Do not paste secrets, customer data, exploit payloads against live systems, or production access details into this public file.

## Next recommended review order

1. Paddle checkout/webhook trust boundary.
2. One-installation / one-site credential binding and replay defense.
3. Private update signing/distribution trust.
4. API tenant/site authorization and entitlement checks.
5. Scanner filesystem/parser boundary.
6. Remediation + backup/rollback boundary.
7. WordPress admin/REST CSRF/XSS/capability review.
8. Privacy/telemetry verification.
9. Supply chain and incident response.

This order prioritizes paths that can create unauthorized paid access, cross-customer access, trusted-code compromise, arbitrary server/file operations, or irreversible production changes.
