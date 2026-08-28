# AppCare Mandatory Pre-Beta Security Gate

Status: **MANDATORY RELEASE BLOCKER**

Owner decision date: 2026-08-27

Target: `AppCare`

No `CUSTOMER_ONBOARDING_READY=YES`, `PILOT_READY=YES`, or external beta launch is permitted until this security gate is complete and the evidence is exact-head bound to the release candidate.

This review is broader than a repository vulnerability scan. It covers AppCare's own control plane, customer connectors, credentials, remote execution, backups, restore, scanners, staging, deployment, rollback, monitoring, scheduling, alerting, dashboards, customer auth, supply chain, operations, and real-target behavior.

## Required security evidence

Every final pre-beta security review must include all of the following:

1. exact protected-main release candidate SHA
2. full standard Codex Security repository scan
3. Codex Security diff scan for the final readiness/security PR range
4. `verify-fix` evidence for every security defect fixed during the gate where an original attack path exists
5. dependency vulnerability audit
6. secret/public-safety scan
7. Graphify blast-radius/security-impact review
8. Saveruflo sanitized checkpoint
9. exact-head GitHub CI
10. tenant-isolation adversarial tests
11. authorization/approval negative tests
12. customer connector adversarial tests
13. backup/restore adversarial tests
14. deployment/rollback adversarial tests
15. monitoring/scheduler adversarial tests
16. authentication/session tests
17. AppCare self-recovery evidence
18. real-target security acceptance evidence
19. published known limitations
20. coordinator sign-off on all P0 trust-boundary functions

Any missing, stale, mismatched, inconclusive, or failed mandatory security evidence blocks beta readiness.

## Security review principles

- fail closed on ambiguity
- least privilege per tenant/application/action
- no raw secrets in model context, logs, prompts, evidence, issues, reports, tests, or source
- no arbitrary model-controlled production shell
- no customer production write before backup + staging + validation + rollback + explicit authorization
- no cross-tenant read/write/evidence leakage
- no fixture/reference result may substitute for live target proof at the final real-target gate
- no security finding is waived merely to meet a launch date
- high-risk irreversible operations require explicit owner approval

## Gate S01 — Tenant and application isolation

Review and adversarially test:

- tenant ID binding on every resource
- application ID binding on every connector/job/evidence/deployment/backup/monitoring record
- cross-tenant API reads
- cross-tenant writes
- IDOR/BOLA attempts
- guessed object identifiers
- replay using another tenant's evidence reference
- cross-tenant backup lookup/restore
- cross-tenant deployment/rollback intent
- cross-tenant monitoring observations
- dashboard/API filtering
- operator-vs-customer role separation

Required result: `PASS` with explicit negative-test evidence.

## Gate S02 — Authentication and session security

Review:

- password/session/token handling
- token entropy and expiration
- session revocation
- logout invalidation
- account recovery
- brute-force/rate limits
- MFA for privileged operations where required
- CSRF where cookie/session authentication applies
- secure cookie attributes where applicable
- login error oracles
- session fixation
- privilege escalation
- operator impersonation controls
- production approver identity binding

Beta cannot rely solely on development-only auth assumptions.

## Gate S03 — Authorization and production approval

Adversarially test that no path can bypass:

- tenant/application scope
- authoritative backup evidence
- authoritative preproduction evidence
- exact source revision
- exact artifact digest
- production approver identity
- approval expiration/revocation
- emergency stop
- credential revocation
- idempotency/duplicate protection

Test bypass attempts through:

- direct API calls
- stale approvals
- mismatched application
- mismatched revision
- mismatched artifact
- replayed approval
- worker/model output
- hidden configuration
- emergency/recovery endpoints
- restart recovery

Required result: no bypass path.

## Gate S04 — Customer credential custody

Review the complete credential lifecycle:

- creation/import
- storage encryption
- tenant/application binding
- least-privilege scope
- runtime retrieval
- process exposure
- model isolation
- logs/evidence redaction
- rotation
- revocation
- expiration
- operator visibility
- backup of credential metadata vs credential values
- disaster recovery
- offboarding/deletion

Raw SSH keys, passwords, tokens, DB passwords, API keys, signing secrets, and provider credentials must never be visible to models or persisted in sanitized evidence.

## Gate S05 — SSH and remote execution

Before any customer Linux/SSH stack is supported, test:

- strict SSH host-key verification
- host-key mismatch rejection
- DNS/IP substitution
- username/app binding
- credential revocation
- command allowlist
- trusted argument construction
- rejection of shell metacharacters
- rejection of arbitrary `sh -c`/`bash -c`
- no model-generated arbitrary shell
- no arbitrary sudo
- no unsafe environment-variable expansion
- timeouts
- output caps
- binary/encoding handling
- connection interruption
- replay/duplicate execution
- privilege boundaries
- safe file transfer
- path traversal
- symlink traversal

Treat customer-controlled filenames, paths, configuration, command output, and service metadata as hostile input.

## Gate S06 — Filesystem and archive safety

Test:

- absolute path rejection
- `..` traversal
- symlink/hardlink escape
- race conditions around path validation where relevant
- special devices/FIFOs/sockets
- ownership/permission preservation
- world-writable content handling
- huge files
- sparse files
- archive bombs
- zip/tar traversal
- duplicate filenames
- Unicode/confusable paths
- case sensitivity collisions
- secret-containing files
- prohibited path boundaries
- cleanup of partial staging/restore trees

No backup, restore, remediation, or deployment operation may escape its exact tenant/application root.

## Gate S07 — Database safety

Review MariaDB/MySQL/PostgreSQL/Supabase paths for:

- credential-safe invocation
- no password in argv/process list/logs
- least-privilege DB role
- dump consistency
- partial dump detection
- dump corruption
- dangerous restore target selection
- SQL injection through identifiers/arguments
- cross-tenant DB selection
- migration identity
- migration replay
- schema drift
- irreversible migrations
- rollback/data-loss risk
- post-restore integrity queries
- customer transaction preservation

Automatic DB rollback must fail closed if it could destroy valid post-deployment transactions.

## Gate S08 — Backup confidentiality, integrity, and immutability

Review:

- source capture integrity
- manifest integrity
- component checksums
- authenticated encryption
- encryption key separation
- B2 tenant/application namespace
- Object Lock/retention evidence
- remote readback
- remote checksum verification
- duplicate/idempotency handling
- stale backup detection
- partial upload
- provider interruption
- object substitution
- wrong-tenant lookup
- wrong-app restore
- expired/revoked credential
- retention deletion denial
- Glacier lifecycle/archive metadata
- local backup boundary permissions

A listed object is not a healthy backup until readback/integrity and isolated restore evidence exist.

## Gate S09 — Restore and recovery safety

Test:

- restore only into isolated approved targets during rehearsal
- manifest/component identity
- archive/path traversal
- symlinks
- partial restore cleanup
- wrong tenant/app backup
- wrong encryption key
- corruption
- restore interruption
- permission reconstruction
- DB reconstruction
- configuration isolation
- staging promotion atomics
- production recovery authorization
- post-restore verification

No rehearsal may overwrite customer production.

## Gate S10 — Scanner execution security

Treat scanners as untrusted tools/processes. Review:

- scanner binary provenance/version pinning
- sandbox boundaries
- resource limits
- timeouts
- output limits
- malformed output
- hostile filenames/source
- secret redaction
- scanner command injection
- network access
- dependency installer side effects
- false-positive suppression authorization
- scanner failure vs finding separation
- tenant/target binding

Raw scanner output must never bypass the normalized sanitization/evidence pipeline.

## Gate S11 — Remediation and AI/agent safety

Review:

- finding-to-remediation evidence binding
- workspace tenant/app/job scope
- patch path restrictions
- preimage verification
- unrelated-change rejection
- secret-bearing patch rejection
- delete/rename/broad-change policy
- generated dependency changes
- malicious repository instructions/prompt injection
- model attempts to escape task scope
- worker sandbox
- worker network access
- worker credential access
- self-approval prevention
- coordinator review of actual diff

AI/model output is advisory until deterministic validation and independent review pass.

## Gate S12 — Supply-chain and dependency security

Review:

- Python dependency lock integrity
- direct/transitive vulnerabilities
- pinned versions
- malicious/abandoned dependencies
- build tooling
- GitHub Actions pins/permissions
- third-party skills
- scanner binaries
- CLI utilities used by adapters
- container/base images where applicable
- package-install scripts
- dependency confusion
- typosquatting

Apply the repository rule: `discover -> inspect -> sandbox -> pressure-test -> patch/debug -> retest -> pin -> use`.

## Gate S13 — Staging isolation

Verify staging cannot affect production through:

- shared DB
- shared writable files/uploads
- production email
- production payment providers
- production webhooks
- cron/scheduled jobs
- destructive callbacks
- shared queues
- shared caches
- production tokens
- production object storage writes
- production domain/session cookies

Staging secrets and data must be separately scoped or safely sanitized.

## Gate S14 — Deployment security

Review:

- exact artifact/source binding
- artifact integrity
- deployment target validation
- tenant/app binding
- atomic release strategy
- symlink safety
- service identity
- service restart command construction
- partial deployment handling
- duplicate execution
- concurrency/races
- stale approval
- stale backup
- stale preproduction receipt
- credential revocation during deploy
- emergency stop during deploy
- post-deploy verification

No direct production mutation is allowed from an unversioned/unverified workspace.

## Gate S15 — Rollback and data-loss security

Review:

- exact rollback reference
- rollback artifact integrity
- file/config rollback
- DB rollback classification
- transaction/data-loss detection
- verification after rollback
- rollback failure escalation
- repeat rollback/idempotency
- concurrent deployment/rollback exclusion
- operator emergency stop

Rollback logic must prefer safety over automatic destructive recovery.

## Gate S16 — Monitoring collector security

Monitoring introduces network and target access. Test:

- SSRF through customer URLs
- DNS rebinding
- link-local/private-network access policy
- redirect handling
- credential leakage in probes
- HTTP header injection
- response size limits
- timeouts
- TLS validation
- sensitive body logging
- monitor target ownership
- cross-tenant observations
- malicious response parsing
- alert flooding

Public URL monitoring must not become a general-purpose internal network scanner.

## Gate S17 — Scheduler and worker security

Review:

- durable ownership/lease
- duplicate job prevention
- replay after restart
- missed-run handling
- tenant quotas
- starvation
- alert/backup amplification
- job spoofing
- unauthorized schedule creation
- schedule modification audit
- disabled tenant execution
- offboarded customer execution
- credential revocation propagation
- emergency stop propagation

No duplicate production mutation may result from worker failover or restart.

## Gate S18 — Alert delivery security

Review:

- tenant-specific destinations
- email/header injection
- webhook SSRF if webhooks are added
- secrets in notification bodies
- excessive sensitive evidence
- rate limiting
- alert storms
- spoofed resolution/acknowledgement
- delivery failure handling

## Gate S19 — Dashboard and API security

Review both customer and operator surfaces for:

- authentication
- authorization/IDOR
- XSS
- CSRF where relevant
- CSP
- clickjacking
- CORS
- secure headers
- rate limiting
- request body limits
- file upload boundaries
- cache control
- sensitive browser storage
- error sanitization
- pagination abuse
- export/report authorization
- operator-only actions

Operator and customer capabilities must be explicitly separated.

## Gate S20 — Public edge and TLS

Before public customer beta exposure verify:

- DNS correctness
- TLS chain/expiry/renewal
- HTTPS-only behavior
- HSTS decision
- reverse proxy configuration
- trusted host handling
- forwarded header trust
- rate limiting
- body/header limits
- security headers
- CSP
- request smuggling/desync considerations
- log sanitization
- health/readiness exposure
- admin/debug endpoint exposure

DNS changes remain owner-authorized.

## Gate S21 — Logging, evidence, privacy, and PII

Review:

- secret redaction
- customer-data minimization
- path/hostname disclosure policy
- error sanitization
- audit immutability
- evidence retention
- backup retention
- report sanitization
- deletion/export/offboarding policy
- log permissions
- log rotation
- prompt/worker-packet contents
- public GitHub issue/CI artifact exposure

Customer content and private infrastructure details must not leak through public source or CI.

## Gate S22 — AppCare infrastructure isolation

Re-verify AppCare separation from the SecurityOla WordPress product:

- application paths
- service users
- databases/schemas
- queues/workers
- secrets
- logs
- backup namespaces
- provider credentials
- writable volumes
- production routes

Also verify dev/staging/prod isolation inside AppCare.

## Gate S23 — AppCare self-protection and disaster recovery

Before paid beta, prove AppCare can recover itself:

- control-plane DB backup/restore
- monitoring/deployment evidence recovery
- configuration recovery
- credential-custody recovery process
- scheduler restart
- worker restart
- backup-provider outage handling
- disk/capacity alerts
- service monitoring
- operator emergency access procedure

Do not sell recovery without a tested recovery procedure for AppCare's own control plane.

## Gate S24 — Denial of service and resource controls

Test/define limits for:

- API request rates
- scan concurrency
- SSH concurrency
- database backup concurrency
- backup size
- restore size
- file count
- scanner CPU/memory/time
- worker concurrency
- scheduler queues
- monitoring frequency
- report generation
- model usage/cost
- tenant quotas

A single customer/target must not exhaust shared AppCare capacity.

## Gate S25 — Business logic and billing boundaries

Before paid service, review:

- plan entitlement
- suspended/cancelled accounts
- service after failed payment
- emergency recovery authorization
- production actions after cancellation
- backup retention after cancellation
- customer offboarding
- cost abuse

Billing state must not create unsafe partial service states.

## Gate S26 — WordPress profile security

Before `STACK_WORDPRESS_READY=YES`, additionally review:

- wp-config secret handling
- core checksum verification
- plugin/theme provenance
- WP-CLI invocation
- upload directories
- plugin/theme arbitrary code
- unsafe writable PHP
- wp-admin/wp-login/wp-json exposure
- multisite if supported
- staging email/cron isolation
- DB prefix/tenant assumptions

This is AppCare-managed customer WordPress support, not the separate SecurityOla WordPress security plugin product.

## Gate S27 — WooCommerce transaction safety

Before `STACK_WOOCOMMERCE_READY=YES`, additionally review:

- customer/order data handling
- checkout critical flow
- payment gateway credentials
- sandbox/test payments only in staging
- no real fulfilment during staging/tests
- no real customer email
- scheduled actions
- webhooks
- inventory/order concurrency
- DB rollback after new orders
- privacy/PII

Automatic DB rollback is prohibited when it could erase valid post-deployment orders without an explicit recovery decision.

## Gate S28 — GitHub/Vercel/Supabase provider security

Before the initial modern stack is considered ready, review real provider adapters for:

- OAuth/token scope
- ownership validation
- tenant binding
- token rotation/revocation
- webhook verification where used
- GitHub PR/merge authority boundaries
- Vercel deployment scope/alias safety
- Supabase DB/storage/auth boundaries
- provider API rate limits
- provider outage behavior

A provider contract without live transport is not support.

## Gate S29 — Real-target adversarial acceptance

The real pilot must validate the actual attack surfaces introduced by live customer integration. At minimum exercise safely:

- wrong host key
- wrong tenant/app identifier
- path traversal
- symlink escape
- secret-shaped files
- failed/partial DB dump
- remote backup interruption
- corrupt backup
- restore mismatch
- scanner timeout/malformed output
- stale approval
- wrong artifact
- duplicate deployment request
- failed health verification
- safe rollback path
- monitoring timeout/oversized response
- scheduler duplicate suppression
- AppCare restart during non-mutating/in-flight-safe stages

Do not intentionally damage production to prove an adversarial condition. Use fixtures/staging for destructive cases and the real target for safe live-boundary proof.

## Gate S30 — Final release decision

The final coordinator report must record:

```text
RELEASE_CANDIDATE_SHA=
CODEX_SECURITY_FULL_SCAN=
CODEX_SECURITY_DIFF_SCAN=
SECURITY_FINDINGS_OPEN=
DEPENDENCY_AUDIT=
SECRET_SCAN=
TENANT_ISOLATION=
AUTH_SECURITY=
AUTHORIZATION_GATES=
CREDENTIAL_CUSTODY=
SSH_SECURITY=
FILESYSTEM_SECURITY=
DATABASE_SECURITY=
BACKUP_SECURITY=
RESTORE_SECURITY=
SCANNER_SECURITY=
REMEDIATION_SECURITY=
SUPPLY_CHAIN_SECURITY=
STAGING_ISOLATION=
DEPLOYMENT_SECURITY=
ROLLBACK_SECURITY=
MONITORING_SECURITY=
SCHEDULER_SECURITY=
DASHBOARD_API_SECURITY=
PUBLIC_EDGE_SECURITY=
PRIVACY_LOGGING=
APPCARE_ISOLATION=
APPCARE_DR=
DOS_RESOURCE_CONTROLS=
REAL_TARGET_SECURITY=
KNOWN_LIMITATIONS=
GRAPHIFY=
SAVERUFLO=
EXACT_HEAD_CI=
LUNA_COORDINATOR_SECURITY_DECISION=
```

Required coordinator decision values:

- `APPROVE_FOR_CONTROLLED_PRIVATE_BETA`
- `REJECT`
- `BLOCKED`

Only `APPROVE_FOR_CONTROLLED_PRIVATE_BETA` with every mandatory gate passing permits customer beta readiness to advance.

`LIVE_CUSTOMER_PRODUCTION_ENABLED` remains `NO` globally; production access is granted only through exact tenant/application/action authorization.
