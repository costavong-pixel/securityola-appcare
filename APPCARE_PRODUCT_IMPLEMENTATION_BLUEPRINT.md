# AppCare Product Implementation Blueprint

Status: **MANDATORY CURRENT-SCOPE IMPLEMENTATION GOVERNANCE**

Owner decision date: 2026-08-29  
Target: `AppCare`  
First supported beta profile: Linux-hosted PHP 8.x applications using Nginx or Apache and MariaDB/MySQL  
First real acceptance target: `video.slabfranchise.com`

This blueprint is the binding dependency plan for turning the existing AppCare core platform into a real managed website-care service. It controls current-branch implementation sequencing, component maturity reporting, phase exit gates, model responsibilities, and readiness promotion.

Where an older roadmap conflicts with this blueprint, this blueprint governs the current implementation branch. The A-Z gap register remains the broad backlog. WordPress and WooCommerce remain documented future branches and are not part of the current critical path.

---

## 1. Product contract

AppCare must deliver the managed lifecycle:

```text
SCAN
→ FIX
→ BACKUP
→ MONITOR
→ RECOVER
```

For the first supported profile, the service must operationally provide:

```text
CONNECT
→ INVENTORY
→ IMMUTABLE BASELINE
→ FILESYSTEM BACKUP
→ DATABASE BACKUP
→ B2 UPLOAD
→ REMOTE READBACK
→ ISOLATED RESTORE
→ SECURITY SCAN
→ TEST DISCOVERY
→ STAGING
→ REMEDIATION
→ DEPLOYMENT PACKAGE
→ ROLLBACK READY
→ MONITORING
→ ALERTING
→ REPORTING
```

A component contract, fixture, reference environment, synthetic rehearsal, persisted flag, or passing unit test may prove a subsystem. None of those alone proves customer service readiness.

At least one real internal application must complete the applicable end-to-end lifecycle before any external private-beta customer is onboarded.

---

## 2. Current supported scope

### 2.1 First supported beta profile

The current implementation must support:

- Linux-hosted PHP 8.x applications;
- Nginx or Apache;
- MariaDB/MySQL;
- direct-filesystem applications after AppCare brownfield normalization;
- Git-based deployments after AppCare verifies exact source/artifact binding;
- owner-controlled or customer-controlled Linux infrastructure;
- one application-scoped production approval at a time.

### 2.2 First real acceptance target

```text
APPLICATION=video.slabfranchise.com
HOST=64.44.115.21
EXPECTED_HOSTNAME=slab-prompt-ola
```

The target is an internal acceptance application, not permission for unrestricted production mutation.

### 2.3 Explicitly deferred current-branch work

The following are future branches and require separate owner authorization before implementation:

```text
WORDPRESS=FUTURE_BRANCH
WOOCOMMERCE=FUTURE_BRANCH
```

Node.js, Python, provider-native GitHub/Supabase service profiles, and Vercel deployment automation are later expansion work. Vercel Issue #30 remains separate and is not a blocker for the current Linux/PHP critical path.

---

## 3. Mandatory maturity model

Every component, adapter, capability, and service must be reported with exactly one maturity level:

### `DOCUMENTED`

Requirements or design exist, but working code is absent or incomplete.

### `COMPONENT_IMPLEMENTED`

The component has code and deterministic component tests, but is not fully wired into the AppCare runtime for the supported profile.

### `RUNTIME_INTEGRATED`

The component is wired through the real AppCare API/workflow/persistence/runtime path in an AppCare-controlled environment.

### `LIVE_VERIFIED`

The component has qualifying, exact-scope, exact-revision, real-target evidence against the approved internal target.

### `SERVICE_READY`

The component and all mandatory dependencies have passed live evidence, operational controls, security gates, recovery, observability, documentation, and support requirements for the advertised service.

The unqualified word `IMPLEMENTED` is prohibited in readiness reports.

---

## 4. Current implementation baseline

This table records customer-service maturity, not merely the amount of code present.

| Component | Current maturity | Existing foundation | Missing for next maturity |
|---|---|---|---|
| Product readiness evaluator | `RUNTIME_INTEGRATED` | Spec 013 layered readiness, capability registry, evidence binding, downgrade rules | Real-target capability evidence |
| Linux/SSH typed transport | `COMPONENT_IMPLEMENTED` | Strict host-key verification, bounded typed read-only commands, no TOFU | Credential custody, onboarding, live acceptance |
| Credential metadata | `COMPONENT_IMPLEMENTED` | Opaque references and lifecycle metadata | Encrypted secret custody and runtime resolver |
| SSH bootstrap/provisioning | `DOCUMENTED` | Owner authorization and security boundaries | Manual-install and one-time admin bootstrap implementations |
| Live CONNECT/INVENTORY | `DOCUMENTED` | Transport and collectors exist | Real credential path and live evidence |
| Immutable application baseline | `DOCUMENTED` | Requirement identified | Captured revision, manifests, hashes, runtime/database binding |
| Filesystem backup source | `DOCUMENTED` | BackupSource contract exists | Real safe walker, classifier, streaming/chunking, manifest |
| Database adapters | `COMPONENT_IMPLEMENTED` | Spec 015 MariaDB/PostgreSQL reference adapters and tests | Live credential/transport and real isolated restore |
| Backup integrity engine | `COMPONENT_IMPLEMENTED` | Manifest, checksum, AES-GCM, readback and isolated artifact restore logic | Real source adapters, streaming, runtime job wiring |
| B2 operational vault | `DOCUMENTED` | Controlled provider boundary exists outside full runtime | Concrete AppCare runtime vault and lifecycle |
| Glacier archive lifecycle | `DOCUMENTED` | Policy and controlled evidence | Automated archive transition/readback/retention |
| Complete application restore | `DOCUMENTED` | Artifact restore verifier | Filesystem tree, DB, modes, config, service reconstruction |
| Finding normalization | `RUNTIME_INTEGRATED` | Existing normalized evidence/finding pipeline | Live bounded scanner execution |
| Live scanning | `DOCUMENTED` | Scanner adapter contracts | Sandboxed scanner registry and real-target evidence |
| Test discovery | `DOCUMENTED` | Requirement identified | PHP/Composer/custom test detection and fallback profile |
| Remediation workflow | `COMPONENT_IMPLEMENTED` | Isolated workspace, approval and evidence contracts | Brownfield source capture, staging runtime and artifact |
| Customer staging | `DOCUMENTED` | AppCare reference environments exist | Isolated customer clone, sanitized DB, side-effect suppression |
| Customer deployment | `DOCUMENTED` | Reference atomic deployment provider | Generic Linux/PHP deployment adapter |
| Migration safety | `DOCUMENTED` | Release requirement identified | Migration classification and rollback/data-loss plan |
| Customer rollback | `DOCUMENTED` | Workflow/reference rollback exists | Target-specific file/config/DB rollback |
| Monitoring engine | `COMPONENT_IMPLEMENTED` | Persistence, replay, dedupe, report state | Live collectors and scheduler |
| Durable scheduler | `DOCUMENTED` | Durable workflow foundation | Production schedules, leases, recovery and quotas |
| Alert delivery | `DOCUMENTED` | Alert records/deduplication | Operator email and customer notification delivery |
| Customer dashboard | `RUNTIME_INTEGRATED` | Tenant-scoped dashboard state | Public production hardening and complete live inputs |
| Operator dashboard | `DOCUMENTED` | Requirements identified | Operator UI/API for onboarding, incidents, credentials and approvals |
| Billing/offboarding | `DOCUMENTED` | Commercial policy exists | Entitlements, cancellation, export, retention, deletion, credential removal |
| AppCare disaster recovery | `DOCUMENTED` | Backup principles exist | Control-plane, evidence and custody restore proof |

No row may advance solely because a worker reports success. Evidence and coordinator approval are mandatory.

---

## 5. Architecture planes

The finished service requires five connected planes.

### 5.1 Control plane

Owns tenants, users, applications, supportability, jobs, findings, approvals, audit, evidence, costs, dashboards, incidents, and readiness.

### 5.2 Credential and trust plane

Owns SSH keys, provider credentials, DB credentials, backup-provider credentials, trusted host fingerprints, encryption, rotation, revocation, bootstrap, and offboarding.

### 5.3 Customer execution plane

Performs bounded connect, inventory, file capture, DB capture, scanning, staging, testing, deployment, verification, rollback, and monitoring against the approved target.

### 5.4 Evidence and recovery plane

Owns immutable manifests, checksums, encryption, B2, Glacier, remote readback, restore rehearsals, rollback references, customer reports, and recovery receipts.

### 5.5 Operations plane

Owns durable schedules, workers, operator dashboard, email/customer alerts, support tiers, billing, cancellation, capacity controls, and AppCare self-recovery.

A phase is incomplete when its control-plane record exists but its execution-plane action is not wired.

---

## 6. Global security and production invariants

1. `TARGET=AppCare` is mandatory for all work.
2. SecurityOla WordPress/plugin files, DBs, services, credentials, logs, and backup namespaces remain untouched.
3. Root is not a normal AppCare customer-access identity.
4. Unrestricted sudo is prohibited.
5. Model output cannot become arbitrary shell, SQL, scanner command, deployment command, or path.
6. Raw credentials never enter Git, issues, PRs, evidence, model prompts, API responses, normal logs, or CI artifacts.
7. Host identity must be pre-registered and strictly verified; no TOFU.
8. Tenant, application, target, revision, artifact, credential, backup, and approval identities remain bound.
9. A production change requires a valid pre-change backup and verified recovery path.
10. A production deployment without reliable rollback is denied.
11. Every private-beta production change requires explicit owner/customer-approver authorization.
12. Staging may perform bounded minimal changes only after side effects and production secrets are removed or replaced.
13. Production email, real payment processing, customer webhooks, fulfillment, production cron, and production tokens must not run in staging.
14. Upload success is not backup success. Remote readback and isolated restore evidence are required.
15. Large-site backups require bounded streaming/chunking; one in-memory JSON bundle is not service-ready.
16. A real target is never deliberately broken merely to demonstrate rollback.
17. Every phase has a hard exit gate.
18. Later independent research may proceed in parallel, but no readiness state may bypass a failed dependency.
19. Exact-head CI and security evidence are required for protected merge.
20. The final beta candidate must pass the complete S01-S30 security gate.

---

## 7. Multi-model engineering responsibilities

### GPT-5.6 Luna Max — primary coordinator

Luna owns:

- dependency planning;
- architecture integration;
- task packet definition;
- scope control;
- acceptance criteria;
- actual-diff review;
- trust-boundary function approval;
- readiness decisions;
- merge recommendation;
- final owner-facing report.

Luna must publish a dependency-based plan before delegating code.

### GPT-5.3 Spark — primary coder

Spark implements bounded Luna-approved work packets, tests, fixes, and documentation. Spark cannot change architecture, approve its own work, promote readiness, merge, or authorize production.

### GPT-5.6 Terra — independent architecture/security challenger

Terra reviews designs and actual security-sensitive diffs for privilege, cross-tenant access, data loss, injection, credential exposure, rollback hazards, recovery gaps, and operational failure. Terra does not merge or self-approve a patch it authored.

### Codex Security — independent security verification

Every security-relevant PR requires the applicable diff/repository scan. Repaired attack paths require verify-fix where appropriate.

### Protected merge loop

```text
Luna dependency plan
→ Spec Kit artifacts
→ Terra design challenge
→ Spark bounded implementation
→ Luna actual-diff review
→ Terra security review
→ deterministic and adversarial tests
→ dependency/secret/public-safety scans
→ Codex Security
→ exact-head CI
→ protected merge
→ evidence/readiness update
```

---

# PHASE 01 — Binding blueprint and enforcement

## Objective

Make this blueprint, the current scope, maturity model, future-branch exclusions, and phase gates impossible to silently remove or bypass.

## Build deliverables

- `APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md`;
- machine-readable `docs/governance/APPCARE_CURRENT_SCOPE.json`;
- CI tests enforcing:
  - five maturity levels;
  - first supported stack;
  - first real target;
  - 12 phases;
  - hard exit gates;
  - WordPress/WooCommerce current exclusion;
  - model responsibilities;
  - fail-closed readiness;
- links from README and active agent/workflow governance;
- issue #32 update;
- dependency-based phase status format.

## Security requirements

- governance changes use protected PR;
- no production or credential mutation;
- scope JSON contains no secrets or private infrastructure details beyond approved public/internal identifiers;
- CI must fail when mandatory markers are deleted or changed inconsistently.

## Acceptance

- new governance tests pass;
- full CI passes;
- public-safety and secret scans pass;
- Luna confirms actual diff;
- Terra confirms the blueprint does not create unsafe authority;
- protected merge completes.

## Hard exit gate

```text
P01_BLUEPRINT_MERGED=YES
P01_SCOPE_MACHINE_READABLE=YES
P01_CI_ENFORCEMENT=PASS
```

## Readiness effect

No customer capability is promoted. This phase only makes the remaining work mandatory.

---

# PHASE 02 — Credential custody and SSH onboarding

## Objective

Build the actual secure harness that converts an opaque credential reference into a usable, scoped, revocable SSH identity without exposing private key material.

## Build deliverables

### Local encrypted pilot vault

- AppCare-owned encrypted credential store;
- master-key boundary outside Git/model/evidence;
- atomic writes;
- strict owner/mode/symlink validation;
- bounded key size and supported formats;
- tenant/application/target/version binding;
- backup and recovery procedure for custody metadata and encrypted blobs.

### SSH key service

- Ed25519 key generation;
- approved key import;
- public-key derivation;
- credential fingerprint;
- versioning;
- active/expired/revoked states;
- rotation;
- destruction/offboarding.

### Runtime credential provider

- `credential_reference -> private runtime handle`;
- no raw secret return through API/evidence;
- identity-file lifecycle bounded to the operation;
- strict permission/owner checks;
- no agent fallback;
- no root credential;
- no cross-tenant/application reuse.

### Manual onboarding path

- produce only the public key and installation instructions;
- owner/customer installs it;
- AppCare verifies account/host/key binding;
- no private key leaves custody.

### One-time administrator bootstrap path

- separate privileged state machine;
- explicit authorization record;
- fixed operations only:
  - create/verify dedicated non-root account;
  - create `.ssh` safely;
  - install exact public key;
  - apply approved restrictions;
  - verify access;
- no arbitrary root shell API;
- no permanent admin credential reuse;
- deterministic cleanup on partial failure.

### Offboarding

- remove/revoke public key;
- disable/remove dedicated account when policy allows;
- prove old key fails;
- preserve sanitized audit record.

## Security threat tests

- private-key disclosure;
- wrong file owner/mode;
- symlink/path traversal;
- key substitution;
- cross-tenant/app credential;
- root/sudo path;
- authorized_keys injection;
- newline/options injection;
- stale/revoked/expired key;
- rotation races;
- partial bootstrap;
- replay/duplicate bootstrap;
- secret-shaped stderr/logging;
- recovery after process crash.

## Acceptance

Reference acceptance must prove create, resolve, rotate, revoke, and offboard. Live acceptance uses the already owner-authorized internal target and the AppCare harness itself.

## Hard exit gate

```text
P02_LOCAL_VAULT=RUNTIME_INTEGRATED
P02_MANUAL_ONBOARDING=LIVE_VERIFIED
P02_BOOTSTRAP_PATH=LIVE_VERIFIED_OR_BLOCKED_EXTERNAL_WITH_MANUAL_PATH_PASS
P02_ROTATION=LIVE_VERIFIED
P02_OFFBOARDING=LIVE_VERIFIED
P02_SECRETS_EXPOSED=NO
```

## Readiness effect

Credential rotation/offboarding remain unpromoted until the whole lifecycle and external-beta vault requirement pass.

---

# PHASE 03 — Live CONNECT, INVENTORY, and immutable baseline

## Objective

Use AppCare itself to establish trusted read-only access, collect normalized inventory, and assign an immutable identity to a brownfield application that has no Git revision.

## Build deliverables

### Live target registration

- tenant/application/environment/host/port;
- expected hostname;
- trusted host-key fingerprint;
- dedicated credential reference;
- approved application roots;
- approved services and DB identifiers;
- target status and last verification.

### Live inventory

- OS/kernel;
- web server and vhost;
- PHP runtime/FPM;
- relevant services;
- network bindings;
- TLS metadata;
- application root;
- owners/modes;
- storage;
- database identity metadata;
- deployment layout;
- existing backup metadata;
- persistent/uploads/cache/temp classification candidates.

### Captured application revision

- deterministic filesystem manifest;
- file hashes;
- selected config hashes without secret values;
- permission/ownership metadata;
- runtime identity;
- DB schema/reference identity;
- deployment metadata;
- persistent-data classification;
- canonical revision digest.

### Internal source mirror

For non-Git text/code, create an AppCare-owned versioned mirror outside customer production. Do not initialize or rewrite Git inside production without separate authorization.

## Security tests

- host-key mismatch;
- hostname mismatch;
- wrong root;
- symlink escape;
- malicious filenames;
- huge output;
- secret-bearing paths;
- cross-tenant target;
- modified file during capture;
- duplicate/replay;
- unstable manifest;
- TOCTOU defenses where practical.

## Acceptance

The exact internal target must produce:

```text
CONNECT=LIVE_VERIFIED
INVENTORY=LIVE_VERIFIED
SOURCE_REVISION=LIVE_VERIFIED
```

Repeated capture with no change must produce the same revision digest; a controlled staging fixture change must change it.

## Hard exit gate

```text
P03_HOST_IDENTITY=PASS
P03_CONNECT=LIVE_VERIFIED
P03_INVENTORY=LIVE_VERIFIED
P03_IMMUTABLE_REVISION=LIVE_VERIFIED
P03_INTERNAL_MIRROR=RUNTIME_INTEGRATED
```

---

# PHASE 04 — Streaming filesystem backup and data classification

## Objective

Capture the real application filesystem safely and efficiently without loading the full site into memory or backing up unnecessary regenerable media.

## Build deliverables

- `LinuxFilesystemBackupSource`;
- allowlisted roots;
- durable/selective/regenerable/temp/secret/prohibited classification;
- include/exclude policy;
- symlink and special-file policy;
- ownership/mode manifest;
- streaming/chunked archive;
- bounded memory;
- resumable checkpoints;
- per-file and aggregate digests;
- incremental/deduplication strategy;
- large-file policy;
- deterministic manifest;
- cleanup/quarantine of failed partial artifacts.

## Default exclusions

- render caches;
- generated thumbnails;
- regenerable outputs;
- package caches;
- temporary downloads;
- temp/session files;
- logs outside approved retention.

Persistent uploads, durable application data, approved configuration, manifests, and application files remain included.

## Security tests

- symlink and hard-link escapes;
- device/FIFO/socket files;
- path traversal;
- sparse/huge files;
- file mutation during capture;
- unreadable files;
- disk exhaustion;
- archive bombs;
- secret leakage into evidence;
- cross-tenant destination;
- retry/resume corruption.

## Acceptance

Against the internal target, create a pre-change filesystem backup with bounded memory and a stable manifest. Restore the file tree into an isolated location and verify content, path boundaries, and required modes.

## Hard exit gate

```text
P04_FILESYSTEM_BACKUP=LIVE_VERIFIED
P04_STREAMING_BOUNDED=PASS
P04_MANIFEST=PASS
P04_ISOLATED_FILE_RESTORE=PASS
```

---

# PHASE 05 — Live MariaDB/MySQL transport and database restore

## Objective

Connect the Spec 015 safety contracts to a real customer database path and prove a consistent backup and isolated restore without modifying production.

## Build deliverables

- database credential provider;
- SSH-mediated or approved network DB transport;
- DB identity and version verification;
- consistent MariaDB/MySQL dump;
- charset/collation preservation;
- routines/triggers/events policy;
- credential-safe invocation;
- streaming output;
- checksums and manifest binding;
- cancellation/timeouts;
- partial/truncated dump detection;
- isolated MariaDB restore environment;
- schema/data integrity queries;
- cleanup and quarantine;
- runtime wiring to AppCare backup jobs.

PostgreSQL reference support remains maintained, but the first profile exit gate is MariaDB/MySQL.

## Security tests

- DB-name/argument injection;
- process-list credential leakage;
- wrong DB/tenant/app;
- partial dump;
- disconnect;
- oversized output;
- malicious DEFINER/security context;
- version mismatch;
- charset mismatch;
- restore to production identifier;
- restore cleanup failure;
- disk exhaustion;
- replay/concurrency.

## Acceptance

Produce a live read-only backup of the internal target database and restore it into an isolated non-production DB. Verify counts/schema/application-specific integrity without exposing production data in evidence.

## Hard exit gate

```text
P05_DATABASE_BACKUP=LIVE_VERIFIED
P05_ISOLATED_DB_RESTORE=LIVE_VERIFIED
P05_PRODUCTION_DB_WRITES=NO
P05_CREDENTIAL_EXPOSURE=NO
```

---

# PHASE 06 — B2, Glacier, and complete application restore

## Objective

Turn separate file/DB artifacts into an authoritative off-site recovery point and reconstruct the application in an isolated environment.

## Build deliverables

### B2 operational vault

- concrete runtime vault;
- canonical namespace:
  `appcare/backups/<tenant>/<application>/<backup>/`;
- upload;
- remote HEAD/readback;
- checksum match;
- retention/Object Lock evidence;
- retry/resume;
- provider outage classification;
- durable evidence.

### Glacier archive

- monthly archive transition;
- 12-month policy;
- archive reference;
- retention evidence;
- restore-request workflow;
- cost controls.

### Complete restore planner

- bind exact captured revision;
- fetch files and DB;
- reconstruct filesystem tree;
- restore modes/ownership where safe;
- restore DB;
- replace secrets through custody;
- generate isolated vhost/service configuration;
- start isolated application;
- verify HTTP, PHP, DB, and critical baseline flow;
- create recovery receipt and measured RTO.

## Backup policy

```text
PRE_CHANGE_BACKUP=MANDATORY
FILES_BACKUP=DAILY
DATABASE_BACKUP=DAILY
B2_OPERATIONAL_RETENTION=30_DAYS
MONTHLY_GLACIER_ARCHIVE=12_MONTHS
REMOTE_READBACK=EVERY_BACKUP
ISOLATED_RESTORE_REHEARSAL=MONTHLY
```

## Security tests

- wrong object/prefix;
- cross-tenant readback;
- corrupted ciphertext;
- checksum mismatch;
- retention missing;
- provider partial upload;
- malicious archive paths;
- credential substitution;
- restore over production;
- stale revision;
- restore secret exposure;
- incomplete component set.

## Acceptance

A backup is valid only when remote readback and isolated full-application restore pass for the same exact application revision.

## Hard exit gate

```text
P06_OFFSITE_BACKUP=LIVE_VERIFIED
P06_REMOTE_READBACK=LIVE_VERIFIED
P06_COMPLETE_ISOLATED_RESTORE=LIVE_VERIFIED
P06_MONTHLY_RESTORE_SCHEDULE=RUNTIME_INTEGRATED
```

---

# PHASE 07 — Live security scanning and test discovery

## Objective

Run real bounded scanners and discover executable application tests without allowing customer content or model output to control the scanner runtime.

## Build deliverables

### Sandboxed scanner runtime

- closed scanner registry;
- pinned/allowlisted scanner identities;
- no arbitrary executable;
- sanitized environment;
- no inherited credentials;
- network denied by default;
- bounded CPU, memory, disk, time, stdout/stderr;
- tenant/application/path binding;
- realpath and symlink enforcement;
- replay/idempotency;
- normalized findings and evidence digest.

### First-profile scanner set

- secret scan;
- PHP syntax;
- Composer dependency/security;
- source/static security;
- permissions/ownership;
- Nginx/Apache config;
- TLS;
- exposed/bound ports;
- service configuration;
- public HTTP security checks.

### Test discovery

- PHPUnit;
- Pest;
- Composer scripts;
- custom safe test commands;
- health/HTTP/DB fallback profile;
- explicit `NO_TEST_SUITE`;
- no false `PASS`.

## Security tests

- scanner/config injection;
- malicious files and filenames;
- symlink escape;
- archive bombs;
- huge output;
- hangs;
- resource exhaustion;
- scanner-output poisoning;
- cross-tenant path;
- SSRF/network escape;
- secret exfiltration;
- malformed findings;
- duplicate/replay.

## Acceptance

Run the approved first-profile scanners against the captured internal target in read-only mode. Select one evidence-backed safe finding or controlled staging fixture for later remediation.

## Hard exit gate

```text
P07_SECURITY_SCAN=LIVE_VERIFIED
P07_TEST_DISCOVERY=LIVE_VERIFIED
P07_SCANNER_SANDBOX=PASS
P07_FINDING_EVIDENCE=PASS
```

---

# PHASE 08 — Brownfield normalization, staging, and remediation

## Objective

Convert a direct-filesystem application into an AppCare-manageable, versioned, testable deployment without editing production first.

## Build deliverables

### Brownfield normalization

- captured baseline;
- AppCare internal mirror;
- persistent-data separation;
- releases directory strategy;
- health probe;
- deployment metadata;
- current/previous known-good references;
- backup/restore references;
- monitoring profile.

### Isolated staging

- separate filesystem;
- separate sanitized DB;
- separate service/port/vhost/domain;
- no production email;
- no real payment;
- no customer webhooks;
- no fulfillment;
- no production cron;
- no production provider tokens;
- bounded outbound network;
- cleanup.

### Remediation

- finding-to-patch plan;
- minimal diff;
- approved file set;
- no opportunistic refactor;
- test execution;
- security regression;
- artifact build;
- exact revision/artifact/evidence binding.

## Security tests

- production secret copied to staging;
- real email/webhook/payment side effect;
- staging path escape;
- DB sanitization failure;
- unrelated diff;
- dependency drift;
- artifact substitution;
- stale finding;
- worker self-approval.

## Acceptance

A safe evidence-backed issue must be fixed in staging, tested, security-reviewed, and packaged as an exact artifact. Production remains untouched.

## Hard exit gate

```text
P08_BROWNFIELD_NORMALIZED=LIVE_VERIFIED
P08_STAGING=LIVE_VERIFIED
P08_REMEDIATION=LIVE_VERIFIED
P08_PREPRODUCTION_RECEIPT=PASS
```

---

# PHASE 09 — Deployment, migration safety, verification, and rollback

## Objective

Deploy only the exact approved artifact through a target-specific controlled path and recover safely when verification fails.

## Build deliverables

### Deployment adapter

- generic Linux atomic/versioned release;
- exact artifact digest;
- current/previous pointers;
- bounded service reload/restart;
- application-scoped authorization;
- immutable deployment record.

### Migration safety

Classify:

```text
NO_DB_CHANGE
REVERSIBLE
BACKWARD_COMPATIBLE
IRREVERSIBLE
UNKNOWN
```

Require fresh DB backup, migration identity, forward/rollback plan, compatibility analysis, and explicit approval for irreversible/unknown changes.

### Verification profile

- HTTP/TLS;
- expected content;
- PHP/service;
- DB connectivity;
- critical application flow;
- error/log signal;
- deployment revision/artifact match.

### Rollback

- file/config pointer rollback;
- DB rollback only when transaction/data-loss policy permits;
- post-rollback verification;
- incident record;
- no infinite automatic retries.

## Security tests

- artifact/revision substitution;
- stale authorization;
- cross-tenant deployment;
- unapproved service/path;
- partial deployment;
- restart failure;
- verification false positive;
- unsafe DB rollback;
- transactions after deployment;
- rollback failure;
- operator stop.

## Acceptance

The internal pilot must produce a production authorization package and stop for explicit authorization. After authorization, execute one safe reversible deployment, verify it, and prove rollback without intentionally causing a needless outage.

## Hard exit gate

```text
P09_DEPLOY=LIVE_VERIFIED
P09_PRODUCTION_VERIFY=LIVE_VERIFIED
P09_DATABASE_MIGRATION_SAFETY=LIVE_VERIFIED
P09_ROLLBACK=LIVE_VERIFIED
```

---

# PHASE 10 — Monitoring, scheduler, alerting, reporting, and support tiers

## Objective

Operate the Protection service continuously rather than only on demand.

## Build deliverables

### Durable scheduler

- PostgreSQL-backed schedules;
- worker lease/leadership;
- duplicate prevention;
- restart recovery;
- missed-run recovery;
- cancellation;
- tenant quotas;
- cost budgets;
- dead-letter/escalation state.

### Mandatory collectors

- HTTP uptime;
- TLS expiry;
- application service/process;
- database connectivity;
- disk capacity;
- backup freshness;
- backup readback/integrity;
- critical application flow;
- deployment change;
- configuration drift.

### Alert delivery

Internal pilot:

- operator dashboard/CLI state;
- operator email.

External beta:

- operator dashboard;
- operator email;
- policy-based customer notifications.

### Reporting

- weekly summary;
- monthly customer report;
- backup/restore status;
- findings/remediation;
- incidents;
- known limitations;
- usage/cost.

### Support tiers

```text
TIER_1=deterministic documented resolution
TIER_2=Luna-coordinated diagnosis and proposed remediation
TIER_3=owner/engineer decision
```

## Security tests

- scheduler duplicate execution;
- cross-tenant schedule;
- collector SSRF;
- credential leakage;
- huge responses;
- alert storms;
- dedupe bypass;
- email injection;
- stale data;
- worker crash/restart;
- quota bypass.

## Acceptance

Run the internal target for a sustained observation window with scheduled backups, monitoring, alert test, restart replay, and customer/operator reports.

## Hard exit gate

```text
P10_MONITORING=LIVE_VERIFIED
P10_SCHEDULER=LIVE_VERIFIED
P10_ALERTING=LIVE_VERIFIED
P10_REPORTING=LIVE_VERIFIED
P10_RESTART_DURABILITY=PASS
```

---

# PHASE 11 — Operator productization, commercial lifecycle, and AppCare self-recovery

## Objective

Complete the operational features required before external or paid customers.

## Build deliverables

### Operator dashboard

- tenants/applications;
- supportability;
- connector/credential health;
- findings;
- backups;
- restore rehearsals;
- approvals;
- deployments/rollback;
- monitoring/alerts/incidents;
- schedules;
- usage/cost;
- emergency stop;
- offboarding.

### Customer authentication and approval

- production-safe sessions;
- recovery;
- session revocation;
- optional TOTP;
- owner/operator/approver roles;
- application-scoped approvals;
- audit.

### Commercial lifecycle

Before first paid customer:

- billing/entitlement;
- failed-payment policy;
- cancellation;
- final verified backup/export;
- retention/deletion automation;
- credential revocation/offboarding;
- customer data export/delete;
- support status.

### AppCare disaster recovery

- control-plane DB backup;
- evidence backup;
- credential-vault recovery;
- scheduler/workflow recovery;
- service redeployment;
- AppCare RPO/RTO receipt;
- worker/service observability.

### Credential requirement for external beta

The local encrypted pilot vault is insufficient for paid external beta. Integrate an external secret manager and prove migration/rotation/recovery.

## Security tests

- RBAC bypass;
- approver spoofing;
- session theft/replay;
- MFA/recovery abuse;
- billing entitlement bypass;
- cancellation data leak;
- failed credential removal;
- AppCare DR without vault;
- operator dashboard cross-tenant exposure.

## Acceptance

Perform complete onboarding/offboarding rehearsal, credential rotation, final backup export, AppCare restore rehearsal, and external-vault acceptance.

## Hard exit gate

```text
P11_OPERATOR_DASHBOARD=LIVE_VERIFIED
P11_AUTH_APPROVAL=LIVE_VERIFIED
P11_BILLING_OFFBOARDING=LIVE_VERIFIED
P11_EXTERNAL_SECRET_MANAGER=LIVE_VERIFIED
P11_APPCARE_DR=LIVE_VERIFIED
```

---

# PHASE 12 — Real-target acceptance, final security gate, and beta launch decision

## Objective

Prove the product promise on the real internal target, perform the exact-release security review, and make the internal-pilot/external-beta decision.

## Preproduction real-target sequence

1. CONNECT
2. INVENTORY
3. SUPPORTABILITY
4. IMMUTABLE REVISION
5. FILESYSTEM BACKUP
6. DATABASE BACKUP
7. B2 UPLOAD
8. REMOTE READBACK
9. CHECKSUM VERIFICATION
10. ISOLATED FULL RESTORE
11. RESTORE VALIDATION
12. LIVE SECURITY SCAN
13. EVIDENCE-BACKED SAFE FINDING
14. REMEDIATION WORKSPACE
15. MINIMAL FIX
16. TESTS
17. SECURITY TESTS
18. ISOLATED STAGING
19. CRITICAL-FLOW VERIFICATION
20. AUTHORITATIVE PREPRODUCTION RECEIPT
21. ROLLBACK READY
22. PRODUCTION AUTHORIZATION PACKAGE

Stop for explicit owner authorization before the first production mutation.

## Owner-authorized sequence

23. EXACT APPLICATION-SCOPED AUTHORIZATION
24. CONTROLLED DEPLOY
25. PRODUCTION VERIFICATION
26. SAFE ROLLBACK PROOF
27. ROLLBACK VERIFICATION
28. LIVE MONITORING
29. ALERT TEST
30. BACKUP-HEALTH MONITOR
31. CUSTOMER REPORT
32. OPERATOR REPORT
33. APPCARE RESTART
34. DURABLE-STATE VERIFICATION
35. REAL COST MEASUREMENT
36. CREDENTIAL ROTATION
37. OFFBOARDING REHEARSAL

## Final security gate

Against the exact release candidate:

- S01-S30 review;
- full Codex Security repository scan;
- exact range diff review;
- dependency audit;
- secret/public-safety scan;
- Graphify impact/integrity;
- adversarial real-target tests;
- credential-custody review;
- backup/restore review;
- scanner sandbox review;
- deployment/rollback/data-loss review;
- monitoring/scheduler/alert review;
- AppCare DR review;
- Luna final acceptance;
- Terra independent security disposition.

## Hard exit gate

```text
P12_REAL_TARGET_FULL_LIFECYCLE=PASS
P12_S01_S30=PASS
P12_INTERNAL_PILOT=PASS
P12_REAL_COST_MEASURED=YES
P12_OPEN_CRITICAL_FINDINGS=0
```

## Readiness transitions

```text
CUSTOMER_ONBOARDING_READY=YES
```

only after the real target passes authoritative preproduction.

```text
PILOT_READY=YES
```

only after explicit owner-authorized production, verification, rollback proof, monitoring, alerts, reports, restart durability, rotation, and offboarding pass.

```text
PAID_SERVICE_READY=YES
```

only after Phase 11 and Phase 12 external-customer requirements pass.

Global production does not become unrestricted:

```text
LIVE_CUSTOMER_PRODUCTION_ENABLED=NO
```

The system continues to use exact application-scoped authorization.

---

## 20. Dependency map

```text
P01 Blueprint/enforcement
  ↓
P02 Credential custody/onboarding
  ↓
P03 Connect/inventory/immutable revision
  ↓
P04 Filesystem backup ──┐
  ↓                     │
P05 Database backup ────┤
  ↓                     │
P06 Offsite/full restore┘
  ↓
P07 Live scan/test discovery
  ↓
P08 Normalize/stage/remediate
  ↓
P09 Deploy/verify/rollback
  ↓
P10 Monitor/schedule/alert/report
  ↓
P11 Productize/offboard/self-DR
  ↓
P12 Real target/security/beta decision
```

No higher readiness state may skip a failed predecessor.

---

## 21. Phase reporting contract

Every owner-facing phase report must include:

```text
PHASE=
BASE_MAIN_SHA=
BRANCH=
PR=
EXACT_HEAD=
MERGE_SHA=

MATURITY_BEFORE=
MATURITY_AFTER=

DELIVERABLES_BUILT=
RUNTIME_WIRING=
LIVE_EVIDENCE=
FUNCTION_APPROVALS=

TESTS=
NEGATIVE_TESTS=
CODEX_SECURITY=
TERRA_SECURITY_REVIEW=
LUNA_ACTUAL_DIFF_REVIEW=
CI=
GRAPHIFY=
SAVERUFLO=
SPECKIT=

DEPENDENCIES_SATISFIED=
HARD_EXIT_GATE=
CAPABILITIES_PROMOTED=
CAPABILITIES_NOT_PROMOTED=
OWNER_ONLY_BLOCKERS=

CUSTOMER_PRODUCTION_MUTATED=
WORDPRESS_TOUCHED=NO
WOOCOMMERCE_TOUCHED=NO
SECRETS_EXPOSED=NO
LIVE_CUSTOMER_PRODUCTION_ENABLED=NO
```

Reports must state the exact maturity level rather than using `IMPLEMENTED` alone.

---

## 22. Current truthful readiness

```text
CORE_PLATFORM_READY=YES

STACK_GENERIC_LINUX_READY=NO
STACK_WORDPRESS_READY=NO
STACK_WOOCOMMERCE_READY=NO
STACK_GITHUB_VERCEL_SUPABASE_READY=NO

CUSTOMER_ONBOARDING_READY=NO
PILOT_READY=NO
PAID_SERVICE_READY=NO

LIVE_CUSTOMER_PRODUCTION_ENABLED=NO
```

---

## 23. Definition of completion

The current project is complete only when:

- all 12 phase hard exits pass;
- all required capabilities for the Linux/PHP/MariaDB profile are `SERVICE_READY`;
- one real internal application completes the full lifecycle;
- the exact release candidate passes S01-S30;
- no unresolved critical/high release blocker remains;
- monitoring, backup, restore, alerting, rotation, offboarding, and AppCare DR remain operational after restart;
- real cost and operator effort fit the approved commercial model;
- WordPress and WooCommerce remain separate future branches unless separately authorized.

This blueprint may be amended only through a protected PR that records the owner decision, affected dependencies, readiness impact, security impact, tests, and exact-head CI.
