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
21. Only qualifying `real_target` evidence may promote customer-onboarding, pilot, or paid-service readiness; fixture, reference, and controlled-provider evidence must fail closed at those layers.
22. The Spec 013 readiness evaluator is the sole authority for capability and readiness promotion; a caller-supplied boolean or worker claim is never sufficient.
23. Production authority is resolved from persisted, scope-bound approval and recovery evidence, never from an input flag supplied by a worker or caller.

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

## Enforceable phase contract

- objective: Bind the current AppCare product scope and dependency gates to protected governance.
- components: blueprint, machine-readable scope, active-guidance links, and deterministic governance tests.
- runtime_wiring: CI parses the scope contract and the blueprint contract; no customer capability is enabled by this phase.
- security_requirements: protected review, no credentials or customer data, fail-closed readiness, and no production mutation.
- positive_tests: validate the product contract, exact profile and target, phase graph, gate requirements, exclusions, and readiness floor.
- negative_adversarial_tests: removing or weakening a phase, gate, dependency, exclusion, authority boundary, or evidence rule must fail CI.
- live_reference_evidence: none; this phase accepts governance evidence only and cannot substitute fixture or reference evidence for live proof.
- hard_exit_requirements: P01_BLUEPRINT_MERGED=YES; P01_SCOPE_MACHINE_READABLE=YES; P01_TWELVE_PHASES=PASS; P01_HARD_EXIT_GATES=PASS; P01_CI_ENFORCEMENT=PASS; P01_CROSS_DOCUMENT_CONSISTENCY=PASS; P01_LUNA_APPROVAL=PASS; P01_TERRA_APPROVAL=PASS; P01_CODEX_SECURITY=PASS; P01_EXACT_HEAD_CI=PASS; P01_PROTECTED_MAIN_VERIFIED=PASS.
- maturity_effect: BLUEPRINT_GOVERNANCE_MATURITY may reach SERVICE_READY only for governance enforcement itself.
- readiness_effect: promote no CONNECT, INVENTORY, customer, pilot, paid-service, or production capability.
- predecessor_dependencies: none.
- prohibited_actions: no customer access, credentials, production writes, WordPress/WooCommerce work, Vercel retry, or readiness bypass.
- owner_only_gates: owner-approved scope/amendment decisions and protected merge remain required for governance changes.

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
P01_TWELVE_PHASES=PASS
P01_HARD_EXIT_GATES=PASS
P01_CI_ENFORCEMENT=PASS
P01_CROSS_DOCUMENT_CONSISTENCY=PASS
P01_LUNA_APPROVAL=PASS
P01_TERRA_APPROVAL=PASS
P01_CODEX_SECURITY=PASS
P01_EXACT_HEAD_CI=PASS
P01_PROTECTED_MAIN_VERIFIED=PASS
```

## Readiness effect

No customer capability is promoted. This phase only makes the remaining work mandatory.

---

# PHASE 02 — Credential custody and SSH onboarding

## Objective

Build the actual secure harness that converts an opaque credential reference into a usable, scoped, revocable SSH identity without exposing private key material.

## Enforceable phase contract

- objective: Provide encrypted, scoped, revocable SSH credential custody and safe onboarding primitives.
- components: encrypted vault, Ed25519 key service, opaque resolver, manual public-key path, restricted bootstrap, rotation, revocation, and offboarding.
- runtime_wiring: credential references resolve only at the Linux SSH boundary and bootstrap uses fixed typed operations with durable audit state.
- security_requirements: no plaintext secret persistence, non-root identity, tenant binding, strict ownership/modes, no arbitrary root shell, and fail-closed revocation.
- positive_tests: create, resolve, rotate, revoke, manually onboard, bootstrap, verify, and offboard an isolated reference identity.
- negative_adversarial_tests: reject secret leakage, path/symlink attacks, key substitution, cross-tenant reuse, root/sudo, injection, replay, stale keys, and partial bootstrap.
- live_reference_evidence: approved internal target may provide bounded read-only or onboarding evidence; no customer production write is implied.
- hard_exit_requirements: P02_LOCAL_VAULT=RUNTIME_INTEGRATED; P02_MANUAL_ONBOARDING=LIVE_VERIFIED; P02_BOOTSTRAP_PATH=LIVE_VERIFIED_OR_BLOCKED_EXTERNAL_WITH_MANUAL_PATH_PASS; P02_ROTATION=LIVE_VERIFIED; P02_OFFBOARDING=LIVE_VERIFIED; P02_SECRETS_EXPOSED=NO.
- maturity_effect: custody and onboarding components advance only to the highest evidence-backed maturity level.
- readiness_effect: credential rotation/offboarding and stack readiness remain unpromoted until the whole lifecycle and external-vault requirements pass.
- predecessor_dependencies: P01.
- prohibited_actions: no customer production mutation, shared WordPress/plugin identity reuse, unrestricted sudo, or private-key exposure.
- owner_only_gates: external credential/account authorization and any first customer production bootstrap require explicit owner approval.

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

## Enforceable phase contract

- objective: Establish a trusted live target identity, normalized inventory, and immutable application baseline.
- components: target registration, host-key binding, typed connect/inventory collectors, revision capture, and internal source mirror.
- runtime_wiring: Spec 014 transport and Spec 013 capability/evidence evaluators consume the same tenant/application target identity.
- security_requirements: strict host-key verification, non-root read-only access, path/output limits, no TOFU, and no automatic privilege escalation.
- positive_tests: connect and inventory the authorized internal target, normalize observations, and seal the baseline digest.
- negative_adversarial_tests: reject wrong host keys, target substitution, traversal, symlink escape, secret output, timeouts, replay, and partial inventory masquerading as complete.
- live_reference_evidence: qualifying real-target CONNECT, INVENTORY, and immutable revision evidence is required; fixtures/reference runs remain non-live.
- hard_exit_requirements: P03_HOST_IDENTITY=PASS; P03_CONNECT=LIVE_VERIFIED; P03_INVENTORY=LIVE_VERIFIED; P03_IMMUTABLE_REVISION=LIVE_VERIFIED; P03_INTERNAL_MIRROR=RUNTIME_INTEGRATED.
- maturity_effect: Linux transport and inventory advance only when live evidence is independently accepted.
- readiness_effect: CONNECT/INVENTORY may be promoted for the exact target; backup, scan, staging, deploy, rollback, and monitoring remain missing.
- predecessor_dependencies: P02.
- prohibited_actions: no filesystem/database writes, service changes, deployment, backup, remediation, DNS, SSL, firewall, or WordPress access.
- owner_only_gates: live target scope, trust anchor, and any production mutation remain owner-authorized boundaries.

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

## Enforceable phase contract

- objective: Capture a real target filesystem through bounded streaming with explicit data classification.
- components: allowlisted source, classification policy, streaming archive, manifest, checksum, and isolated file restore.
- runtime_wiring: the filesystem source feeds the existing AppCare backup manifest and restore pipeline without a second backup system.
- security_requirements: tenant roots, symlink/special-file controls, secret exclusion, byte/resource caps, immutable metadata, and no production overwrite.
- positive_tests: stream bounded synthetic and approved reference data, seal checksums/manifests, and restore into the canonical isolated boundary.
- negative_adversarial_tests: reject traversal, symlink escape, secret/prohibited files, oversized data, truncation, checksum mismatch, and cross-tenant paths.
- live_reference_evidence: real-target filesystem evidence is required for LIVE_VERIFIED; fixture/reference archives cannot promote customer readiness.
- hard_exit_requirements: P04_FILESYSTEM_BACKUP=LIVE_VERIFIED; P04_STREAMING_BOUNDED=PASS; P04_MANIFEST=PASS; P04_ISOLATED_FILE_RESTORE=PASS.
- maturity_effect: filesystem backup advances only after bounded streaming, manifest, checksum, and isolated restore evidence pass.
- readiness_effect: no off-site or whole-application recovery claim until P06 completes remote readback and restore.
- predecessor_dependencies: P03.
- prohibited_actions: no full-memory archive, production cleanup, secret capture, WordPress/plugin backup, or alternate backup root.
- owner_only_gates: customer filesystem scope and any destructive cleanup require explicit application approval.

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

# PHASE 05 — Live MariaDB/MySQL transport and isolated database restore

## Objective

Connect the Spec 015 safety contracts to a real customer database path and prove a consistent backup and isolated restore without modifying production.

## Enforceable phase contract

- objective: Prove a bounded MariaDB/MySQL logical backup and isolated restore for the approved application database.
- components: database credential broker, identity/version check, consistent dump, artifact streaming, manifest/checksum, restore target, and verification.
- runtime_wiring: Spec 015 adapters feed the existing AppCare backup pipeline and Spec 013 evidence registry with exact target binding.
- security_requirements: closed commands, no arbitrary SQL, no secret argv/logs, consistency limitations, timeout/cancel, tenant isolation, and non-production restore only.
- positive_tests: run a real/reference logical dump, readback/checksum, isolated restore, and post-restore verification with limitations recorded.
- negative_adversarial_tests: reject wrong DB identity, unsafe definers, injection, partial/truncated dump, timeout, credential failure, production restore, and mismatched manifest.
- live_reference_evidence: qualifying real-target database evidence is required for LIVE_VERIFIED; fixtures and isolated reference databases remain non-live.
- hard_exit_requirements: P05_DATABASE_BACKUP=LIVE_VERIFIED; P05_ISOLATED_DB_RESTORE=LIVE_VERIFIED; P05_PRODUCTION_DB_WRITES=NO; P05_CREDENTIAL_EXPOSURE=NO.
- maturity_effect: database adapter maturity advances only after the exact engine, scope, integrity, and restore evidence pass.
- readiness_effect: database capability alone cannot promote whole-application backup, restore, or customer readiness.
- predecessor_dependencies: P03.
- prohibited_actions: no production restore/write, arbitrary SQL, WordPress/plugin database access, or credential copying.
- owner_only_gates: database scope and any real customer database access require explicit owner/application authorization.

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

## Enforceable phase contract

- objective: Join verified filesystem and database components into immutable off-site recovery and complete isolated restore evidence.
- components: B2 vault, Glacier archive, retention/readback verification, backup manifest, restore planner, and recovery validation.
- runtime_wiring: existing canonical AppCare backup boundary feeds approved provider wrappers and isolated restore only.
- security_requirements: least-privilege provider scope, immutable retention, remote readback on every backup, checksum binding, no secret evidence, and no production restore.
- positive_tests: upload synthetic/approved data, HEAD/read back exact objects, compare checksums, verify retention, restore files and DB in isolation, and validate application state.
- negative_adversarial_tests: reject wrong prefix, missing readback, checksum/version mismatch, retention loss, cross-tenant object, local-only restore, and restore escape.
- live_reference_evidence: provider-controlled or real-target off-site evidence must be independently proven; local snapshots are not authoritative.
- hard_exit_requirements: P06_OFFSITE_BACKUP=LIVE_VERIFIED; P06_REMOTE_READBACK=LIVE_VERIFIED; P06_COMPLETE_ISOLATED_RESTORE=LIVE_VERIFIED; P06_MONTHLY_RESTORE_SCHEDULE=RUNTIME_INTEGRATED.
- maturity_effect: off-site and complete-restore components advance only after provider and isolated-recovery receipts pass.
- readiness_effect: no deploy or pilot readiness without a verified application recovery point and rehearsal.
- predecessor_dependencies: P04 and P05.
- prohibited_actions: no alternate backup namespace, unapproved provider credential, customer-data migration, or production overwrite.
- owner_only_gates: provider/account authority and any customer data scope beyond the approved target require explicit approval.

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

## Enforceable phase contract

- objective: Execute allowlisted scanners and discover tests safely against the verified application scope.
- components: sandboxed scanner runtime, pinned scanner registry, finding normalization, test discovery, and evidence receipts.
- runtime_wiring: scanner and test-discovery results flow through the existing AppCare workflow/evidence model and cannot directly authorize remediation or production.
- security_requirements: no arbitrary executable/config/network, bounded resources/output, symlink/path scope, sanitized findings, and no inherited secrets.
- positive_tests: scan the approved target/reference fixture, discover bounded tests, normalize findings, and persist evidence with exact scope.
- negative_adversarial_tests: reject executable/config injection, SSRF, archive bombs, symlink escape, huge output, hangs, poisoned findings, secret exfiltration, and cross-tenant paths.
- live_reference_evidence: real-target scan/test-discovery evidence is required for LIVE_VERIFIED; reference scans remain non-live.
- hard_exit_requirements: P07_SECURITY_SCAN=LIVE_VERIFIED; P07_TEST_DISCOVERY=LIVE_VERIFIED; P07_SCANNER_SANDBOX=PASS; P07_FINDING_EVIDENCE=PASS.
- maturity_effect: scanner and test-discovery components advance only with bounded live evidence and independent security review.
- readiness_effect: findings do not imply a permitted fix or production action; staging and remediation remain governed by P08.
- predecessor_dependencies: P06.
- prohibited_actions: no arbitrary scanner, network pivot, customer production mutation, or model-controlled remediation.
- owner_only_gates: scope expansion, invasive checks, and production-impacting actions require explicit owner approval.

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

## Enforceable phase contract

- objective: Normalize brownfield state and perform remediation only in an isolated staging workflow.
- components: baseline/mirror, persistent-data separation, release layout, staging environment, health probe, remediation and regression evidence.
- runtime_wiring: normalized artifacts feed the existing staging/remediation workflow and preserve exact source, data, and approval bindings.
- security_requirements: no production-first edits, tenant isolation, deterministic patches, secret-safe staging, backup-before-change, and rollback preparation.
- positive_tests: normalize the approved reference target, stage the exact artifact, apply a bounded seeded fix, and pass regression/security checks.
- negative_adversarial_tests: reject unsafe patch, scope drift, secret exposure, missing backup, failed health, staging-to-production crossover, and unreviewed AI output.
- live_reference_evidence: real-target normalization and verified preproduction evidence are required for LIVE_VERIFIED; synthetic staging alone is insufficient.
- hard_exit_requirements: P08_BROWNFIELD_NORMALIZED=LIVE_VERIFIED; P08_STAGING=LIVE_VERIFIED; P08_REMEDIATION=LIVE_VERIFIED; P08_PREPRODUCTION_RECEIPT=PASS.
- maturity_effect: normalization, staging, and remediation advance independently to the highest accepted evidence level.
- readiness_effect: no deployment or customer onboarding promotion without exact preproduction evidence and rollback-ready artifact.
- predecessor_dependencies: P07.
- prohibited_actions: no direct production edit, unbounded AI patch, missing backup, or shared WordPress/plugin staging.
- owner_only_gates: remediation scope and any production write remain explicitly application-approved.

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

## Enforceable phase contract

- objective: Execute exact-artifact deployment with migration safety, verification, and automatic rollback.
- components: deployment adapter, migration planner, verification profile, immutable deployment record, rollback controller, and stop latch.
- runtime_wiring: deployment is reachable only through the durable AppCare workflow using the approved artifact, verification, and automatic rollback after authoritative preproduction and application-scoped approval.
- security_requirements: immutable intent, exact revision/digest binding, explicit approval, no arbitrary commands, transaction/data-loss analysis, rollback reference, duplicate prevention, and fail-closed verification.
- positive_tests: deploy a verified artifact to the controlled target, verify health/critical flow, exercise safe rollback, and persist all receipts.
- negative_adversarial_tests: reject missing evidence, wrong artifact, migration risk, duplicate deploy, failed health, operator stop, provider mutation after stop, and rollback mismatch.
- live_reference_evidence: qualifying controlled/real-target deployment and rollback evidence is required; fixture providers cannot certify customer service.
- hard_exit_requirements: P09_DEPLOY=LIVE_VERIFIED; P09_PRODUCTION_VERIFY=LIVE_VERIFIED; P09_DATABASE_MIGRATION_SAFETY=LIVE_VERIFIED; P09_ROLLBACK=LIVE_VERIFIED.
- maturity_effect: deployment and rollback advance only together with exact identity and verification evidence.
- readiness_effect: no pilot readiness from staging success alone and no production promotion without rollback; global live production remains disabled.
- predecessor_dependencies: P08.
- prohibited_actions: no unapproved production deploy, deliberate production failure, arbitrary shell/SQL, or rollbackless mutation.
- owner_only_gates: every real customer production write requires explicit application-scoped owner/customer approval.

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

## Enforceable phase contract

- objective: Provide durable monitoring, scheduling, alerting, reporting, and support operations.
- components: persistent scheduler, collectors, alert delivery, reports, support tiers, usage/cost records, and restart recovery.
- runtime_wiring: monitoring state persists in the PostgreSQL-backed AppCare database and is consumed by dashboard/reporting surfaces after restart.
- security_requirements: tenant-scoped collectors, bounded polling and resource quotas, alert deduplication, no secret/raw customer leakage, worker leases, and durable replay safety.
- positive_tests: run scheduled checks, persist observations/alerts/reports, restart services, replay state, and verify customer/operator views.
- negative_adversarial_tests: reject stale state, duplicate events, alert storms, cross-tenant observations, collector compromise, output exhaustion, and lost checkpoints.
- live_reference_evidence: sustained controlled/real-target monitoring and alert/report delivery are required for LIVE_VERIFIED.
- hard_exit_requirements: P10_MONITORING=LIVE_VERIFIED; P10_SCHEDULER=LIVE_VERIFIED; P10_ALERTING=LIVE_VERIFIED; P10_REPORTING=LIVE_VERIFIED; P10_RESTART_DURABILITY=PASS.
- maturity_effect: monitoring and operations advance only after persisted restart-safe evidence, not in-memory observations.
- readiness_effect: no paid-service readiness without sustained operations, support workflow, and cost evidence.
- predecessor_dependencies: P09.
- prohibited_actions: no in-memory-only acceptance, unbounded polling, customer-data leakage, production mutation through monitoring, or WordPress/WooCommerce work before the future branch.
- owner_only_gates: support-tier changes and production incident actions remain application-scoped and approved.

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

# PHASE 11 — Operator productization, commercial lifecycle, offboarding, and AppCare DR

## Objective

Complete the operational features required before external or paid customers.

## Enforceable phase contract

- objective: Operator productization, commercial lifecycle, offboarding, and AppCare DR/self-recovery.
- components: operator dashboard, customer auth/approval, billing/cancellation and billing/offboarding, external secret custody, offboarding, AppCare DR, and support procedures.
- runtime_wiring: operator/customer state, support tiers, approvals, billing status, credentials, offboarding, reports, and DR evidence are persisted and auditable.
- security_requirements: least privilege, tenant isolation, external secret custody (secret-manager custody), approval separation, recovery/offboarding proof, restart durability, and no global production switch.
- positive_tests: rehearse onboarding, approval, billing lifecycle/cancellation, rotation/offboarding, dashboard/report access, AppCare restore, and DR recovery.
- negative_adversarial_tests: reject unauthorized operator action, stale approval, revoked credential, tenant crossover, incomplete offboarding, unsafe data retention, missing DR, and billing-state mismatch.
- live_reference_evidence: external-beta service readiness requires qualifying real operational, service-ready evidence; reference product flows remain insufficient.
- hard_exit_requirements: P11_OPERATOR_DASHBOARD=LIVE_VERIFIED; P11_AUTH_APPROVAL=LIVE_VERIFIED; P11_BILLING_OFFBOARDING=LIVE_VERIFIED; P11_EXTERNAL_SECRET_MANAGER=LIVE_VERIFIED; P11_APPCARE_DR=LIVE_VERIFIED.
- maturity_effect: complete operations and operator/commercial components advance only after durable live workflow and recovery evidence.
- readiness_effect: paid-service and customer onboarding readiness remains blocked until all dependencies and the external secret-custody requirement pass.
- predecessor_dependencies: P10.
- prohibited_actions: no plaintext secret custody, global production enablement, broad autonomous onboarding, unapproved billing mutation, or WordPress/WooCommerce work before the future branch.
- owner_only_gates: commercial/legal decisions, billing/account decisions, external secret-manager authorization, and first customer production authorization remain owner-only.

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

# PHASE 12 — Real-target acceptance, exact-release security review, and beta decision

## Objective

Prove the product promise on the real internal target, perform the exact-release security review, and make the internal-pilot/external-beta decision.

## Enforceable phase contract

- objective: Complete the real-target lifecycle, real cost measurement, exact-release S01-S30 review, and evidence-backed beta decision.
- components: end-to-end/full lifecycle runner, release evidence manifest, adversarial suite, S01-S30 security suite, cost measurement, release evaluator, and owner decision record.
- runtime_wiring: the evaluator consumes all predecessor and exact-head/exact-scope persisted evidence for the decision and cannot be enabled by a caller boolean, worker claim, or stale receipt.
- security_requirements: all mandatory S01-S30 gates, real-target cost, rotation/offboarding, restart durability, reporting, rollback, and production-disable invariants must pass fail-closed.
- positive_tests: complete the full lifecycle for the real internal application, verify every receipt/digest/head, run adversarial drills, and execute the final release-readiness evaluator.
- negative_adversarial_tests: reject fixture-only evidence, stale/mismatched head/artifact, missing receipt, wrong tenant, revoked credential, failed rollback, stale monitoring, security failure, operator stop bypass, and any production bypass.
- live_reference_evidence: one real internal application must complete the applicable lifecycle; synthetic/reference evidence remains insufficient, and external private-beta requires the owner-authorized gate and exact real-target evidence.
- hard_exit_requirements: P12_REAL_TARGET_FULL_LIFECYCLE=PASS; P12_S01_S30=PASS; P12_INTERNAL_PILOT=PASS; P12_REAL_COST_MEASURED=YES; P12_OPEN_CRITICAL_FINDINGS=0.
- maturity_effect: only the exact evidence-backed layers may advance; no phase documentation or fixture result can become SERVICE_READY.
- readiness_effect: decide PRIVATE_BETA customer/pilot/paid readiness only after all predecessor gates and owner-authorized production evidence; keep global production disabled with LIVE_CUSTOMER_PRODUCTION_ENABLED=NO.
- predecessor_dependencies: P11.
- prohibited_actions: no evaluator override, evidence relabeling, readiness bypass, broad production enable, Vercel retry, deliberate customer failure, customer production mutation, or unapproved production mutation.
- owner_only_gates: final beta decision, first private-beta decision, and first external/customer production authorization require explicit owner approval; no worker can substitute for that approval.

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
