# SecurityOla AppCare Agent Instructions

## Binding authority

Before any AppCare implementation work, read:

1. `APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md`
2. `docs/governance/APPCARE_CURRENT_SCOPE.json`
3. `.specify/memory/constitution.md`
4. `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`
5. `docs/security/PRE_BETA_SECURITY_GATE.md`
6. `BETA_LOOP.md`
7. the relevant Spec Kit package

The blueprint is the authoritative current-branch dependency plan. Older roadmaps remain historical or broad backlog where they conflict.

## Product boundary

AppCare provides **Scan -> Fix -> Backup -> Monitor -> Recover** for supported websites and applications.

Current supported-profile build target:

- Linux-hosted PHP 8.x;
- Nginx or Apache;
- MariaDB/MySQL;
- direct-filesystem or Git-based deployment after normalization and exact binding.

First real acceptance target: `video.slabfranchise.com`.

Current implementation exclusions:

```text
WORDPRESS=FUTURE_BRANCH
WOOCOMMERCE=FUTURE_BRANCH
```

Do not implement, test, or promote WordPress/WooCommerce capability without separate owner authorization.

## Mandatory maturity labels

Every component report must use exactly one:

- `DOCUMENTED`
- `COMPONENT_IMPLEMENTED`
- `RUNTIME_INTEGRATED`
- `LIVE_VERIFIED`
- `SERVICE_READY`

Do not use `IMPLEMENTED` alone.

## Shared physical server, isolated applications

For every server, DNS, deployment, database, worker, backup, or service action, explicitly state:

```text
TARGET=AppCare
```

For AppCare work, do not reuse or modify the WordPress Security product's repository, DB/schema/user, secrets, queues, services, writable volumes, deploy credentials, service accounts, API routes, backup namespace, logs, or staging paths.

AppCare must keep its own application path, runtime identity, deployment path, DB, workers, secrets, logs, provider credentials, backup namespace, and environment boundaries.

No customer production write is authorized by ordinary engineering work.

## Multi-model engineering roles

### GPT-5.6 Luna Max — coordinator

Luna owns dependency planning, architecture integration, task packets, acceptance criteria, actual-diff review, trust-boundary approvals, readiness decisions, and final owner-facing reports.

Luna must produce a dependency-based plan before delegation.

### GPT-5.3 Spark — primary coder

Spark implements bounded Luna-approved work packets and tests. Spark cannot set architecture, approve its own work, promote readiness, merge, or authorize production.

### GPT-5.6 Terra — independent architecture/security challenger

Terra reviews designs and security-sensitive diffs for cross-tenant access, credential exposure, injection, data loss, recovery gaps, privilege, and unsafe rollback. Terra does not merge or self-approve authored fixes.

### Codex Security

Security-relevant PRs require the applicable Codex Security review. Repaired attack paths require verify-fix where applicable.

### Auxiliary OpenCode/DeepSeek/Qwen workers

Use `WORKER_PROTOCOL.md`. Auxiliary workers are optional and bounded. They cannot replace Luna review, Terra challenge, or Codex Security.

## Current 12-phase queue

1. Blueprint and enforcement
2. Credential custody and SSH onboarding
3. Live connect, inventory, immutable baseline
4. Streaming filesystem backup
5. Live MariaDB backup/restore
6. B2, Glacier, complete application restore
7. Live scanning and test discovery
8. Brownfield normalization, staging, remediation
9. Deployment, migration safety, verification, rollback
10. Monitoring, scheduler, alerting, reporting
11. Operator/commercial/offboarding/AppCare DR
12. Real-target acceptance and S01-S30 launch decision

No readiness state may bypass a failed predecessor.

## Required engineering loop

```text
Saveruflo preflight when available
→ Graphify query/update
→ repository-native Spec Kit workflow
→ Luna dependency plan
→ Terra design challenge
→ Spark or bounded worker implementation
→ Luna actual-diff review
→ Terra security review
→ deterministic/negative/adversarial tests
→ dependency and secret/public-safety scans
→ Codex Security
→ exact-head CI
→ protected merge
→ evidence and maturity update
```

If a tool is unavailable, record `UNAVAILABLE`; do not fabricate `PASS`.

## Production safety

Never perform a production write without:

1. authoritative evidence;
2. mandatory pre-change backup;
3. B2 remote readback;
4. verified isolated restore;
5. staging/reproduction;
6. regression/security validation;
7. exact artifact/revision binding;
8. exact application-scoped approval;
9. production verification;
10. rollback readiness;
11. monitoring.

No unrestricted model-controlled root SSH. No arbitrary model-generated shell, SQL, scanner, or deployment execution.

## Stop conditions

Do not stop for ordinary implementation decisions, bugs, failed tests, missing adapters, dependency issues, skill defects, legacy layouts, missing Git, or missing health endpoints that can be engineered safely.

Stop for genuine owner-only boundaries: new account/credential authorization not covered by existing approval, DNS, payment/billing account action, legal decision, irreversible/high-risk production data action, or first real production deployment authorization.

## Repository safety

- Never commit credentials or customer data.
- Keep customer vulnerability evidence out of this public repository.
- Prefer small reviewable PRs.
- Do not widen current stack scope.
- Do not touch WordPress/WooCommerce current implementation.
- Do not report fixture/reference evidence as live support.
