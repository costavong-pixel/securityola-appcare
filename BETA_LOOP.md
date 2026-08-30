# SecurityOla AppCare Engineering and Beta Readiness Loop

## Mandatory interpretation

Historical BETA-00 through BETA-10 proved the AppCare **core platform**. It did not prove customer onboarding or a managed service.

Authoritative current governance:

- `APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md`
- `docs/governance/APPCARE_CURRENT_SCOPE.json`
- `.specify/memory/constitution.md`
- `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`
- `docs/security/PRE_BETA_SECURITY_GATE.md`
- `specs/013-product-readiness/`

The previous broad `PRIVATE_BETA_READY=YES` interpretation is revoked.

Current readiness:

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

## Current supported profile

```text
Linux + PHP 8.x + Nginx/Apache + MariaDB/MySQL
```

First real acceptance target: `video.slabfranchise.com`.

WordPress and WooCommerce are future branches and current implementation is prohibited without separate owner authorization.

## Current 12-phase dependency sequence

1. `P01` binding blueprint and enforcement;
2. `P02` credential custody and SSH onboarding;
3. `P03` live CONNECT, INVENTORY, immutable baseline;
4. `P04` streaming filesystem backup;
5. `P05` live MariaDB backup and isolated DB restore;
6. `P06` B2, Glacier, and complete application restore;
7. `P07` live scanning and test discovery;
8. `P08` brownfield normalization, staging, remediation;
9. `P09` deployment, migration safety, verification, rollback;
10. `P10` monitoring, scheduler, alerting, reporting;
11. `P11` operator/commercial/offboarding/AppCare DR;
12. `P12` real-target acceptance and exact-release S01-S30 security decision.

Independent later research may run in parallel, but no readiness level may bypass a failed phase dependency.

## Mandatory maturity labels

```text
DOCUMENTED
COMPONENT_IMPLEMENTED
RUNTIME_INTEGRATED
LIVE_VERIFIED
SERVICE_READY
```

Do not use `IMPLEMENTED` alone.

## Engineering loop

1. Verify protected main and open PRs.
2. Run Saveruflo preflight when available.
3. Update/query Graphify.
4. Run the repository-native Spec Kit workflow.
5. Luna publishes a dependency-based plan and bounded task packet.
6. Terra challenges security/architecture.
7. Spark or an approved bounded worker implements.
8. Luna reads the actual diff.
9. Terra reads security-sensitive actual diff.
10. Run deterministic, negative, failure, and adversarial tests.
11. Run dependency, secret, public-safety, and worker-policy gates.
12. Run Codex Security and verify-fix when applicable.
13. Require exact-head CI.
14. Protected merge.
15. Update evidence, capability, maturity, and phase status.
16. Continue only if the hard exit gate permits.

## Production rule

No customer production write without:

```text
evidence
→ mandatory pre-change backup
→ B2 readback
→ verified isolated restore
→ staging
→ tests/security
→ exact preproduction receipt
→ exact application approval
→ deploy
→ production verification
→ rollback ready
→ monitoring
```

Every private-beta production change requires explicit owner/customer approval.

Global `LIVE_CUSTOMER_PRODUCTION_ENABLED` remains `NO`.

## Stop conditions

Do not stop for ordinary engineering work. Stop for new owner-controlled account/credential authorization, DNS, billing/payment account action, legal decision, irreversible/high-risk production data action, or first production deployment authorization.

## Beta completion

Customer beta readiness requires all applicable phase hard exits, one real internal application lifecycle, exact-release S01-S30 security approval, safe owner-authorized production, monitoring, alerts, reports, credential rotation, offboarding, restart durability, and real cost measurement.
