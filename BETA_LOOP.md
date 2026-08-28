# SecurityOla AppCare Engineering and Beta Readiness Loop

## Mandatory interpretation

The historical BETA-00 through BETA-10 program proved the AppCare **core platform**. It must not be interpreted as proof that AppCare can onboard or operate a real customer application.

Authoritative current governance:

- `.specify/memory/constitution.md`
- `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`
- `docs/security/PRE_BETA_SECURITY_GATE.md`
- `specs/013-product-readiness/`

The previous broad `PRIVATE_BETA_READY=YES` interpretation is revoked.

Current readiness at adoption:

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

## Server/runtime isolation gate

AppCare is developed and deployed independently from the SecurityOla WordPress plugin/backend.

AppCare must retain its own runtime/service identity, repository/deployment path, secrets, database, workers, logs, provider credentials, backup namespace, and environment boundaries. No WordPress production resource may be reused or modified.

Inside AppCare keep `development -> staging -> production` isolated; development must not receive production credentials.

## Historical core-platform beta

BETA-00 through BETA-10 established the control plane, tenant/audit boundaries, connector contracts, scanning foundation, backup/recovery domain, durable workflow, remediation, production control, monitoring/reporting, dashboard foundation, adversarial release evidence, filesystem backup boundary, and provider-neutral preproduction evidence.

Those results remain valid core-platform evidence and must not be deleted or rewritten.

Historical fixture/reference acceptance is not live customer acceptance.

## Current mandatory customer-readiness sequence

The new sequence is:

1. `013-product-readiness`
2. `014-generic-linux-ssh`
3. `015-database-adapters`
4. `016-live-scanning`
5. `017-brownfield-normalization`
6. `018-customer-staging-deploy`
7. `019-live-monitoring-scheduler`
8. `020-wordpress-profile`
9. `021-woocommerce-profile`
10. `022-live-initial-stack-connectors`
11. `023-real-target-private-beta-gate`

The complete A-Z gap register and implementation waves are mandatory in `docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md`.

## Engineering loop

For every current issue/PR:

1. `/saveruflo` read-only preflight.
2. `/graphify . --update` and query affected architecture/blast radius.
3. Run the relevant Spec Kit constitution/specify/clarify/plan/checklist/tasks/analyze/converge workflow.
4. GPT-5.6 Luna Max coordinator scopes the smallest safe task.
5. A bounded worker implements; worker cannot self-approve.
6. Luna reads the actual diff and security-critical functions.
7. Run deterministic unit/integration/static tests.
8. Run failure/negative/security tests appropriate to the change.
9. Run dependency and secret/public-safety gates.
10. Run Codex Security diff scan; use verify-fix for repaired attack paths where applicable.
11. Fix failures/findings and repeat until green.
12. Require exact-head GitHub CI.
13. Save the Saveruflo checkpoint/evidence.
14. Update Graphify and re-check impact.
15. Protected merge only after coordinator approval.
16. Update the capability/readiness matrix after merge.

Before beta launch, also run the complete repository security review required by `docs/security/PRE_BETA_SECURITY_GATE.md` against the exact release candidate.

## Production rule

No customer production write without:

`evidence -> valid backup -> isolated restore/reproduction -> tests -> security validation -> authoritative preproduction evidence -> exact application-scoped approval -> deploy -> production verification -> rollback ready -> monitoring`

Global `LIVE_CUSTOMER_PRODUCTION_ENABLED` remains `NO`.

## Stop conditions

Do not stop for ordinary implementation decisions, bugs, failed tests, dependency problems, skill bugs, missing Git, missing health endpoints, legacy filesystem layouts, or missing adapters that can be engineered safely.

Stop for genuine owner-controlled or high-risk boundaries such as new customer/account authorization, DNS changes, payment/billing account actions, legal decisions, the first real customer production authorization, or irreversible/high-risk production data migration.

If a production/data boundary is genuinely ambiguous, stop and ask the owner for clarification.

## Customer beta done

Customer private-beta readiness is not achieved merely because Spec 013–023 code exists.

At minimum:

- generic required stack capability matrix passes
- mandatory pre-beta security gate passes against exact head
- one real target completes connect/inventory/revision/backup/remote-readback/restore/scan/remediation/test/staging/preproduction
- exact owner authorization is obtained for the first production mutation
- controlled production deployment and verification pass
- safe rollback proof passes
- live monitoring/alerting/reporting run
- restart durability passes
- real operating cost is measured

Only then may the corresponding layered readiness states advance.
