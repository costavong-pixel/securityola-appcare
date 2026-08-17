# SecurityOla AppCare Private Beta Engineering Loop

Master queue: GitHub issue #12.

## Server/runtime isolation gate

AppCare is developed and deployed independently from the SecurityOla WordPress plugin/backend.

Before BETA-01 starts, Codex must verify and record that AppCare has its own server/runtime path, service user, secrets, database, workers, logs, provider credentials, backup namespace, and environment boundaries. No WordPress production resource may be reused or modified.

Inside AppCare keep `development → staging → production` isolated; development must not receive production credentials.

## Ordered beta gates

- [ ] BETA-00 — bootstrap Codex, Saveruflo, Spec Kit, Graphify, audited skills, CI, and AppCare/WordPress runtime isolation
- [x] BETA-01 — control plane, tenancy, audit trail
- [x] BETA-02 — read-only GitHub/Vercel/Supabase connectors (merged through protected main at `4eae0682f6e421b65f7ff75c521b331ccd164de1`)
- [ ] BETA-03 — security scanning and normalized evidence-backed findings
- [ ] BETA-04 — B2 immutable backup, Glacier archive, restore rehearsal
- [ ] BETA-05 — LangGraph durable scan-to-recovery workflow
- [ ] BETA-06 — isolated remediation, tests, PR, preview deployment
- [ ] BETA-07 — controlled production deploy, verification, automatic rollback
- [ ] BETA-08 — monitoring, backup health, alerts, reports, service-cost tracking
- [ ] BETA-09 — dashboard + SecurityOla beta website + Impeccable QA
- [ ] BETA-10 — adversarial drills, full security review, release decision

## Engineering loop

For the current open beta issue:

1. `/saveruflo` read-only preflight.
2. `/graphify . --update` and query affected architecture/blast radius.
3. Use `/speckit` to specify/plan the bounded work when needed.
4. Codex implements the smallest safe task.
5. Run deterministic unit/integration/static tests.
6. Run security and failure/pressure tests appropriate to the change.
7. Run independent Codex final review through the current agent/app/cloud session or GitHub Codex review; Codex CLI is optional.
8. Fix failures and repeat steps 4–7 until green.
9. Require exact-head CI.
10. Save the Saveruflo checkpoint/evidence.
11. Update Graphify and re-check impact.
12. Close the issue only when every acceptance criterion passes.
13. Pick the next open beta issue and repeat.

## Third-party skill loop

`discover → inspect → sandbox → pressure-test → patch/debug → retest → pin → use`

If a skill cannot be made safe and maintainable, drop it and replace it.

## Current BETA-03 state

The isolated AppCare workspace has started BETA-03 from protected main at
`4eae0682f6e421b65f7ff75c521b331ccd164de1`. The approved foundation scope is
scanner contracts, deterministic evidence, source/secret/dependency adapter
boundaries, normalized findings, deduplication, distinct scanner failures,
tenant/target enforcement, and seeded vulnerability/false-positive fixtures.
No remediation writes, live provider authorization, production access, or
WordPress resource is in scope.

## Production rule

No customer production write without:

`evidence → valid backup → staging/isolation → tests → approval/policy gate → deploy → production verification → rollback ready`

## Stop conditions

Do not stop for ordinary implementation decisions, bugs, failed tests, dependency problems, skill bugs, or design questions that can be resolved from the product requirements.

Stop only for a genuine external blocker such as unavailable owner-controlled credentials/account verification, required domain/DNS authorization, or an unsafe/ambiguous production authorization boundary.

## Beta done

Private beta is complete only when BETA-10 passes and records:

- exact release commit
- exact test/CI evidence
- tenant-isolation result
- AppCare/WordPress runtime-isolation evidence
- backup + restore evidence
- production-failure rollback evidence
- supported-stack/known-limitations document
- emergency-stop/revocation drill
- measured per-app operating cost
