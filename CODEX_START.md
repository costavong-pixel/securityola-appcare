# Codex Start — SecurityOla AppCare

## Mission

Build SecurityOla AppCare to private beta by executing GitHub issue #12 `[BETA-MASTER]` in order until BETA-10 passes.

Do not wait for the owner between normal engineering decisions. Follow `AGENTS.md`, `BETA_LOOP.md`, `PRODUCT.md`, `ARCHITECTURE.md`, `DEVELOPMENT.md`, and `SECURITY.md` as the source of truth.

## Environment boundary

Dedicated SecurityOla AppCare server:

`51.161.32.138`

AppCare must remain isolated from the WordPress SecurityOla/plugin development environment.

Do not touch, deploy to, restart, migrate, or reuse:
- the WordPress plugin repository/runtime,
- the WordPress plugin database,
- WordPress plugin secrets,
- WordPress plugin workers/services,
- WordPress plugin deployment paths,
unless a later explicitly approved integration task says otherwise.

AppCare must have its own:
- application directory,
- system user/service identity,
- virtualenv/container/runtime,
- PostgreSQL database/schema,
- environment/secrets,
- ports/services,
- logs,
- workers/queues,
- backup configuration,
- deployment/staging paths.

Development, staging, and production must also be isolated from each other. Development must not hold production credentials.

## Start task

Start with GitHub issue #1 `BETA-00`.

For each beta issue, run:

`/saveruflo preflight → /graphify . --update/query → /speckit task/spec as needed → implement smallest safe task → deterministic tests → security/failure pressure tests → independent review → exact-head CI → Saveruflo checkpoint → Graphify update/impact review → close issue → next issue`

If anything fails, remain on that issue, diagnose, patch, retest, and continue. Do not skip ahead.

## Third-party skills

For every candidate skill:

`discover → inspect → sandbox → pressure-test → patch/debug → retest → pin → use`

If it cannot be made safe, maintainable, and testable, drop it and replace/build the capability.

Initial skill areas:
- security testing
- Supabase security
- Vercel preview/deployment/rollback
- database backup/restore
- B2/S3/Glacier storage and lifecycle
- monitoring/failure injection

## Production safety

No customer production write unless all are true:

1. deterministic evidence exists,
2. valid backup/snapshot exists,
3. issue/fix is reproduced and tested in staging/isolation,
4. automated validation passes,
5. policy/approval gate permits the action,
6. rollback target is recorded,
7. post-deploy production verification runs,
8. failed verification triggers rollback.

No unrestricted AI-controlled root shell. No arbitrary model-generated production shell execution.

## Stop conditions

Stop only for a genuine external blocker that cannot be solved from the repo/server, such as:
- missing owner-controlled provider credential/account approval,
- domain/DNS ownership action,
- payment/KYC requirement,
- ambiguous authorization to touch a real customer production system.

Normal bugs, failed tests, dependency problems, skill defects, architecture decisions inside the locked product scope, and implementation choices are not stop conditions.

## Private beta complete

Do not declare beta complete until BETA-10 records:
- exact release commit,
- exact CI/test evidence,
- tenant-isolation pass,
- backup + successful restore evidence,
- failed-production-change automatic rollback evidence,
- emergency stop/revocation evidence,
- supported-stack and known limitations,
- measured per-app operating cost.
