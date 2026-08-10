# SecurityOla AppCare Agent Instructions

## Product boundary

SecurityOla AppCare: **Scan → Fix → Backup → Monitor → Recover** for supported AI-built web applications.

Initial supported stack: GitHub + Vercel + Supabase + Lovable-generated/similar apps.

## Hard server/runtime boundary

AppCare is isolated from the SecurityOla WordPress plugin/backend that is still under development.

Do not reuse or modify the WordPress product's:
- server/application runtime
- database/schema
- `.env` or secrets
- queues/workers
- writable volumes
- deploy/SSH credentials
- service accounts
- production API routes
- backup credentials

AppCare uses its own server/runtime, deployment path, database, workers, secrets, logs, provider credentials, backup namespace, and hostnames.

Inside AppCare, keep `development → staging → production` isolated. Development jobs must never receive production credentials.

Do not touch the WordPress repositories or production runtime unless a future explicit integration specification authorizes it.

## Closed-loop beta execution

Primary work queue: GitHub issue **#12 `[BETA-MASTER]`** and its ordered BETA-00 through BETA-10 issues.

For every issue, repeat this loop until its acceptance criteria pass:

`/saveruflo preflight → /graphify . --update/query → /speckit task/spec as needed → Codex implement → deterministic tests → security/failure pressure tests → independent review → exact-head CI → Saveruflo checkpoint → Graphify update/impact review → close issue → next open beta issue`

If validation fails, remain on the same issue, diagnose, patch, and retest. Do not skip ahead.

Only stop for a genuine external blocker that cannot be resolved from repository/server context, such as missing owner-controlled credentials/KYC/domain authorization or an unsafe ambiguous production authorization boundary. Normal bugs, failed tests, dependency problems, skill bugs, and implementation choices are not stop conditions.

Private beta is complete only when BETA-10 passes and the exact release commit/test evidence is recorded.

## Required development workflow

- Use `/saveruflo` as a bounded read-only preflight before implementation work and save a checkpoint after each bounded task/phase.
- Use `/speckit` for feature specification, clarification, planning, tasks, consistency analysis, and implementation.
- Install/use Graphify with Codex to maintain a persistent code graph; query it for architecture/impact and update it after meaningful structural changes.
- Use LangGraph only where durable/resumable workflow orchestration is justified: scan → backup gate → findings → remediation → approval → deploy → verify/rollback → monitor/report.
- Use `/impeccable` after functional flows work for website/portal UX and visual QA.

## Production safety

Never perform a production write unless the workflow has:

1. preserved evidence,
2. created a valid backup/snapshot,
3. reproduced/tested in staging or isolation,
4. passed relevant automated validation,
5. a defined rollback path,
6. production verification after deployment.

No unrestricted model-controlled root SSH. No arbitrary model-generated shell execution in production.

## Third-party skills

Do not trust third-party skills by default.

**Inspect → sandbox → pressure-test → patch/debug → retest → pin → use.**

Drop any skill that cannot be made safe, maintainable, and testable.

## Repository safety

- Never commit credentials or customer data.
- Keep customer-specific vulnerability evidence out of this public repository.
- Prefer small, reviewable changes with exact test evidence.
- Do not expand product scope or add new product names without an explicit product decision.
