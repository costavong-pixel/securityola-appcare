# SecurityOla AppCare Agent Instructions

## Product boundary

SecurityOla AppCare: **Scan → Fix → Backup → Monitor → Recover** for supported AI-built web applications.

Initial supported stack: GitHub + Vercel + Supabase + Lovable-generated/similar apps.

## Required development workflow

- Use `/saveruflo` as a bounded read-only preflight before implementation work.
- Use `/speckit` for feature specification, clarification, planning, tasks, consistency analysis, and implementation.
- Use LangGraph only where durable/resumable workflow orchestration is justified.
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
