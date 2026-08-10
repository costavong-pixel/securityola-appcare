# Development Workflow

## Required workflow tools

- `/speckit` — specification-driven development
- `/saveruflo` — bounded repository preflight/checkpoints/review workflow
- LangGraph — resumable long-running operational workflows
- `/impeccable` — website/portal design QA after functionality works

## Third-party skill policy

Candidate skill sources may include official vendor repositories, GitHub skill collections, and discovery registries.

Every imported skill must pass:

1. source and dependency inspection
2. permission and secret-handling review
3. disposable sandbox run
4. failure and pressure testing
5. patch/debug if necessary
6. regression retest
7. exact commit/version pinning
8. periodic re-audit

If a skill cannot be fixed safely, drop it.

## Candidate skill areas

- security testing
- Supabase security
- Vercel deployment/rollback
- database backup/restore
- S3/B2/Glacier lifecycle
- monitoring
- failure-injection testing
