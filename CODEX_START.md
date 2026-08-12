# Codex Start — SecurityOla AppCare

## Mission

Build SecurityOla AppCare to private beta by executing GitHub issue #12 `[BETA-MASTER]` in order until BETA-10 passes.

Do not wait for the owner between normal engineering decisions. Follow `AGENTS.md`, `WORKER_PROTOCOL.md`, `BETA_LOOP.md`, `PRODUCT.md`, `ARCHITECTURE.md`, `DEVELOPMENT.md`, and `SECURITY.md` as the source of truth.

## Environment boundary

The AppCare server address is owner-controlled server-local configuration. Do not commit the IP/hostname or production credentials into this public repository.

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

## Cost-aware worker bootstrap

Codex is the coordinator. OpenCode + DeepSeek V4 Flash is the bounded low-cost implementation worker. Codex CLI is the final review gate.

On the AppCare development environment:

1. Check `opencode --version`.
2. The audited bootstrap pin is **OpenCode 1.18.16**. `scripts/deepseek-worker.sh` refuses a different version until Codex intentionally reviews and updates the pin.
3. If OpenCode is missing, install the official `anomalyco/opencode` release matching the pin; verify the installed version before continuing.
4. Configure the DeepSeek credential through OpenCode `/connect` on that machine. Credentials remain in OpenCode's user-local auth store and must never be committed.
5. Worker model is **DeepSeek V4 Flash** (`opencode/deepseek-v4-flash-free`) through the project agent `.opencode/agents/deepseek-worker.md`; this exact provider/model ID must be rechecked against the installed catalog before use.
6. Smoke-test the worker on a harmless read/edit/test task before delegating implementation.

Delegated tasks use:

```bash
scripts/deepseek-worker.sh .codex/tasks/<task>.md
```

Do not use the DeepSeek worker for architecture, security-policy decisions, production/deployment authorization, credentials, third-party skill acceptance, or final review.

Maximum three DeepSeek repair passes on the same defect; then Codex takes over.

Before an issue is closed or a change is merged/released, Codex CLI independently reviews the complete diff and deterministic test evidence. Security-sensitive work also runs the applicable Codex Security scan/validation flow.

## Start task

Start with GitHub issue #1 `BETA-00`.

For each beta issue, run:

`/saveruflo preflight → /graphify . --update/query → /speckit task/spec as needed → Codex scopes → DeepSeek/OpenCode handles bounded cheap work → Codex reviews/handles sensitive work → deterministic tests → security/failure pressure tests → independent review → Codex CLI final gate → exact-head CI → Saveruflo checkpoint → Graphify update/impact review → close issue → next issue`

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
