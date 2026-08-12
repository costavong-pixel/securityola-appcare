# SecurityOla AppCare Agent Instructions

## Product boundary

SecurityOla AppCare: **Scan → Fix → Backup → Monitor → Recover** for supported AI-built web applications.

Initial supported stack: GitHub + Vercel + Supabase + Lovable-generated/similar apps.

## Shared physical server, isolated applications

SecurityOla AppCare and the SecurityOla WordPress plugin/backend share the same physical SecurityOla server, but they are separate applications and must remain isolated at the application/runtime level.

For every server, DNS, deployment, database, worker, backup, or service action, explicitly state the target application before acting:
- `TARGET=AppCare`, or
- `TARGET=WordPress Security`

For AppCare work, do not reuse or modify the WordPress product's:
- application/repository directory
- database/schema/user
- `.env` or secrets
- queues/workers/services
- writable volumes
- deploy credentials
- service accounts
- production API routes
- backup credentials/namespaces
- logs or staging paths

AppCare must have its own application path, runtime/service identity, deployment path, database, workers, secrets, logs, provider credentials, backup namespace, and staging/development paths on the shared server.

Inside AppCare, keep `development → staging → production` isolated. Development jobs must never receive production credentials.

Do not touch the WordPress repositories or runtime unless a future explicit integration specification authorizes it.

## Public product routing

SecurityOla remains one brand with two products. Marketing does not require separate product subdomains.

Preferred public structure:
- `securityola.com` — SecurityOla homepage presenting both products
- `securityola.com/appcare` — AppCare marketing/product page
- `securityola.com/wordpress` — WordPress Security marketing/product page
- `app.securityola.com` — AppCare customer dashboard/login when needed
- `api.securityola.com` — API entrypoint; AppCare and WordPress API routes/services must remain technically isolated behind it

Do not create additional product subdomains unless there is a concrete technical or product requirement.

## Cost-aware engineering roles

Use `WORKER_PROTOCOL.md` as the delegation contract.

### Codex owns
- architecture and product decisions
- security boundaries and threat-model decisions
- task decomposition and acceptance criteria
- dependency and third-party skill approval
- production/deployment logic
- review of every worker diff
- final merge/release decisions

### OpenCode + DeepSeek V4 Flash is the bounded cheap worker
Delegate clearly specified, reversible repository work when it reduces Codex token usage, including scaffolding, repetitive implementation, tests, docs, mechanical refactors, and first-pass fixes after Codex identifies the problem.

Do **not** delegate architecture, security-policy decisions, production access, deployment authorization, credential handling, third-party skill acceptance, or final review.

For a delegated task, Codex creates a minimal packet under `.codex/tasks/` and runs `scripts/deepseek-worker.sh <task-file>`. Inspect the resulting diff and test evidence directly; never trust the worker summary as proof.

Maximum three DeepSeek repair passes for the same defect. After three failed passes, Codex takes over root-cause/fix work.

### Codex CLI final gate
Before closing a beta issue or merging/releasing its changes, use Codex CLI for an independent final review of the complete diff and deterministic test evidence. Security-sensitive changes also require the applicable Codex Security review/validation workflow.

## Closed-loop beta execution

Primary work queue: GitHub issue **#12 `[BETA-MASTER]`** and its ordered BETA-00 through BETA-10 issues.

For every issue, repeat this loop until its acceptance criteria pass:

`/saveruflo preflight → /graphify . --update/query → /speckit task/spec as needed → Codex scopes work → OpenCode/DeepSeek executes bounded cheap tasks where safe → Codex implements sensitive/remaining work → deterministic tests → security/failure pressure tests → independent Codex review → Codex CLI final gate → exact-head CI → Saveruflo checkpoint → Graphify update/impact review → close issue → next open beta issue`

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

<!-- SPECKIT START -->
For additional context about technologies to be used, project structure,
shell commands, and other important information, read the current plan
<!-- SPECKIT END -->
