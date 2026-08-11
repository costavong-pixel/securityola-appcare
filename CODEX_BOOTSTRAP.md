# Codex Bootstrap Assignment — SecurityOla AppCare

## Objective

Prepare the complete SecurityOla AppCare development environment and repository so the BETA-00 → BETA-10 loop can run with minimal owner involvement.

Codex is the coordinator. OpenCode + DeepSeek V4 Flash is the bounded low-cost worker. Codex CLI is the independent final gate.

## Execute this assignment end-to-end

### 1. Server and repository isolation
- Clone/work only in `costavong-pixel/securityola-appcare`.
- Use the owner-provided AppCare server from server-local configuration.
- Create a dedicated AppCare system user, application directory, runtime, logs, database, worker/process namespace, and staging/development paths.
- Do not reuse or touch the WordPress SecurityOla plugin/backend runtime, database, secrets, queues, deployment paths, or credentials.
- Keep development, staging, and production credentials isolated.

### 2. Bootstrap the engineering tools
Discover the current official upstream/source for each tool before installation. Prefer official/vendor sources over registries and mirrors.

Required:
- Codex CLI
- `/saveruflo`
- Spec Kit (`/speckit` workflow)
- Graphify for persistent code mapping/impact review
- LangGraph tooling/dependency when the application scaffold reaches the workflow phase
- `/impeccable` for website/dashboard UX QA
- OpenCode pinned initially to the reviewed version recorded in `WORKER_PROTOCOL.md`
- DeepSeek V4 Flash as the OpenCode worker model

Do not commit API keys or credentials. Configure them only in machine-local credential stores/environment.

### 3. Discover and audit the application/security skills
Do not blindly install any third-party skill. For every candidate use:

`discover → source verification → inspect → dependency/permission review → sandbox → pressure-test → patch/debug → retest → pin exact revision → accept`

If it cannot be made safe and maintainable, **drop it** and replace it or implement the capability locally.

Required capability areas:

#### Security testing
- Codex Security repository/diff/security-validation workflows where available.
- A general application security review/scanning skill for source and configuration analysis.
- Secret scanning and dependency vulnerability scanning.
- Failure/silent-error detection and test analysis skills where useful.

#### Supabase
- Prefer Supabase-maintained agent skills or official documentation-derived workflows.
- Required coverage: RLS, Auth, Storage, service-role exposure, database privileges, migrations, and configuration checks.

#### Vercel
- Inspect the official Vercel agent/deployment skills as raw material.
- Preview deployment must be sandboxed and pressure-tested.
- Patch known/observed defects before use.
- AppCare needs preview → validate → promote → verify → rollback; if the upstream skill cannot support this safely, build our own wrapper using official Vercel APIs/CLI.

#### Backup/restore
Evaluate the previously identified `database-backup-restore` and `cloud-backup` skills as raw material.
- retention
- checksums/integrity
- restore rehearsal
- RPO/RTO evidence
- failure handling
- S3-compatible lifecycle
- B2 Object Lock / immutable backups
- AWS S3 Glacier Deep Archive

Pressure-test at minimum:
- interrupted upload
- corrupted backup
- checksum mismatch
- expired credentials
- duplicate jobs
- partial restore
- failed restore
- retention edge cases
- deletion attempt against immutable backup

#### Monitoring/reliability
Find or build skills/workflows for:
- uptime/critical-flow checks
- backup freshness/integrity
- deployment-change detection
- dependency/secret/config drift
- alert deduplication
- failure injection

### 4. OpenCode/DeepSeek worker setup
Follow `WORKER_PROTOCOL.md` and `.opencode/agents/deepseek-worker.md`.

- Verify OpenCode pin before use.
- Configure DeepSeek credentials machine-locally.
- Smoke-test the worker on a harmless bounded repository task.
- Prove it cannot access external directories, SSH/production, credentials, git push/merge, or deployment commands.
- Use small `.codex/tasks/` packets instead of sending full project history.
- Maximum three worker repair passes on the same defect; then Codex takes over.

### 5. Saveruflo
- Run as a read-only preflight before implementation.
- Confirm repository identity, branch, dirty state, instructions, tests, deployment boundary, and unresolved risk.
- Preserve the bounded-builder/reviewer/checkpoint model already defined for this project.
- Save a checkpoint after every bounded task/phase.
- Do not store credentials/customer data in checkpoints.

### 6. Spec Kit
Initialize the project specification workflow.

Project constitution must lock:
- security before speed
- deterministic evidence before AI claims
- least privilege
- no secrets in repo/logs/prompts/checkpoints
- reversible production changes
- backup before production write
- staging/isolation before production
- exact test evidence before merge/release
- tenant isolation
- AppCare/WordPress runtime separation
- third-party skills are untrusted until audited
- Codex owns final security/architecture/release decisions

Use the Spec Kit flow for each beta feature as appropriate:
`constitution → specify → clarify → plan → checklist → tasks → analyze → implement`

### 7. Graphify
- Build the initial AppCare code graph.
- Keep generated graph/cache artifacts local unless there is a specific reason to version a small source artifact.
- Query it before structural changes and after them for blast-radius/architecture review.
- Update incrementally after meaningful code structure changes.

### 8. CI and local quality gates
Create a green baseline with at least:
- formatting/lint
- type checks
- unit tests
- integration-test framework
- secret scanning
- dependency/security scanning
- exact-head GitHub Actions verification
- test/failure evidence suitable for Codex review

Add stronger gates as the stack is implemented.

### 9. Codex CLI final gate
Before closing BETA-00:
- inspect the complete diff directly
- run the deterministic test suite
- verify the DeepSeek worker restrictions
- verify no secret/server/customer data is committed
- run applicable security review
- verify all accepted third-party skills are pinned and documented
- verify rejected skills are recorded with reason

Do not accept another agent's summary as proof.

### 10. Deliverables for BETA-00
Commit durable, non-secret artifacts documenting:
- installed/audited tool versions and exact source revisions
- accepted/patched/dropped skills
- patches we own for third-party skills
- CI/test commands
- Saveruflo checkpoint
- Spec Kit constitution/bootstrap
- Graphify bootstrap instructions
- DeepSeek worker smoke/permission-test evidence
- remaining external blockers, if any

Then close GitHub issue #1 only when every acceptance criterion passes and continue automatically to issue #2.

## Continuous loop

After BETA-00:

`Saveruflo preflight → Graphify impact → Spec Kit scope → Codex task packet → DeepSeek bounded work where safe → Codex review/sensitive implementation → deterministic tests → pressure/security tests → Codex CLI final review → exact-head CI → Saveruflo checkpoint → Graphify update → close current issue → next BETA issue`

Do not stop for ordinary bugs, dependency issues, skill defects, test failures, or implementation choices. Fix/replace/retest and continue.

Stop only for a genuine external owner-controlled blocker such as unavailable provider credentials/KYC/domain authorization or ambiguous authorization to touch a real customer production system.
