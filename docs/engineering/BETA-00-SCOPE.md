# BETA-00 bootstrap scope

Status: blocked at the live DeepSeek worker smoke gate; the exact OpenCode model is reachable, but the provider returned rate-limit responses before a complete bounded smoke could finish. Issue #1 remains open until every gate is independently verified.

## Scope locked for this phase

- Product target: SecurityOla AppCare only.
- BETA-00 establishes the engineering loop, specification workflow, code graph, worker restrictions, CI/security baseline, and sanitized checkpoints.
- Application control-plane behavior, connectors, databases, LangGraph orchestration, backup providers, deployment, dashboard, and customer distribution remain ordered work for BETA-01 through BETA-10.
- No customer production system, DNS record, WordPress runtime, or production credential is touched by this phase.

## Completed evidence

- Dedicated checkout verified against public repository `costavong-pixel/securityola-appcare`; the reviewed work is on the local `codex/beta-00-bootstrap` branch and no remote push was made.
- Repository instructions and issues #1 through #12 were read before edits.
- Saveruflo selected `FULL`; its installed self-test suite passed 13/13.
- Graphify post-change update produced 395 nodes and 456 raw edges. Diagnosis found 25 external/import-name dangling endpoints, with no missing endpoint edges, self-loops, or same-endpoint edge collapse; the dangling set is limited to import-name relations rather than AppCare file endpoints.
- Spec Kit 0.11.3 bundled templates, Codex skills, workflow metadata, and constitution were initialized locally.
- The shared-server audit was read-only until the explicit isolation step. Existing WordPress and DockPanel resources were categorized as do-not-touch; BETA-00 then created only an empty root-controlled AppCare service identity and namespace, with no runtime or database.
- OpenCode 1.18.16 was installed from the official upstream package and version-checked. The installed catalog exposes DeepSeek V4 Flash as `opencode/deepseek-v4-flash-free`; the launcher and policy assertions were updated to that exact reviewed ID, with no credential value inspected.
- A direct no-tool request reached the OpenCode DeepSeek provider and returned `Rate limit exceeded`, proving provider/model resolution but not a passing worker smoke.
- The bounded smoke ran in disposable Git worktrees. The first run correctly rejected OpenCode-managed `.opencode/node_modules` as unscoped local state; the scope verifier was repaired to ignore only that generated cache, with a regression test. The second launcher run reached the worker but timed out during provider retries; the worktree, processes, and temporary directory were cleaned up and the coordinator checkout remained unchanged.
- Permission-denial evidence passed: an external task path was rejected, a credential-bearing task packet was rejected, and the worker was denied the unallowlisted `git diff --check` command while the explicitly allowed `git diff --no-ext-diff --check` succeeded.
- The repository-scoped Codex Security standard scan finalized with no reportable findings; coverage explicitly defers the unimplemented runtime/connectors and the blocked live worker smoke.
- Final deterministic local evidence: 14 tests passed, strict typing passed for 9 source files, public-safety and worker-policy checks passed, the hash-locked development environment validated, and `pip-audit` reported no known vulnerabilities. Independent review must be refreshed for the current head before publication.

## Remaining BETA-00 gates

1. Obtain a completed bounded smoke from the configured OpenCode DeepSeek provider after the current rate-limit condition clears; do not paste credentials into chat.
2. Push the reviewed candidate, verify exact-head GitHub Actions CI, and preserve the final release evidence.
3. Close #1 only after the live smoke and CI gates pass; BETA-01 must not start before then.

The next product issue is BETA-01 only after this checklist passes.
