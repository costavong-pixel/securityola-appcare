# BETA-00 bootstrap scope

Status: blocked at the owner-controlled DeepSeek worker-authentication gate; issue #1 remains open until every gate is independently verified.

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
- OpenCode 1.18.16 was installed from the official upstream package and version-checked. DeepSeek authentication remains a separate machine-local gate and no credential value was inspected.
- The bounded smoke ran in a disposable Git worktree. Scope verification passed, the worker returned an OpenCode provider error because no DeepSeek credential is configured locally, and the worktree/temporary directory were removed with the coordinator checkout unchanged.
- The repository-scoped Codex Security standard scan finalized with no reportable findings; coverage explicitly defers the unimplemented runtime/connectors and the blocked live worker smoke.
- Final deterministic local evidence: 13 tests passed, strict typing passed for 9 source files, public-safety and worker-policy checks passed, the hash-locked development environment validated, and `pip-audit` reported no known vulnerabilities. Independent Codex CLI review reported no findings.

## Remaining BETA-00 gates

1. Owner configures the approved DeepSeek credential in the machine-local OpenCode store without pasting it into chat.
2. Codex reruns the bounded smoke and verifies the exact worker evidence.
3. Push the reviewed commit, verify exact-head GitHub Actions CI, and preserve the final release evidence.
4. Close #1 only after those gates pass; BETA-01 must not start before then.

The next product issue is BETA-01 only after this checklist passes.
