# BETA-00 bootstrap scope

Status: implementation in progress; issue #1 remains open until every gate is independently verified.

## Scope locked for this phase

- Product target: SecurityOla AppCare only.
- BETA-00 establishes the engineering loop, specification workflow, code graph, worker restrictions, CI/security baseline, and sanitized checkpoints.
- Application control-plane behavior, connectors, databases, LangGraph orchestration, backup providers, deployment, dashboard, and customer distribution remain ordered work for BETA-01 through BETA-10.
- No customer production system, DNS record, WordPress runtime, or production credential is touched by this phase.

## Completed evidence

- Dedicated checkout verified against public repository `costavong-pixel/securityola-appcare`, branch `main`, live base head recorded in the local checkpoint.
- Repository instructions and issues #1 through #12 were read before edits.
- Saveruflo selected `FULL`; its installed self-test suite passed 13/13.
- Graphify code/documentation update produced a 99-node, 86-edge graph with no dangling, missing, collapsed, or self-loop edges.
- Spec Kit 0.11.3 bundled templates, Codex skills, workflow metadata, and constitution were initialized locally.
- The shared-server audit was read-only until the explicit isolation step. Existing WordPress and DockPanel resources were categorized as do-not-touch; BETA-00 then created only an empty root-controlled AppCare service identity and namespace, with no runtime or database.
- OpenCode 1.18.16 was installed from the official upstream package and version-checked. DeepSeek authentication remains a separate machine-local gate and no credential value was inspected.
- The repository-scoped Codex Security standard scan finalized with no reportable findings; coverage explicitly defers the unimplemented runtime/connectors and the blocked live worker smoke.

## Remaining BETA-00 gates

1. Complete the bounded DeepSeek worker smoke task with machine-local authentication.
2. Run the independent Codex CLI review against the complete diff and evidence.
3. Verify the exact-head GitHub Actions result.
4. Save the final sanitized Saveruflo checkpoint and Graphify post-change impact review.

The next product issue is BETA-01 only after this checklist passes.
