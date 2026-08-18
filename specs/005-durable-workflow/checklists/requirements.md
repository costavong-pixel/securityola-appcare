# BETA-05 Requirements Checklist

## Functional

- [ ] PostgreSQL-backed LangGraph checkpointer is explicit and fail-closed.
- [ ] Typed state persists only sanitized workflow data and bounded references.
- [ ] Every transition has durable workflow/audit evidence.
- [ ] Actions use durable idempotency keys and duplicate delivery is harmless.
- [ ] Retry, timeout, and cost budgets are finite and exhaustion escalates.
- [ ] Approval interrupt survives graph recreation and resumes explicitly.
- [ ] Failed post-deploy verification routes to one idempotent rollback action.
- [ ] Scanner/tool evidence is separate from AI explanation references.

## Safety

- [ ] No production/WordPress resource or live provider is accessed.
- [ ] No credential, raw artifact, raw scanner payload, or private prompt enters
  state, logs, checkpoints, fixtures, or repository files.
- [ ] Workflow nodes do not possess deployment or merge authority.

## Verification

- [ ] Deterministic unit/integration/failure-injection tests pass.
- [ ] Ruff, mypy, public-safety, worker-policy, build-lock, and dependency
  gates pass.
- [ ] Applicable Codex Security review and independent final review pass.
- [ ] Exact-head GitHub CI passes before merge.
