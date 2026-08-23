"""LangGraph scan-to-recovery workflow with explicit safety gates."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from ..deployment.contracts import live_preview_is_passed, normalize_live_preview_status
from .contracts import (
    ActionAdapter,
    ActionResult,
    EvidenceItem,
    RetryableWorkflowError,
    ScanAdapter,
    ScanResult,
    TerminalWorkflowError,
    WorkflowConfigurationError,
    WorkflowState,
    validate_checkpoint_state,
    validate_failure_code,
    validate_safe_id,
)
from .store import WorkflowActionError, WorkflowBudgetExceeded, WorkflowStore


def _opaque_reference(prefix: str, *parts: str) -> str:
    digest = sha256("|".join(parts).encode("utf-8")).hexdigest()
    return f"{prefix}:{digest[:48]}"


class _NoopActionAdapter:
    """A deterministic test adapter; production callers must inject real policy code."""

    def execute(
        self, action_key: str, action_kind: str, state: Mapping[str, object]
    ) -> ActionResult:
        del state
        return ActionResult(
            result_reference=_opaque_reference("simulated", action_key, action_kind)
        )


class _NoopScanAdapter:
    """A deterministic empty scan used only when a test explicitly omits an adapter."""

    def scan(self, state: Mapping[str, object]) -> ScanResult:
        workflow_id = str(state["workflow_id"])
        digest = sha256(f"empty-scan|{workflow_id}".encode()).hexdigest()
        return ScanResult(
            evidence=(
                EvidenceItem(
                    evidence_ref=f"scan-summary:{digest[:48]}",
                    kind="scan-summary",
                    source="scanner-noop",
                    digest=digest,
                    summary={"finding_count": 0},
                ),
            )
        )


@dataclass(frozen=True, slots=True)
class WorkflowRuntime:
    """Explicit workflow dependencies and finite policy limits."""

    store: WorkflowStore
    action_adapter: ActionAdapter = field(default_factory=_NoopActionAdapter)
    scan_adapter: ScanAdapter = field(default_factory=_NoopScanAdapter)
    max_action_attempts: int = 3

    def __post_init__(self) -> None:
        if self.max_action_attempts < 1 or self.max_action_attempts > 10:
            raise ValueError("max_action_attempts must be between 1 and 10")


def initial_state(
    *,
    workflow_id: str,
    tenant_id: str,
    application_id: str,
    job_id: str,
    target_environment: str = "staging",
    beta06_verified_live_preview: str = "unverified",
    risk_level: str = "low",
    backup_status: str = "required",
    retry_budget: int = 3,
    timeout_budget_seconds: int = 900,
    cost_budget_micros: int = 1_000_000,
) -> WorkflowState:
    """Construct the bounded initial state for one AppCare workflow."""

    values: WorkflowState = {
        "workflow_id": validate_safe_id(workflow_id, field_name="workflow_id"),
        "tenant_id": validate_safe_id(tenant_id, field_name="tenant_id"),
        "application_id": validate_safe_id(application_id, field_name="application_id"),
        "job_id": validate_safe_id(job_id, field_name="job_id"),
        "phase": "intake",
        "status": "running",
        "target_environment": target_environment,
        "beta06_verified_live_preview": normalize_live_preview_status(beta06_verified_live_preview),
        "risk_level": risk_level,
        "backup_status": backup_status,
        "inventory_status": "pending",
        "scan_status": "pending",
        "evidence_status": "pending",
        "approval_status": "not_required",
        "deployment_status": "not_started",
        "rollback_status": "not_started",
        "scanner_failure_code": None,
        "failure_code": None,
        "retry_budget": retry_budget,
        "timeout_budget_seconds": timeout_budget_seconds,
        "cost_budget_micros": cost_budget_micros,
        "cost_used_micros": 0,
        "attempts": {},
        "evidence_refs": [],
        "finding_refs": [],
        "ai_explanation_refs": [],
        "approval_ref": None,
        "deployment_ref": None,
        "rollback_ref": None,
        "verification_passed": None,
    }
    if target_environment not in {"development", "staging", "production"}:
        raise ValueError("target_environment is invalid")
    if risk_level not in {"low", "medium", "high", "critical"}:
        raise ValueError("risk_level is invalid")
    if retry_budget < 1 or retry_budget > 10:
        raise ValueError("retry_budget must be between 1 and 10")
    if timeout_budget_seconds < 1 or timeout_budget_seconds > 86_400:
        raise ValueError("timeout_budget_seconds is outside the supported range")
    if cost_budget_micros < 1 or cost_budget_micros > 100_000_000:
        raise ValueError("cost_budget_micros is outside the supported range")
    validate_checkpoint_state(values)
    return values


def _refs(state: WorkflowState, additions: tuple[str, ...] | list[str] = ()) -> list[str]:
    existing = list(state.get("evidence_refs", []))
    for value in additions:
        if value not in existing:
            existing.append(value)
    if len(existing) > 100:
        raise WorkflowConfigurationError("workflow evidence reference budget exceeded")
    return existing


def _update_refs(update: Mapping[str, object]) -> tuple[str, ...]:
    values = update.get("evidence_refs", [])
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise WorkflowConfigurationError("workflow action evidence references are invalid")
    return tuple(values)


def _transition(
    runtime: WorkflowRuntime,
    state: WorkflowState,
    *,
    key: str,
    to_phase: str,
    outcome: str,
    evidence_refs: tuple[str, ...] | list[str] = (),
    metadata: Mapping[str, object] | None = None,
) -> None:
    runtime.store.record_transition(
        tenant_id=state["tenant_id"],
        workflow_id=state["workflow_id"],
        transition_key=key,
        from_phase=str(state.get("phase", "intake")),
        to_phase=to_phase,
        outcome=outcome,
        evidence_refs=evidence_refs,
        metadata=metadata,
    )


def _failure(
    runtime: WorkflowRuntime,
    state: WorkflowState,
    code: str,
    *,
    scanner_failure_code: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> dict[str, object]:
    safe_code = validate_failure_code(code)
    _transition(
        runtime,
        state,
        key=f"{state.get('phase', 'workflow')}:failed:{safe_code}",
        to_phase="escalated",
        outcome="escalated",
        evidence_refs=tuple(state.get("evidence_refs", [])),
        metadata=metadata or {"failure_code": safe_code},
    )
    return {
        "phase": "escalated",
        "status": "escalated",
        "failure_code": safe_code,
        "scanner_failure_code": scanner_failure_code,
    }


def _action_key(state: WorkflowState, action_kind: str) -> str:
    return _opaque_reference(
        action_kind,
        state["tenant_id"],
        state["workflow_id"],
        state["application_id"],
        state["job_id"],
    )


def _run_action(
    runtime: WorkflowRuntime,
    state: WorkflowState,
    *,
    action_kind: str,
) -> tuple[ActionResult, dict[str, object]]:
    max_attempts = min(runtime.max_action_attempts, int(state["retry_budget"]))
    result = runtime.store.run_action(
        tenant_id=state["tenant_id"],
        workflow_id=state["workflow_id"],
        action_key=_action_key(state, action_kind),
        action_kind=action_kind,
        state=state,
        adapter=runtime.action_adapter,
        max_attempts=max_attempts,
    )
    cost_used = int(state["cost_used_micros"]) + result.cost_micros
    if cost_used > int(state["cost_budget_micros"]):
        raise WorkflowBudgetExceeded()
    attempts = dict(state.get("attempts", {}))
    attempts[_action_key(state, action_kind)] = result.attempts
    return result, {
        "cost_used_micros": cost_used,
        "attempts": attempts,
        "evidence_refs": _refs(state, result.evidence_refs),
    }


def build_workflow(runtime: WorkflowRuntime, checkpointer: Any) -> Any:
    """Build the resumable graph; all capabilities remain injected boundaries."""

    def intake(state: WorkflowState) -> dict[str, object]:
        try:
            validate_checkpoint_state(state)
        except ValueError:
            return _failure(runtime, state, "workflow_state_rejected")
        _transition(runtime, state, key="intake:scope", to_phase="scope", outcome="succeeded")
        return {"phase": "scope"}

    def scope(state: WorkflowState) -> dict[str, object]:
        values = (
            state["tenant_id"],
            state["application_id"],
            state["job_id"],
            str(state.get("target_environment", "")),
        )
        lowered = "|".join(values).casefold()
        if any(marker in lowered for marker in ("wordpress", "barnd", "shield", "/var/www")):
            return _failure(runtime, state, "scope_boundary_rejected")
        _transition(
            runtime,
            state,
            key="scope:inventory",
            to_phase="asset_inventory",
            outcome="succeeded",
        )
        return {"phase": "asset_inventory"}

    def action_node(
        action_kind: str, next_phase: str
    ) -> Callable[[WorkflowState], dict[str, object]]:
        def node(state: WorkflowState) -> dict[str, object]:
            try:
                result, update = _run_action(runtime, state, action_kind=action_kind)
            except WorkflowActionError as exc:
                return {
                    "failure_code": exc.code,
                    "status": "escalated" if exc.escalated else "failed",
                }
            _transition(
                runtime,
                state,
                key=f"{action_kind}:succeeded",
                to_phase=next_phase,
                outcome="succeeded",
                evidence_refs=_update_refs(update),
                metadata={"action_kind": action_kind, "result_reference": result.result_reference},
            )
            return {"phase": next_phase, "status": "running", **update}

        return node

    def backup_gate(state: WorkflowState) -> dict[str, object]:
        if state.get("backup_status") != "verified":
            return _failure(runtime, state, "backup_not_verified")
        _transition(
            runtime,
            state,
            key="backup_gate:verified",
            to_phase="parallel_scans",
            outcome="succeeded",
        )
        return {"phase": "parallel_scans"}

    def parallel_scans(state: WorkflowState) -> dict[str, object]:
        try:
            result = runtime.scan_adapter.scan(dict(state))
        except RetryableWorkflowError as exc:
            result = ScanResult(failure_code=exc.code, retryable=True)
        except TerminalWorkflowError as exc:
            result = ScanResult(failure_code=exc.code)
        except Exception:
            result = ScanResult(failure_code="scanner_execution_failed")
        if result.failure_code is not None:
            return _failure(
                runtime,
                state,
                f"scanner_failure:{result.failure_code}",
                scanner_failure_code=result.failure_code,
                metadata={"scanner_failure": True, "retryable": result.retryable},
            )
        evidence_refs = list(result.evidence_refs)
        for item in result.evidence:
            runtime.store.record_evidence(
                tenant_id=state["tenant_id"],
                workflow_id=state["workflow_id"],
                evidence_ref=item.evidence_ref,
                kind=item.kind,
                source=item.source,
                digest=item.digest,
                summary=item.summary,
            )
            if item.evidence_ref not in evidence_refs:
                evidence_refs.append(item.evidence_ref)
        refs = _refs(state, tuple(evidence_refs))
        _transition(
            runtime,
            state,
            key="parallel_scans:complete",
            to_phase="evidence_gate",
            outcome="succeeded",
            evidence_refs=tuple(refs),
            metadata={"finding_count": len(result.finding_refs)},
        )
        return {
            "phase": "evidence_gate",
            "scan_status": "completed",
            "evidence_refs": refs,
            "finding_refs": list(result.finding_refs),
        }

    def evidence_gate(state: WorkflowState) -> dict[str, object]:
        refs = state.get("evidence_refs", [])
        if not refs:
            return _failure(runtime, state, "evidence_missing")
        _transition(
            runtime,
            state,
            key="evidence_gate:verified",
            to_phase="risk_policy",
            outcome="succeeded",
            evidence_refs=tuple(refs),
        )
        return {"phase": "risk_policy", "evidence_status": "verified"}

    def risk_policy(state: WorkflowState) -> dict[str, object]:
        approval_required = state.get("target_environment") == "production" or state.get(
            "risk_level"
        ) in {"high", "critical"}
        approval_status = "required" if approval_required else "not_required"
        _transition(
            runtime,
            state,
            key="risk_policy:isolated-workspace",
            to_phase="isolated_workspace",
            outcome="succeeded",
            metadata={"approval_required": approval_required},
        )
        return {"phase": "isolated_workspace", "approval_status": approval_status}

    def approval(state: WorkflowState) -> dict[str, object]:
        if state.get("target_environment") == "production" and not live_preview_is_passed(
            state.get("beta06_verified_live_preview")
        ):
            return _failure(runtime, state, "beta06_live_preview_required")
        if state.get("approval_status") != "required":
            _transition(
                runtime,
                state,
                key="approval:not-required",
                to_phase="controlled_deploy",
                outcome="succeeded",
            )
            return {"phase": "controlled_deploy", "approval_status": "not_required"}

        approval_ref = state.get("approval_ref") or _opaque_reference(
            "approval", state["tenant_id"], state["workflow_id"]
        )
        _transition(
            runtime,
            state,
            key="approval:paused",
            to_phase="approval",
            outcome="paused",
            metadata={"approval_ref": approval_ref, "action": "controlled_deploy"},
        )
        decision = interrupt(
            {
                "type": "approval_required",
                "workflow_id": state["workflow_id"],
                "approval_ref": approval_ref,
                "action": "controlled_deploy",
            }
        )
        if not isinstance(decision, Mapping):
            raise WorkflowConfigurationError("approval decision must be an object")
        decision_value = str(decision.get("decision", "")).casefold()
        decision_ref = decision.get("decision_ref")
        if decision_value not in {"approved", "rejected"} or not isinstance(decision_ref, str):
            raise WorkflowConfigurationError("approval decision is incomplete")
        validate_safe_id(decision_ref, field_name="decision_ref")
        if decision_value == "rejected":
            return _failure(
                runtime,
                state,
                "approval_rejected",
                metadata={"approval_ref": approval_ref, "decision_ref": decision_ref},
            )
        _transition(
            runtime,
            state,
            key="approval:approved",
            to_phase="controlled_deploy",
            outcome="succeeded",
            metadata={"approval_ref": approval_ref, "decision_ref": decision_ref},
        )
        return {
            "phase": "controlled_deploy",
            "approval_status": "approved",
            "approval_ref": approval_ref,
        }

    def controlled_deploy(state: WorkflowState) -> dict[str, object]:
        if state.get("target_environment") == "production" and not live_preview_is_passed(
            state.get("beta06_verified_live_preview")
        ):
            return _failure(runtime, state, "beta06_live_preview_required")
        if state.get("approval_status") not in {"approved", "not_required"}:
            return _failure(runtime, state, "approval_required_before_deploy")
        try:
            result, update = _run_action(runtime, state, action_kind="controlled_deploy")
        except WorkflowActionError as exc:
            return {"failure_code": exc.code, "status": "escalated" if exc.escalated else "failed"}
        _transition(
            runtime,
            state,
            key="controlled_deploy:succeeded",
            to_phase="post_deploy_verify",
            outcome="succeeded",
            evidence_refs=_update_refs(update),
            metadata={"result_reference": result.result_reference},
        )
        return {
            "phase": "post_deploy_verify",
            "deployment_status": "deployed",
            "deployment_ref": result.result_reference,
            "status": "running",
            **update,
        }

    def post_deploy_verify(state: WorkflowState) -> dict[str, object]:
        try:
            result, update = _run_action(runtime, state, action_kind="post_deploy_verify")
        except WorkflowActionError as exc:
            return {"failure_code": exc.code, "status": "escalated" if exc.escalated else "failed"}
        passed = result.verification_passed is not False
        if not passed:
            _transition(
                runtime,
                state,
                key="post_deploy_verify:failed",
                to_phase="rollback",
                outcome="failed",
                evidence_refs=_update_refs(update),
                metadata={"failure_code": "post_deploy_verification_failed"},
            )
            return {
                "phase": "rollback",
                "status": "failed",
                "deployment_status": "failed",
                "verification_passed": False,
                "failure_code": "post_deploy_verification_failed",
                **update,
            }
        _transition(
            runtime,
            state,
            key="post_deploy_verify:passed",
            to_phase="monitor_report",
            outcome="succeeded",
            evidence_refs=_update_refs(update),
        )
        return {
            "phase": "monitor_report",
            "verification_passed": True,
            "deployment_status": "verified",
            **update,
        }

    def rollback(state: WorkflowState) -> dict[str, object]:
        try:
            result, update = _run_action(runtime, state, action_kind="rollback")
        except WorkflowActionError as exc:
            return {"failure_code": exc.code, "status": "escalated" if exc.escalated else "failed"}
        _transition(
            runtime,
            state,
            key="rollback:succeeded",
            to_phase="monitor_report",
            outcome="succeeded",
            evidence_refs=_update_refs(update),
            metadata={"result_reference": result.result_reference},
        )
        return {
            "phase": "monitor_report",
            "status": "rolled_back",
            "failure_code": None,
            "rollback_status": "completed",
            "rollback_ref": result.result_reference,
            **update,
        }

    def monitor_report(state: WorkflowState) -> dict[str, object]:
        final_status = "rolled_back" if state.get("status") == "rolled_back" else "completed"
        _transition(
            runtime,
            state,
            key="monitor_report:complete",
            to_phase="completed",
            outcome="succeeded",
        )
        return {"phase": "completed", "status": final_status}

    def failure(state: WorkflowState) -> dict[str, object]:
        code = validate_failure_code(str(state.get("failure_code") or "workflow_failed"))
        outcome = "escalated" if state.get("status") == "escalated" else "failed"
        _transition(
            runtime,
            state,
            key=f"failure:terminal:{code}",
            to_phase="escalated",
            outcome=outcome,
            evidence_refs=tuple(state.get("evidence_refs", [])),
            metadata={"failure_code": code},
        )
        return {"phase": "escalated", "status": "escalated", "failure_code": code}

    # LangGraph's current stubs infer a ``Never`` node type for total=False
    # TypedDict schemas; the runtime schema remains the explicit WorkflowState.
    graph: Any = StateGraph(WorkflowState)
    graph.add_node("intake", intake)
    graph.add_node("scope", scope)
    graph.add_node("asset_inventory", action_node("asset_inventory", "backup_gate"))
    graph.add_node("backup_gate", backup_gate)
    graph.add_node("parallel_scans", parallel_scans)
    graph.add_node("evidence_gate", evidence_gate)
    graph.add_node("risk_policy", risk_policy)
    graph.add_node("isolated_workspace", action_node("isolated_workspace", "remediation_plan"))
    graph.add_node("remediation_plan", action_node("remediation_plan", "patch_test"))
    graph.add_node("patch_test", action_node("patch_test", "approval"))
    graph.add_node("approval", approval)
    graph.add_node("controlled_deploy", controlled_deploy)
    graph.add_node("post_deploy_verify", post_deploy_verify)
    graph.add_node("rollback", rollback)
    graph.add_node("monitor_report", monitor_report)
    graph.add_node("failure", failure)
    graph.add_edge(START, "intake")
    graph.add_conditional_edges(
        "intake", lambda state: "failure" if state.get("failure_code") else "scope"
    )
    graph.add_conditional_edges(
        "scope", lambda state: "failure" if state.get("failure_code") else "asset_inventory"
    )
    graph.add_conditional_edges(
        "asset_inventory", lambda state: "failure" if state.get("failure_code") else "backup_gate"
    )
    graph.add_conditional_edges(
        "backup_gate", lambda state: "failure" if state.get("failure_code") else "parallel_scans"
    )
    graph.add_conditional_edges(
        "parallel_scans", lambda state: "failure" if state.get("failure_code") else "evidence_gate"
    )
    graph.add_conditional_edges(
        "evidence_gate", lambda state: "failure" if state.get("failure_code") else "risk_policy"
    )
    graph.add_edge("risk_policy", "isolated_workspace")
    graph.add_conditional_edges(
        "isolated_workspace",
        lambda state: "failure" if state.get("failure_code") else "remediation_plan",
    )
    graph.add_conditional_edges(
        "remediation_plan", lambda state: "failure" if state.get("failure_code") else "patch_test"
    )
    graph.add_conditional_edges(
        "patch_test", lambda state: "failure" if state.get("failure_code") else "approval"
    )
    graph.add_conditional_edges(
        "approval",
        lambda state: (
            "failure"
            if state.get("failure_code") or state.get("approval_status") == "rejected"
            else "controlled_deploy"
        ),
    )
    graph.add_conditional_edges(
        "controlled_deploy",
        lambda state: "failure" if state.get("failure_code") else "post_deploy_verify",
    )
    graph.add_conditional_edges(
        "post_deploy_verify",
        lambda state: (
            "rollback"
            if state.get("phase") == "rollback"
            else ("failure" if state.get("failure_code") else "monitor_report")
        ),
    )
    graph.add_conditional_edges(
        "rollback", lambda state: "failure" if state.get("failure_code") else "monitor_report"
    )
    graph.add_edge("monitor_report", END)
    graph.add_edge("failure", END)
    return graph.compile(checkpointer=checkpointer)


__all__ = ["WorkflowRuntime", "build_workflow", "initial_state"]
