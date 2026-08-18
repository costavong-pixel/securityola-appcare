"""Durable workflow ledgers built on the existing AppCare database boundary."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..db import Database
from ..models import WorkflowAction, WorkflowEvidence, WorkflowTransition, new_id, utcnow
from ..services.audit import append_event, sanitize_metadata, sanitize_text
from ..services.security import contains_credential_like_data, is_secret_key
from .contracts import (
    ActionAdapter,
    ActionResult,
    RetryableWorkflowError,
    TerminalWorkflowError,
    validate_failure_code,
    validate_safe_id,
)


class WorkflowConflictError(ValueError):
    """An idempotency key was reused with materially different data."""


class WorkflowActionError(RuntimeError):
    """A bounded action failed and the graph must route to escalation."""

    def __init__(self, code: str, *, escalated: bool) -> None:
        self.code = validate_failure_code(code)
        self.escalated = escalated
        super().__init__(self.code)


class WorkflowBudgetExceeded(WorkflowActionError):
    """An action was stopped because its finite policy budget was exhausted."""

    def __init__(self, code: str = "cost_budget_exhausted") -> None:
        super().__init__(code, escalated=True)


class WorkflowStore:
    """Persist action, evidence, and transition state without external authority."""

    def __init__(self, database: Database, *, actor_user_id: str | None = None) -> None:
        self.database = database
        self.actor_user_id = actor_user_id

    @staticmethod
    def _refs(values: tuple[str, ...] | list[str] | None) -> list[str]:
        refs = list(values or [])
        if len(refs) > 100:
            raise ValueError("workflow evidence references exceed the limit")
        for value in refs:
            validate_safe_id(value, field_name="evidence_ref")
        return refs

    def record_evidence(
        self,
        *,
        tenant_id: str,
        workflow_id: str,
        evidence_ref: str,
        kind: str,
        source: str,
        digest: str,
        summary: Mapping[str, Any] | None = None,
    ) -> WorkflowEvidence:
        """Record one deterministic evidence reference exactly once."""

        tenant_id = validate_safe_id(tenant_id, field_name="tenant_id")
        workflow_id = validate_safe_id(workflow_id, field_name="workflow_id")
        evidence_ref = validate_safe_id(evidence_ref, field_name="evidence_ref")
        kind = validate_safe_id(kind, field_name="evidence_kind")
        source = validate_safe_id(source, field_name="evidence_source")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("evidence digest must be a SHA-256 hex value")
        safe_summary = sanitize_metadata(summary or {})
        with self.database.session() as session:
            existing = session.scalar(
                select(WorkflowEvidence).where(
                    WorkflowEvidence.tenant_id == tenant_id,
                    WorkflowEvidence.workflow_id == workflow_id,
                    WorkflowEvidence.evidence_ref == evidence_ref,
                )
            )
            if existing is not None:
                if existing.kind != kind or existing.source != source or existing.digest != digest:
                    raise WorkflowConflictError("evidence reference was reused with different data")
                return existing
            evidence = WorkflowEvidence(
                id=new_id(),
                tenant_id=tenant_id,
                workflow_id=workflow_id,
                evidence_ref=evidence_ref,
                kind=kind,
                source=source,
                digest=digest,
                summary_json=safe_summary,
            )
            session.add(evidence)
            session.flush()
            return evidence

    def record_transition(
        self,
        *,
        tenant_id: str,
        workflow_id: str,
        transition_key: str,
        from_phase: str,
        to_phase: str,
        outcome: str,
        evidence_refs: tuple[str, ...] | list[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> WorkflowTransition:
        """Record one transition and its linked audit event idempotently."""

        tenant_id = validate_safe_id(tenant_id, field_name="tenant_id")
        workflow_id = validate_safe_id(workflow_id, field_name="workflow_id")
        transition_key = validate_safe_id(transition_key, field_name="transition_key")
        from_phase = validate_safe_id(from_phase, field_name="from_phase")
        to_phase = validate_safe_id(to_phase, field_name="to_phase")
        if outcome not in {"started", "succeeded", "failed", "paused", "escalated"}:
            raise ValueError("workflow transition outcome is invalid")
        refs = self._refs(evidence_refs)
        safe_metadata = sanitize_metadata(metadata or {})
        with self.database.session() as session:
            existing = session.scalar(
                select(WorkflowTransition).where(
                    WorkflowTransition.tenant_id == tenant_id,
                    WorkflowTransition.workflow_id == workflow_id,
                    WorkflowTransition.transition_key == transition_key,
                )
            )
            if existing is not None:
                if (
                    existing.from_phase != from_phase
                    or existing.to_phase != to_phase
                    or existing.outcome != outcome
                ):
                    raise WorkflowConflictError("transition key was reused with different data")
                return existing
            event = append_event(
                session,
                tenant_id=tenant_id,
                actor_user_id=self.actor_user_id,
                action="workflow.transition",
                subject_type="workflow",
                subject_id=None,
                outcome=outcome,
                metadata={
                    "workflow_id": workflow_id,
                    "transition_key": transition_key,
                    "from_phase": from_phase,
                    "to_phase": to_phase,
                    "evidence_refs": refs,
                    **safe_metadata,
                },
            )
            transition = WorkflowTransition(
                id=new_id(),
                tenant_id=tenant_id,
                workflow_id=workflow_id,
                transition_key=transition_key,
                from_phase=from_phase,
                to_phase=to_phase,
                outcome=outcome,
                evidence_refs_json=refs,
                metadata_json=safe_metadata,
                audit_event_id=event.id,
                occurred_at=utcnow(),
            )
            session.add(transition)
            session.flush()
            return transition

    def run_action(
        self,
        *,
        tenant_id: str,
        workflow_id: str,
        action_key: str,
        action_kind: str,
        state: Mapping[str, object],
        adapter: ActionAdapter,
        max_attempts: int,
    ) -> ActionResult:
        """Run an action under a durable idempotency key and finite retries."""

        tenant_id = validate_safe_id(tenant_id, field_name="tenant_id")
        workflow_id = validate_safe_id(workflow_id, field_name="workflow_id")
        action_key = validate_safe_id(action_key, field_name="action_key")
        action_kind = validate_safe_id(action_kind, field_name="action_kind")
        if max_attempts < 1 or max_attempts > 10:
            raise ValueError("max_attempts must be between 1 and 10")
        if any(not isinstance(key, str) for key in state):
            raise ValueError("workflow state keys must be strings")
        if any(
            is_secret_key(key) and key != "verification_passed" for key in state
        ) or any(contains_credential_like_data(value) for value in state.values()):
            raise ValueError("workflow state contains credential-like data")

        # Create the ledger row in its own short transaction. A concurrent creator
        # may win the unique constraint; the locked claim below then serializes
        # the actual adapter execution.
        try:
            with self.database.session() as session:
                action = session.scalar(
                    select(WorkflowAction).where(
                        WorkflowAction.tenant_id == tenant_id,
                        WorkflowAction.workflow_id == workflow_id,
                        WorkflowAction.action_key == action_key,
                    )
                )
                if action is None:
                    session.add(
                        WorkflowAction(
                            id=new_id(),
                            tenant_id=tenant_id,
                            workflow_id=workflow_id,
                            action_key=action_key,
                            action_kind=action_kind,
                            status="pending",
                            attempt_count=0,
                        )
                    )
                    session.flush()
        except IntegrityError:
            # Another worker created this exact idempotency row first. The
            # database-backed claim below is the source of truth; do not retry
            # the external action from this create race.
            pass

        terminal_error: WorkflowActionError | None = None
        retry_exhausted = False
        result: ActionResult | None = None
        with self.database.session() as session:
            action = session.scalar(
                select(WorkflowAction)
                .where(
                    WorkflowAction.tenant_id == tenant_id,
                    WorkflowAction.workflow_id == workflow_id,
                    WorkflowAction.action_key == action_key,
                )
                .with_for_update()
            )
            if action is None:
                raise WorkflowActionError("action_ledger_missing", escalated=True)
            if action.action_kind != action_kind:
                raise WorkflowConflictError("action key was reused with a different action kind")
            if action.status == "succeeded" and action.result_reference:
                return ActionResult(
                    result_reference=action.result_reference,
                    attempts=action.attempt_count,
                )
            if action.status in {"failed", "escalated"}:
                raise WorkflowActionError(
                    action.failure_code or "action_not_available",
                    escalated=action.status == "escalated",
                )

            # Keep the row lock until the bounded adapter sequence has finished.
            # PostgreSQL workers therefore cannot both observe the same pending
            # action and invoke its external side effect concurrently. Adapters
            # still receive the stable action key and must remain idempotent if a
            # process dies after the provider side effect but before commit.
            while action.attempt_count < max_attempts:
                action.attempt_count += 1
                attempt = action.attempt_count
                action.status = "running"
                action.failure_code = None
                session.flush()
                try:
                    candidate = adapter.execute(action_key, action_kind, dict(state))
                    if not isinstance(candidate, ActionResult):
                        raise ValueError("adapter did not return an ActionResult")
                    result = replace(candidate, attempts=attempt)
                    action.status = "succeeded"
                    action.result_reference = sanitize_text(result.result_reference, max_length=500)
                    action.failure_code = None
                    break
                except RetryableWorkflowError as exc:
                    action.failure_code = exc.code
                    if attempt >= max_attempts:
                        action.status = "escalated"
                        retry_exhausted = True
                        break
                    action.status = "pending"
                except TerminalWorkflowError as exc:
                    action.status = "failed"
                    action.failure_code = exc.code
                    terminal_error = WorkflowActionError(exc.code, escalated=False)
                    break
                except Exception:
                    action.status = "failed"
                    action.failure_code = "action_execution_failed"
                    terminal_error = WorkflowActionError(
                        "action_execution_failed", escalated=False
                    )
                    break

        if retry_exhausted:
            raise WorkflowActionError("retry_budget_exhausted", escalated=True) from None
        if terminal_error is not None:
            raise terminal_error
        if result is None:
            raise WorkflowActionError("action_execution_failed", escalated=False)
        return result


__all__ = [
    "WorkflowActionError",
    "WorkflowBudgetExceeded",
    "WorkflowConflictError",
    "WorkflowStore",
]
