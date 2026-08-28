"""Tenant-scoped, read-only readiness state sourced from durable evidence."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, cast

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ..auth.dependencies import get_current_user, get_session
from ..models import (
    Application,
    ReadinessLevelRecord,
    SupportabilityDecisionRecord,
    User,
)
from .common import owned_application


class ReadinessLevelResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: str
    scope: str
    status: Literal["ready", "blocked", "partial"]
    evidence_refs: list[str] = Field(default_factory=list)
    evidence_classes: list[str] = Field(default_factory=list)
    evidence_kinds: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    evaluator: str
    exact_head: str | None = None
    artifact_digest: str | None = None
    coordinator_decision: str | None = None
    evaluated_at: datetime


class SupportabilityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stack_id: str
    status: Literal["supported", "needs_cleanup", "unsupported"]
    authoritative: bool
    mandatory_capability_digest: str
    blocking_capabilities: list[str] = Field(default_factory=list)
    cleanup_capabilities: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    coordinator_decision: str
    decided_at: datetime


class ReadinessSnapshot(BaseModel):
    """Only persisted, tenant-owned readiness state is exposed to callers."""

    model_config = ConfigDict(extra="forbid")

    state_source: Literal["persisted"] = "persisted"
    captured_at: datetime
    tenant_id: str
    application_id: str
    supportability: SupportabilityResponse | None = None
    levels: list[ReadinessLevelResponse] = Field(default_factory=list)
    live_customer_production_enabled: Literal[False] = False


router = APIRouter(prefix="/v1", tags=["readiness"])


def _latest_levels(
    session: Session, *, tenant_id: str, application_id: str
) -> list[ReadinessLevelRecord]:
    rows = list(
        session.scalars(
            select(ReadinessLevelRecord)
            .where(
                ReadinessLevelRecord.tenant_id == tenant_id,
                ReadinessLevelRecord.application_id == application_id,
            )
            .order_by(desc(ReadinessLevelRecord.evaluated_at), desc(ReadinessLevelRecord.id))
        ).all()
    )
    if not rows:
        return []
    digest = rows[0].assessment_digest
    return sorted(
        (row for row in rows if row.assessment_digest == digest),
        key=lambda row: row.level,
    )


def _latest_supportability(
    session: Session, *, tenant_id: str, application_id: str
) -> SupportabilityDecisionRecord | None:
    return session.scalar(
        select(SupportabilityDecisionRecord)
        .where(
            SupportabilityDecisionRecord.tenant_id == tenant_id,
            SupportabilityDecisionRecord.application_id == application_id,
        )
        .order_by(
            desc(SupportabilityDecisionRecord.decided_at),
            desc(SupportabilityDecisionRecord.id),
        )
        .limit(1)
    )


def _level_response(row: ReadinessLevelRecord) -> ReadinessLevelResponse:
    return ReadinessLevelResponse(
        level=row.level,
        scope=row.scope,
        status=cast(Literal["ready", "blocked", "partial"], row.status),
        evidence_refs=list(row.evidence_refs_json),
        evidence_classes=list(row.evidence_classes_json),
        evidence_kinds=list(row.evidence_kinds_json),
        reason_codes=list(row.reason_codes_json),
        evaluator=row.evaluator,
        exact_head=row.exact_head,
        artifact_digest=row.artifact_digest,
        coordinator_decision=row.coordinator_decision,
        evaluated_at=_aware(row.evaluated_at),
    )


def _supportability_response(
    row: SupportabilityDecisionRecord | None,
) -> SupportabilityResponse | None:
    if row is None:
        return None
    return SupportabilityResponse(
        stack_id=row.stack_id,
        status=cast(Literal["supported", "needs_cleanup", "unsupported"], row.status),
        authoritative=(
            row.status == "supported"
            and row.coordinator == "gpt-5.6-luna-max"
            and row.coordinator_decision == "approve"
        ),
        mandatory_capability_digest=row.mandatory_capability_digest,
        blocking_capabilities=list(row.blocking_capabilities_json),
        cleanup_capabilities=list(row.cleanup_capabilities_json),
        evidence_refs=list(row.evidence_refs_json),
        reason_codes=list(row.reason_codes_json),
        coordinator_decision=row.coordinator_decision,
        decided_at=_aware(row.decided_at),
    )


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


@router.get("/applications/{application_id}/readiness", response_model=ReadinessSnapshot)
def get_application_readiness(
    application_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> ReadinessSnapshot:
    application: Application = owned_application(session, user, application_id)
    return ReadinessSnapshot(
        captured_at=datetime.now(UTC),
        tenant_id=user.tenant_id,
        application_id=application.id,
        supportability=_supportability_response(
            _latest_supportability(
                session,
                tenant_id=user.tenant_id,
                application_id=application.id,
            )
        ),
        levels=[
            _level_response(row)
            for row in _latest_levels(
                session,
                tenant_id=user.tenant_id,
                application_id=application.id,
            )
        ],
    )


__all__ = ["ReadinessSnapshot", "router"]
