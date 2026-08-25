"""SQLAlchemy-backed BETA-08 monitoring event store."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import MonitoringEventRecord
from .contracts import (
    MonitoringBoundaryError,
    MonitoringEvent,
    MonitoringStore,
    MonitorTarget,
    UsageCostSample,
)

SessionFactory = Callable[[], Session]


class SqlAlchemyMonitoringStore(MonitoringStore):
    """Tenant/application/environment-scoped append-only event persistence."""

    def __init__(self, session_factory: SessionFactory, *, target: MonitorTarget) -> None:
        self._session_factory = session_factory
        self._target = target

    def _assert_target(self, event: MonitoringEvent) -> None:
        if event.target != self._target:
            raise MonitoringBoundaryError("monitoring store target boundary was crossed")

    @staticmethod
    def _timestamp(value: str) -> datetime:
        try:
            return datetime.fromisoformat(value)
        except ValueError as exc:
            raise MonitoringBoundaryError("persisted monitoring timestamp is malformed") from exc

    @staticmethod
    def _text(raw: dict[str, object], key: str) -> str:
        value = raw.get(key)
        if not isinstance(value, str):
            raise MonitoringBoundaryError(f"persisted monitoring field {key} is malformed")
        return value

    @staticmethod
    def _nonnegative_int(raw: dict[str, object], key: str) -> int:
        value = raw.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise MonitoringBoundaryError(f"persisted monitoring field {key} is malformed")
        return value

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value

    @staticmethod
    def _usage_json(event: MonitoringEvent) -> dict[str, object] | None:
        if event.usage is None:
            return None
        return {
            "tenant_id": event.usage.target.tenant_id,
            "application_id": event.usage.target.application_id,
            "environment": event.usage.target.environment,
            "app_reference": event.usage.target.app_reference,
            "observed_at": event.usage.observed_at.isoformat(),
            "evidence_ref": event.usage.evidence_ref,
            "jobs": event.usage.jobs,
            "operator_minutes": event.usage.operator_minutes,
            "provider_cost_cents": event.usage.provider_cost_cents,
        }

    @staticmethod
    def _event_from_row(row: MonitoringEventRecord) -> MonitoringEvent:
        target = MonitorTarget(
            tenant_id=row.tenant_id,
            application_id=row.application_id,
            environment=cast(Any, row.environment),
            app_reference=row.app_reference,
        )
        usage: UsageCostSample | None = None
        if row.usage_json is not None:
            raw = row.usage_json
            if not isinstance(raw, dict):
                raise MonitoringBoundaryError("persisted monitoring usage is malformed")
            usage = UsageCostSample(
                target=MonitorTarget(
                    tenant_id=SqlAlchemyMonitoringStore._text(raw, "tenant_id"),
                    application_id=SqlAlchemyMonitoringStore._text(raw, "application_id"),
                    environment=cast(Any, raw.get("environment")),
                    app_reference=SqlAlchemyMonitoringStore._text(raw, "app_reference"),
                ),
                observed_at=SqlAlchemyMonitoringStore._timestamp(
                    SqlAlchemyMonitoringStore._text(raw, "observed_at")
                ),
                evidence_ref=SqlAlchemyMonitoringStore._text(raw, "evidence_ref"),
                jobs=SqlAlchemyMonitoringStore._nonnegative_int(raw, "jobs"),
                operator_minutes=SqlAlchemyMonitoringStore._nonnegative_int(
                    raw, "operator_minutes"
                ),
                provider_cost_cents=SqlAlchemyMonitoringStore._nonnegative_int(
                    raw, "provider_cost_cents"
                ),
            )
            if usage.target != target:
                raise MonitoringBoundaryError("persisted monitoring usage crossed target boundary")
        event = MonitoringEvent(
            sequence=row.sequence,
            event_type=cast(Any, row.event_type),
            occurred_at=SqlAlchemyMonitoringStore._aware(row.occurred_at),
            target=target,
            check_kind=cast(Any, row.check_kind),
            status=cast(Any, row.status),
            evidence_ref=row.evidence_ref,
            summary=row.summary,
            reason_code=row.reason_code,
            fingerprint=row.fingerprint,
            alert_id=row.alert_id,
            alert_state=cast(Any, row.alert_state),
            severity=cast(Any, row.severity),
            occurrences=row.occurrences,
            suppressed_count=row.suppressed_count,
            usage=usage,
        )
        if event.digest != row.digest:
            raise MonitoringBoundaryError("persisted monitoring event digest mismatch")
        return event

    def append(self, event: MonitoringEvent) -> None:
        self._assert_target(event)
        with self._session_factory() as session:
            current = session.scalar(
                select(func.max(MonitoringEventRecord.sequence)).where(
                    MonitoringEventRecord.tenant_id == self._target.tenant_id,
                    MonitoringEventRecord.application_id == self._target.application_id,
                    MonitoringEventRecord.environment == self._target.environment,
                )
            )
            expected = int(current or 0) + 1
            if event.sequence != expected:
                raise MonitoringBoundaryError("monitoring event sequence is not append-only")
            session.add(
                MonitoringEventRecord(
                    tenant_id=self._target.tenant_id,
                    application_id=self._target.application_id,
                    environment=self._target.environment,
                    app_reference=self._target.app_reference,
                    sequence=event.sequence,
                    event_type=event.event_type,
                    occurred_at=event.occurred_at,
                    check_kind=event.check_kind,
                    status=event.status,
                    evidence_ref=event.evidence_ref,
                    summary=event.summary,
                    reason_code=event.reason_code,
                    fingerprint=event.fingerprint,
                    alert_id=event.alert_id,
                    alert_state=event.alert_state,
                    severity=event.severity,
                    occurrences=event.occurrences,
                    suppressed_count=event.suppressed_count,
                    usage_json=self._usage_json(event),
                    digest=event.digest,
                )
            )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise MonitoringBoundaryError("monitoring event sequence conflict") from exc

    def read(self) -> tuple[MonitoringEvent, ...]:
        with self._session_factory() as session:
            rows = list(
                session.scalars(
                    select(MonitoringEventRecord)
                    .where(
                        MonitoringEventRecord.tenant_id == self._target.tenant_id,
                        MonitoringEventRecord.application_id == self._target.application_id,
                        MonitoringEventRecord.environment == self._target.environment,
                    )
                    .order_by(MonitoringEventRecord.sequence)
                ).all()
            )
            return tuple(self._event_from_row(row) for row in rows)


__all__ = ["SqlAlchemyMonitoringStore"]
