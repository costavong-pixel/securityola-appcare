"""Sanitized, deterministic BETA-08 monitoring and reporting contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal, Protocol

from ..deployment.contracts import (
    evidence_digest,
    validate_opaque_reference,
    validate_reason_code,
)
from ..services.security import contains_credential_like

MonitorStatus = Literal["healthy", "degraded", "failed", "unknown"]
AlertSeverity = Literal["low", "medium", "high", "critical"]
AlertState = Literal["open", "resolved"]
CheckKind = Literal[
    "uptime",
    "critical_flow",
    "deployment",
    "dependency",
    "secret",
    "config",
    "backup",
]
MonitoringEventType = Literal[
    "observation",
    "alert_opened",
    "alert_repeated",
    "alert_suppressed",
    "alert_resolved",
    "usage_recorded",
]

_CHECK_KINDS = {
    "uptime",
    "critical_flow",
    "deployment",
    "dependency",
    "secret",
    "config",
    "backup",
}
_STATUSES = {"healthy", "degraded", "failed", "unknown"}
_SEVERITIES = {"low", "medium", "high", "critical"}
_EVENT_TYPES = {
    "observation",
    "alert_opened",
    "alert_repeated",
    "alert_suppressed",
    "alert_resolved",
    "usage_recorded",
}


class MonitoringBoundaryError(ValueError):
    """A monitoring value crosses the AppCare evidence boundary."""


def utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise MonitoringBoundaryError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _text(value: object, *, field_name: str, maximum: int = 240) -> str:
    if not isinstance(value, str):
        raise MonitoringBoundaryError(f"{field_name} must be text")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or any(ord(character) < 32 for character in normalized)
        or contains_credential_like(normalized)
    ):
        raise MonitoringBoundaryError(f"{field_name} is unsafe")
    return normalized


def _nonnegative(value: object, *, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise MonitoringBoundaryError(f"{field_name} must be non-negative")
    return value


@dataclass(frozen=True, slots=True)
class MonitorTarget:
    """One tenant/application scope; no customer content is stored."""

    tenant_id: str
    application_id: str
    environment: Literal["development", "staging", "production"]
    app_reference: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "tenant_id",
            validate_opaque_reference(self.tenant_id, field_name="tenant_id"),
        )
        object.__setattr__(
            self,
            "application_id",
            validate_opaque_reference(self.application_id, field_name="application_id"),
        )
        if self.environment not in {"development", "staging", "production"}:
            raise MonitoringBoundaryError("monitor environment is unsupported")
        object.__setattr__(
            self,
            "app_reference",
            validate_opaque_reference(self.app_reference, field_name="app_reference"),
        )

    @property
    def key(self) -> str:
        return f"{self.tenant_id}:{self.application_id}:{self.environment}"


@dataclass(frozen=True, slots=True)
class Observation:
    """A single sanitized check result."""

    target: MonitorTarget
    check_kind: CheckKind
    status: MonitorStatus
    observed_at: datetime
    evidence_ref: str
    summary: str
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.check_kind not in _CHECK_KINDS:
            raise MonitoringBoundaryError("check kind is unsupported")
        if self.status not in _STATUSES:
            raise MonitoringBoundaryError("monitor status is unsupported")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(
            self,
            "evidence_ref",
            validate_opaque_reference(self.evidence_ref, field_name="evidence_ref"),
        )
        object.__setattr__(
            self,
            "summary",
            _text(self.summary, field_name="summary"),
        )
        if self.reason_code is not None:
            object.__setattr__(
                self,
                "reason_code",
                validate_reason_code(self.reason_code, field_name="reason_code"),
            )

    @property
    def digest(self) -> str:
        return evidence_digest(
            "monitor-observation",
            self.target.key,
            self.check_kind,
            self.status,
            self.observed_at.isoformat(),
            self.evidence_ref,
            self.summary,
            self.reason_code or "none",
        )


@dataclass(frozen=True, slots=True)
class BackupHealthCheck:
    """Input contract whose result is never healthy without verified evidence."""

    target: MonitorTarget
    observed_at: datetime
    evidence_ref: str
    latest_verified_at: datetime | None
    integrity_verified: bool
    freshness_limit_seconds: int
    failure_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        if self.latest_verified_at is not None:
            object.__setattr__(self, "latest_verified_at", utc(self.latest_verified_at))
        object.__setattr__(
            self,
            "evidence_ref",
            validate_opaque_reference(self.evidence_ref, field_name="evidence_ref"),
        )
        if not isinstance(self.integrity_verified, bool):
            raise MonitoringBoundaryError("integrity_verified must be boolean")
        object.__setattr__(
            self,
            "freshness_limit_seconds",
            _nonnegative(self.freshness_limit_seconds, field_name="freshness_limit_seconds"),
        )
        if self.failure_code is not None:
            object.__setattr__(
                self,
                "failure_code",
                validate_reason_code(self.failure_code, field_name="failure_code"),
            )

    def observation(self) -> Observation:
        if self.failure_code is not None:
            reason = self.failure_code
            status: MonitorStatus = "failed"
            summary = "backup verification reported failure"
        elif self.latest_verified_at is None:
            reason = "backup_missing"
            status = "failed"
            summary = "no verified backup evidence is available"
        elif self.latest_verified_at > self.observed_at:
            reason = "backup_timestamp_invalid"
            status = "failed"
            summary = "backup verification timestamp is invalid"
        elif not self.integrity_verified:
            reason = "backup_integrity_failed"
            status = "failed"
            summary = "latest backup integrity verification failed"
        elif (
            self.observed_at - self.latest_verified_at
        ).total_seconds() > self.freshness_limit_seconds:
            reason = "backup_stale"
            status = "failed"
            summary = "latest verified backup is outside the freshness target"
        else:
            reason = "backup_healthy"
            status = "healthy"
            summary = "latest verified backup is fresh and integrity verified"
        return Observation(
            target=self.target,
            check_kind="backup",
            status=status,
            observed_at=self.observed_at,
            evidence_ref=self.evidence_ref,
            summary=summary,
            reason_code=reason,
        )


@dataclass(frozen=True, slots=True)
class UsageCostSample:
    """Sanitized usage and cost accounting for one application observation."""

    target: MonitorTarget
    observed_at: datetime
    evidence_ref: str
    jobs: int
    operator_minutes: int
    provider_cost_cents: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(
            self,
            "evidence_ref",
            validate_opaque_reference(self.evidence_ref, field_name="evidence_ref"),
        )
        for name in ("jobs", "operator_minutes", "provider_cost_cents"):
            object.__setattr__(
                self,
                name,
                _nonnegative(getattr(self, name), field_name=name),
            )

    @property
    def digest(self) -> str:
        return evidence_digest(
            "monitor-usage",
            self.target.key,
            self.observed_at.isoformat(),
            self.evidence_ref,
            str(self.jobs),
            str(self.operator_minutes),
            str(self.provider_cost_cents),
        )


@dataclass(frozen=True, slots=True)
class AlertRecord:
    """One deduplicated incident, represented only by safe evidence references."""

    alert_id: str
    fingerprint: str
    target: MonitorTarget
    check_kind: CheckKind
    severity: AlertSeverity
    state: AlertState
    first_seen: datetime
    last_seen: datetime
    occurrences: int
    suppressed_count: int
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("alert_id", "fingerprint"):
            object.__setattr__(
                self,
                name,
                validate_opaque_reference(getattr(self, name), field_name=name),
            )
        if self.check_kind not in _CHECK_KINDS or self.severity not in _SEVERITIES:
            raise MonitoringBoundaryError("alert classification is unsupported")
        if self.state not in {"open", "resolved"}:
            raise MonitoringBoundaryError("alert state is unsupported")
        object.__setattr__(self, "first_seen", utc(self.first_seen))
        object.__setattr__(self, "last_seen", utc(self.last_seen))
        object.__setattr__(
            self,
            "occurrences",
            _nonnegative(self.occurrences, field_name="occurrences"),
        )
        object.__setattr__(
            self,
            "suppressed_count",
            _nonnegative(self.suppressed_count, field_name="suppressed_count"),
        )
        if not self.evidence_refs:
            raise MonitoringBoundaryError("alert needs evidence")
        object.__setattr__(
            self,
            "evidence_refs",
            tuple(
                validate_opaque_reference(ref, field_name="alert evidence_ref")
                for ref in self.evidence_refs[-8:]
            ),
        )


@dataclass(frozen=True, slots=True)
class MonitoringEvent:
    """Append-only event used to rebuild monitoring state after restart."""

    sequence: int
    event_type: MonitoringEventType
    occurred_at: datetime
    target: MonitorTarget
    check_kind: CheckKind | None
    status: MonitorStatus | None
    evidence_ref: str
    summary: str
    reason_code: str | None = None
    fingerprint: str | None = None
    alert_id: str | None = None
    alert_state: AlertState | None = None
    severity: AlertSeverity | None = None
    occurrences: int = 0
    suppressed_count: int = 0
    usage: UsageCostSample | None = None
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if self.sequence < 1 or self.event_type not in _EVENT_TYPES:
            raise MonitoringBoundaryError("monitoring event identity is invalid")
        object.__setattr__(self, "occurred_at", utc(self.occurred_at))
        object.__setattr__(
            self,
            "evidence_ref",
            validate_opaque_reference(self.evidence_ref, field_name="event evidence_ref"),
        )
        object.__setattr__(
            self,
            "summary",
            _text(self.summary, field_name="event summary"),
        )
        if self.check_kind is not None and self.check_kind not in _CHECK_KINDS:
            raise MonitoringBoundaryError("event check kind is unsupported")
        if self.status is not None and self.status not in _STATUSES:
            raise MonitoringBoundaryError("event status is unsupported")
        if self.reason_code is not None:
            object.__setattr__(
                self,
                "reason_code",
                validate_reason_code(self.reason_code, field_name="reason_code"),
            )
        for name in ("fingerprint", "alert_id"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(
                    self,
                    name,
                    validate_opaque_reference(value, field_name=name),
                )
        if self.alert_state is not None and self.alert_state not in {"open", "resolved"}:
            raise MonitoringBoundaryError("event alert state is unsupported")
        if self.severity is not None and self.severity not in _SEVERITIES:
            raise MonitoringBoundaryError("event severity is unsupported")
        object.__setattr__(
            self,
            "occurrences",
            _nonnegative(self.occurrences, field_name="occurrences"),
        )
        object.__setattr__(
            self,
            "suppressed_count",
            _nonnegative(self.suppressed_count, field_name="suppressed_count"),
        )
        if self.event_type == "usage_recorded" and self.usage is None:
            raise MonitoringBoundaryError("usage event needs usage data")
        if self.event_type != "usage_recorded" and self.usage is not None:
            raise MonitoringBoundaryError("non-usage event cannot carry usage data")
        object.__setattr__(
            self,
            "digest",
            evidence_digest(
                "monitor-event",
                str(self.sequence),
                self.event_type,
                self.occurred_at.isoformat(),
                self.target.key,
                self.check_kind or "none",
                self.status or "none",
                self.evidence_ref,
                self.summary,
                self.reason_code or "none",
                self.fingerprint or "none",
                self.alert_id or "none",
                self.alert_state or "none",
                self.severity or "none",
                str(self.occurrences),
                str(self.suppressed_count),
                self.usage.digest if self.usage is not None else "none",
            ),
        )

    def as_observation(self) -> Observation:
        if self.event_type != "observation" or self.check_kind is None or self.status is None:
            raise MonitoringBoundaryError("event is not an observation")
        return Observation(
            target=self.target,
            check_kind=self.check_kind,
            status=self.status,
            observed_at=self.occurred_at,
            evidence_ref=self.evidence_ref,
            summary=self.summary,
            reason_code=self.reason_code,
        )


class MonitoringStore(Protocol):
    """Append-only persistence boundary; implementations may be database backed."""

    def append(self, event: MonitoringEvent) -> None:
        """Persist one event without rewriting prior events."""

    def read(self) -> tuple[MonitoringEvent, ...]:
        """Read events in sequence order."""


@dataclass
class InMemoryMonitoringStore:
    """Deterministic fixture store shared across engine restarts."""

    _events: list[MonitoringEvent] = field(default_factory=list)

    def append(self, event: MonitoringEvent) -> None:
        expected = len(self._events) + 1
        if event.sequence != expected:
            raise MonitoringBoundaryError("monitoring event sequence is not append-only")
        self._events.append(event)

    def read(self) -> tuple[MonitoringEvent, ...]:
        return tuple(self._events)


@dataclass(frozen=True, slots=True)
class MonthlyReport:
    """Customer-safe aggregate with deterministic evidence identity."""

    target: MonitorTarget
    period_start: datetime
    period_end: datetime
    observation_count: int
    finding_count: int
    fix_count: int
    backup_verified_count: int
    backup_failure_count: int
    incidents_opened: int
    incidents_resolved: int
    remaining_risk_count: int
    jobs: int
    operator_minutes: int
    provider_cost_cents: int
    evidence_digests: tuple[str, ...]
    report_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "period_start", utc(self.period_start))
        object.__setattr__(self, "period_end", utc(self.period_end))
        if self.period_start >= self.period_end:
            raise MonitoringBoundaryError("report period is invalid")
        for name in (
            "observation_count",
            "finding_count",
            "fix_count",
            "backup_verified_count",
            "backup_failure_count",
            "incidents_opened",
            "incidents_resolved",
            "remaining_risk_count",
            "jobs",
            "operator_minutes",
            "provider_cost_cents",
        ):
            object.__setattr__(
                self,
                name,
                _nonnegative(getattr(self, name), field_name=name),
            )
        object.__setattr__(self, "evidence_digests", tuple(sorted(set(self.evidence_digests))))
        object.__setattr__(
            self,
            "report_digest",
            validate_opaque_reference(self.report_digest, field_name="report_digest"),
        )

    @classmethod
    def create(
        cls,
        *,
        target: MonitorTarget,
        period_start: datetime,
        period_end: datetime,
        observation_count: int,
        finding_count: int,
        fix_count: int,
        backup_verified_count: int,
        backup_failure_count: int,
        incidents_opened: int,
        incidents_resolved: int,
        remaining_risk_count: int,
        jobs: int,
        operator_minutes: int,
        provider_cost_cents: int,
        evidence_digests: tuple[str, ...],
    ) -> MonthlyReport:
        start = utc(period_start)
        end = utc(period_end)
        normalized_digests = tuple(sorted(set(evidence_digests)))
        digest = evidence_digest(
            "monthly-report",
            target.key,
            start.isoformat(),
            end.isoformat(),
            str(observation_count),
            str(finding_count),
            str(fix_count),
            str(backup_verified_count),
            str(backup_failure_count),
            str(incidents_opened),
            str(incidents_resolved),
            str(remaining_risk_count),
            str(jobs),
            str(operator_minutes),
            str(provider_cost_cents),
            *normalized_digests,
        )
        return cls(
            target=target,
            period_start=start,
            period_end=end,
            observation_count=observation_count,
            finding_count=finding_count,
            fix_count=fix_count,
            backup_verified_count=backup_verified_count,
            backup_failure_count=backup_failure_count,
            incidents_opened=incidents_opened,
            incidents_resolved=incidents_resolved,
            remaining_risk_count=remaining_risk_count,
            jobs=jobs,
            operator_minutes=operator_minutes,
            provider_cost_cents=provider_cost_cents,
            evidence_digests=normalized_digests,
            report_digest=digest,
        )


__all__ = [
    "AlertRecord",
    "AlertSeverity",
    "AlertState",
    "BackupHealthCheck",
    "CheckKind",
    "InMemoryMonitoringStore",
    "MonitorStatus",
    "MonitorTarget",
    "MonitoringBoundaryError",
    "MonitoringEvent",
    "MonitoringEventType",
    "MonitoringStore",
    "MonthlyReport",
    "Observation",
    "UsageCostSample",
    "utc",
]
