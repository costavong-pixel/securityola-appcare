"""Build dashboard state from persisted AppCare records only."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Literal, cast

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ..models import (
    Application,
    AuditEvent,
    Backup,
    Connector,
    Deployment,
    Finding,
    MonitoringEventRecord,
    User,
)
from ..services.audit import MetadataError, sanitize_text
from .contracts import (
    DashboardActivity,
    DashboardApplication,
    DashboardFindingSummary,
    DashboardSignal,
    DashboardSnapshot,
    DashboardStatus,
)


def _safe_text(value: str | None, fallback: str) -> str:
    try:
        sanitized = sanitize_text(value, max_length=300)
    except MetadataError:
        return fallback
    return sanitized or fallback


def _aware(value: datetime) -> datetime:
    """SQLite may return timezone-aware columns without tzinfo."""

    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _signal(
    statuses: list[str],
    *,
    healthy: set[str],
    attention: set[str],
    label: str,
    empty_detail: str,
    pending_detail: str,
    last_event_at: datetime | None = None,
) -> DashboardSignal:
    if not statuses:
        return DashboardSignal(
            status="unknown",
            label=label,
            detail=empty_detail,
            last_event_at=last_event_at,
        )
    if any(value in attention for value in statuses):
        return DashboardSignal(
            status="attention",
            label=label,
            detail="Recent evidence needs review.",
            last_event_at=last_event_at,
        )
    if all(value in healthy for value in statuses):
        return DashboardSignal(
            status="healthy",
            label=label,
            detail="Latest persisted evidence is current.",
            last_event_at=last_event_at,
        )
    return DashboardSignal(
        status="pending",
        label=label,
        detail=pending_detail,
        last_event_at=last_event_at,
    )


def build_dashboard_snapshot(session: Session, user: User) -> DashboardSnapshot:
    """Return only tenant-scoped, persisted, sanitized state."""

    tenant = user.tenant
    applications = list(
        session.scalars(
            select(Application)
            .where(Application.tenant_id == user.tenant_id)
            .order_by(desc(Application.updated_at), desc(Application.id))
            .limit(100)
        ).all()
    )
    findings = list(
        session.scalars(
            select(Finding)
            .where(Finding.tenant_id == user.tenant_id)
            .order_by(desc(Finding.updated_at), desc(Finding.id))
            .limit(500)
        ).all()
    )
    backups = list(
        session.scalars(
            select(Backup)
            .where(Backup.tenant_id == user.tenant_id)
            .order_by(desc(Backup.updated_at), desc(Backup.id))
            .limit(100)
        ).all()
    )
    connectors = list(
        session.scalars(
            select(Connector)
            .where(Connector.tenant_id == user.tenant_id)
            .order_by(desc(Connector.updated_at), desc(Connector.id))
            .limit(100)
        ).all()
    )
    deployments = list(
        session.scalars(
            select(Deployment)
            .where(Deployment.tenant_id == user.tenant_id)
            .order_by(desc(Deployment.updated_at), desc(Deployment.id))
            .limit(100)
        ).all()
    )

    by_application: dict[str, list[Finding]] = {}
    for finding in findings:
        by_application.setdefault(finding.application_id, []).append(finding)

    dashboard_applications = [
        DashboardApplication(
            id=application.id,
            name=_safe_text(application.name, "Unnamed application"),
            environment=cast(
                Literal["development", "staging", "production"], application.environment
            ),
            status=cast(Literal["active", "archived"], application.status),
            finding_count=len(by_application.get(application.id, [])),
            open_finding_count=sum(
                item.status == "open" for item in by_application.get(application.id, [])
            ),
        )
        for application in applications
    ]

    finding_counts = Counter(item.severity for item in findings)
    open_findings = sum(item.status == "open" for item in findings)
    finding_summary = DashboardFindingSummary(
        total=len(findings),
        open=open_findings,
        critical=finding_counts["critical"],
        high=finding_counts["high"],
        medium=finding_counts["medium"],
        low=finding_counts["low"],
        informational=finding_counts["informational"],
    )

    latest_backup_at = backups[0].updated_at if backups else None
    backup_signal = _signal(
        [item.status for item in backups],
        healthy={"verified"},
        attention={"failed", "expired"},
        label="Backup evidence",
        empty_detail="No backup evidence is recorded for this tenant.",
        pending_detail="Backup evidence is present but not yet verified.",
        last_event_at=latest_backup_at,
    )

    connector_values: list[str] = []
    for connector in connectors:
        connector_values.extend(
            [
                connector.status,
                connector.health_status,
                connector.permission_status,
                connector.ownership_status,
            ]
        )
    connector_signal = _signal(
        connector_values,
        healthy={"configured", "passed"},
        attention={"unavailable", "disabled", "failed"},
        label="Connector health",
        empty_detail="No connector health evidence is recorded.",
        pending_detail="Connector evidence is incomplete or still being checked.",
        last_event_at=connectors[0].last_checked_at if connectors else None,
    )

    deployment_signal = _signal(
        [item.status for item in deployments],
        healthy={"succeeded"},
        attention={"failed", "cancelled"},
        label="Deployment record",
        empty_detail="No deployment record is available.",
        pending_detail="A deployment is requested or still in progress.",
        last_event_at=deployments[0].updated_at if deployments else None,
    )

    monitoring_rows = list(
        session.scalars(
            select(MonitoringEventRecord)
            .where(
                MonitoringEventRecord.tenant_id == user.tenant_id,
                MonitoringEventRecord.status.is_not(None),
            )
            .order_by(desc(MonitoringEventRecord.occurred_at), desc(MonitoringEventRecord.sequence))
            .limit(200)
        ).all()
    )
    latest_monitoring = monitoring_rows[0] if monitoring_rows else None
    if latest_monitoring is None:
        monitoring_signal = DashboardSignal(
            status="unknown",
            label="Monitoring observations",
            detail="No persisted monitoring observation is recorded for this tenant.",
        )
    elif latest_monitoring.status == "healthy":
        monitoring_signal = DashboardSignal(
            status="healthy",
            label="Monitoring observations",
            detail="Latest persisted monitoring evidence is healthy.",
            last_event_at=_aware(latest_monitoring.occurred_at),
        )
    elif latest_monitoring.status in {"failed", "degraded"}:
        monitoring_signal = DashboardSignal(
            status="attention",
            label="Monitoring observations",
            detail="Latest persisted monitoring evidence needs review.",
            last_event_at=_aware(latest_monitoring.occurred_at),
        )
    else:
        monitoring_signal = DashboardSignal(
            status="unknown",
            label="Monitoring observations",
            detail="Latest persisted monitoring evidence is unknown.",
            last_event_at=_aware(latest_monitoring.occurred_at),
        )

    activity_rows = list(
        session.scalars(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == user.tenant_id)
            .order_by(desc(AuditEvent.occurred_at), desc(AuditEvent.id))
            .limit(10)
        ).all()
    )
    recent_activity = [
        DashboardActivity(
            action=_safe_text(item.action, "recorded action"),
            subject_type=_safe_text(item.subject_type, "record"),
            outcome=_safe_text(item.outcome, "unknown"),
            occurred_at=item.occurred_at,
        )
        for item in activity_rows
    ]

    signal_statuses = [
        backup_signal.status,
        connector_signal.status,
        deployment_signal.status,
        monitoring_signal.status,
    ]
    if not applications:
        overall_status: DashboardStatus = "empty"
    elif any(value == "attention" for value in signal_statuses) or open_findings:
        overall_status = "attention"
    elif any(value in {"pending", "unknown"} for value in signal_statuses):
        overall_status = "attention"
    else:
        overall_status = "healthy"

    return DashboardSnapshot(
        captured_at=datetime.now().astimezone(),
        tenant_name=_safe_text(tenant.name, "AppCare tenant"),
        overall_status=overall_status,
        application_count=len(applications),
        applications=dashboard_applications,
        findings=finding_summary,
        backup=backup_signal,
        connectors=connector_signal,
        deployments=deployment_signal,
        monitoring=monitoring_signal,
        recent_activity=recent_activity,
    )
