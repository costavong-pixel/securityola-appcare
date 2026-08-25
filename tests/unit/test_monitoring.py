"""BETA-08 monitoring, restart, reporting, and failure-boundary tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from appcare.monitoring import (
    BackupHealthCheck,
    InMemoryMonitoringStore,
    MonitoringBoundaryError,
    MonitoringEngine,
    MonitorTarget,
    Observation,
    SqlAlchemyMonitoringStore,
    UsageCostSample,
)
from tests.control_plane_helpers import create_application, issue_token, new_test_app, seed_user

TARGET = MonitorTarget(
    tenant_id="tenant-1",
    application_id="app-1",
    environment="production",
    app_reference="appcare-app-1",
)
BASE = datetime(2026, 1, 1, tzinfo=UTC)


def observation(
    *,
    target: MonitorTarget = TARGET,
    kind: str = "uptime",
    status: str = "failed",
    when: datetime = BASE,
    reason: str = "outage",
    evidence: str = "evidence-1",
) -> Observation:
    return Observation(
        target=target,
        check_kind=kind,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        observed_at=when,
        evidence_ref=evidence,
        summary="seeded monitor evidence",
        reason_code=reason,
    )


def test_backup_missing_stale_or_unverified_is_never_healthy() -> None:
    missing = BackupHealthCheck(
        target=TARGET,
        observed_at=BASE,
        evidence_ref="backup-missing",
        latest_verified_at=None,
        integrity_verified=False,
        freshness_limit_seconds=86_400,
    ).observation()
    stale = BackupHealthCheck(
        target=TARGET,
        observed_at=BASE + timedelta(days=2),
        evidence_ref="backup-stale",
        latest_verified_at=BASE,
        integrity_verified=True,
        freshness_limit_seconds=86_400,
    ).observation()
    broken = BackupHealthCheck(
        target=TARGET,
        observed_at=BASE,
        evidence_ref="backup-broken",
        latest_verified_at=BASE,
        integrity_verified=False,
        freshness_limit_seconds=86_400,
    ).observation()

    assert missing.status == "failed"
    assert missing.reason_code == "backup_missing"
    assert stale.status == "failed"
    assert stale.reason_code == "backup_stale"
    assert broken.status == "failed"
    assert broken.reason_code == "backup_integrity_failed"


def test_alerts_are_deduplicated_and_suppressed() -> None:
    store = InMemoryMonitoringStore()
    engine = MonitoringEngine(store, suppression_seconds=3_600)

    first = engine.observe(observation())
    second = engine.observe(observation(when=BASE + timedelta(minutes=10), evidence="evidence-2"))

    assert first is not None
    assert second is not None
    assert len(engine.alerts()) == 1
    assert len(engine.active_alerts()) == 1
    assert second.occurrences == 2
    assert second.suppressed_count == 1
    assert [event.event_type for event in engine.events] == [
        "observation",
        "alert_opened",
        "observation",
        "alert_suppressed",
    ]


def test_incident_resolves_and_state_survives_restart() -> None:
    store = InMemoryMonitoringStore()
    engine = MonitoringEngine(store)
    engine.observe(observation())
    engine.observe(
        observation(
            status="healthy",
            reason="healthy",
            when=BASE + timedelta(hours=2),
            evidence="evidence-healthy",
        )
    )
    restarted = MonitoringEngine(store)

    assert restarted.active_alerts() == ()
    assert restarted.alerts()[0].state == "resolved"
    assert restarted.events[-1].event_type == "alert_resolved"


def test_monthly_report_is_deterministic_and_accounts_for_cost() -> None:
    store = InMemoryMonitoringStore()
    engine = MonitoringEngine(store)
    engine.observe(observation())
    engine.observe(
        observation(
            kind="dependency",
            reason="dependency_update_required",
            evidence="finding-1",
        )
    )
    engine.observe(
        observation(
            kind="deployment",
            status="healthy",
            reason="deployment_verified",
            evidence="fix-1",
        )
    )
    engine.observe(
        BackupHealthCheck(
            target=TARGET,
            observed_at=BASE,
            evidence_ref="backup-good",
            latest_verified_at=BASE,
            integrity_verified=True,
            freshness_limit_seconds=86_400,
        ).observation()
    )
    engine.record_usage(
        UsageCostSample(
            target=TARGET,
            observed_at=BASE,
            evidence_ref="usage-1",
            jobs=4,
            operator_minutes=15,
            provider_cost_cents=27,
        )
    )

    first = engine.monthly_report(
        target=TARGET,
        period_start=BASE,
        period_end=BASE + timedelta(days=31),
    )
    second = engine.monthly_report(
        target=TARGET,
        period_start=BASE,
        period_end=BASE + timedelta(days=31),
    )

    assert first == second
    assert first.finding_count == 1
    assert first.fix_count == 1
    assert first.backup_verified_count == 1
    assert first.jobs == 4
    assert first.operator_minutes == 15
    assert first.provider_cost_cents == 27
    assert first.report_digest


def test_monitoring_rejects_credential_like_summary() -> None:
    with pytest.raises(MonitoringBoundaryError, match="summary"):
        Observation(
            target=TARGET,
            check_kind="uptime",
            status="failed",
            observed_at=BASE,
            evidence_ref="safe",
            summary="Bearer abcdefghijklmnopqrst",
            reason_code="credential_like",
        )


def test_database_monitoring_store_replays_after_restart_and_is_tenant_scoped(
    tmp_path: Path,
) -> None:
    app = new_test_app(f"sqlite+pysqlite:///{(tmp_path / 'appcare-monitor.db').as_posix()}")
    first_user = seed_user(app, "Monitor first")
    second_user = seed_user(app, "Monitor second")
    with TestClient(app) as client:
        first_token = issue_token(client, first_user.email)
        second_token = issue_token(client, second_user.email)
        first_application = create_application(client, first_token, "First monitor app")
        second_application = create_application(client, second_token, "Second monitor app")

    first_target = MonitorTarget(
        tenant_id=first_user.tenant_id,
        application_id=str(first_application["id"]),
        environment="development",
        app_reference="first-monitor-app",
    )
    second_target = MonitorTarget(
        tenant_id=second_user.tenant_id,
        application_id=str(second_application["id"]),
        environment="development",
        app_reference="second-monitor-app",
    )
    first_store = SqlAlchemyMonitoringStore(app.state.database.session_factory, target=first_target)
    second_store = SqlAlchemyMonitoringStore(
        app.state.database.session_factory,
        target=second_target,
    )
    first_engine = MonitoringEngine(first_store)
    first_engine.observe(
        Observation(
            target=first_target,
            check_kind="uptime",
            status="failed",
            observed_at=BASE,
            evidence_ref="first-outage",
            summary="synthetic staging outage",
            reason_code="outage",
        )
    )
    second_engine = MonitoringEngine(second_store)
    second_engine.observe(
        Observation(
            target=second_target,
            check_kind="uptime",
            status="healthy",
            observed_at=BASE,
            evidence_ref="second-healthy",
            summary="synthetic staging healthy",
            reason_code="healthy",
        )
    )

    restarted = MonitoringEngine(
        SqlAlchemyMonitoringStore(app.state.database.session_factory, target=first_target)
    )

    assert len(restarted.events) == 2
    assert restarted.active_alerts()
    assert all(event.target.tenant_id == first_user.tenant_id for event in restarted.events)
    assert (
        SqlAlchemyMonitoringStore(
            app.state.database.session_factory,
            target=second_target,
        )
        .read()[0]
        .target.tenant_id
        == second_user.tenant_id
    )


def test_database_monitoring_evidence_is_append_only(tmp_path: Path) -> None:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'appcare-monitor-immutable.db').as_posix()}"
    app = new_test_app(database_url)
    user = seed_user(app, "Monitor immutable")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        application = create_application(client, token, "Immutable monitor app")
    target = MonitorTarget(
        tenant_id=user.tenant_id,
        application_id=str(application["id"]),
        environment="development",
        app_reference="immutable-monitor-app",
    )
    store = SqlAlchemyMonitoringStore(app.state.database.session_factory, target=target)
    MonitoringEngine(store).observe(observation(target=target))

    from sqlalchemy import update

    from appcare.models import MonitoringEventRecord

    with pytest.raises(Exception, match="immutable"):
        with app.state.database.session_factory() as session:
            session.execute(
                update(MonitoringEventRecord)
                .where(MonitoringEventRecord.tenant_id == user.tenant_id)
                .values(summary="tampered")
            )
            session.commit()
