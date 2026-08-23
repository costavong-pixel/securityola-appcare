"""BETA-08 monitoring, restart, reporting, and failure-boundary tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from appcare.monitoring import (
    BackupHealthCheck,
    InMemoryMonitoringStore,
    MonitorTarget,
    MonitoringBoundaryError,
    MonitoringEngine,
    Observation,
    UsageCostSample,
)

TARGET = MonitorTarget(
    tenant_id="tenant-1",
    application_id="app-1",
    environment="production",
    app_reference="appcare-app-1",
)
BASE = datetime(2026, 1, 1, tzinfo=UTC)


def observation(
    *,
    kind: str = "uptime",
    status: str = "failed",
    when: datetime = BASE,
    reason: str = "outage",
    evidence: str = "evidence-1",
) -> Observation:
    return Observation(
        target=TARGET,
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
