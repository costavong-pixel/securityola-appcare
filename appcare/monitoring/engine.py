"""Restart-safe, provider-neutral BETA-08 monitoring engine."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Literal

from ..deployment.contracts import evidence_digest
from .contracts import (
    AlertRecord,
    AlertSeverity,
    InMemoryMonitoringStore,
    MonitorTarget,
    MonitoringEvent,
    MonitoringStore,
    MonthlyReport,
    Observation,
    UsageCostSample,
    utc,
)

_FINDING_KINDS = {"dependency", "secret", "config"}
LiteralAlertEvent = Literal[
    "alert_opened",
    "alert_repeated",
    "alert_suppressed",
    "alert_resolved",
]


class MonitoringEngine:
    """Evaluate observations without network calls or provider credentials."""

    def __init__(self, store: MonitoringStore, *, suppression_seconds: int = 3_600) -> None:
        if suppression_seconds < 0:
            raise ValueError("suppression_seconds must be non-negative")
        self._store = store
        self._suppression = timedelta(seconds=suppression_seconds)
        self._observations: list[Observation] = []
        self._alerts: dict[str, AlertRecord] = {}
        self._usage: list[UsageCostSample] = []
        self._replay(store.read())

    def _replay(self, events: Iterable[MonitoringEvent]) -> None:
        expected = 1
        for event in events:
            if event.sequence != expected:
                raise ValueError("monitoring evidence sequence is not contiguous")
            expected += 1
            if event.event_type == "observation":
                self._observations.append(event.as_observation())
            elif event.event_type == "usage_recorded":
                if event.usage is None:
                    raise ValueError("usage event has no usage sample")
                self._usage.append(event.usage)
            elif event.fingerprint is not None and event.alert_id is not None:
                current = self._alerts.get(event.fingerprint)
                if current is None:
                    current = AlertRecord(
                        alert_id=event.alert_id,
                        fingerprint=event.fingerprint,
                        target=event.target,
                        check_kind=event.check_kind or "uptime",
                        severity=event.severity or "low",
                        state=event.alert_state or "open",
                        first_seen=event.occurred_at,
                        last_seen=event.occurred_at,
                        occurrences=max(1, event.occurrences),
                        suppressed_count=event.suppressed_count,
                        evidence_refs=(event.evidence_ref,),
                    )
                else:
                    current = replace(
                        current,
                        state=event.alert_state or current.state,
                        last_seen=event.occurred_at,
                        occurrences=max(current.occurrences, event.occurrences),
                        suppressed_count=max(current.suppressed_count, event.suppressed_count),
                        evidence_refs=current.evidence_refs + (event.evidence_ref,),
                    )
                self._alerts[event.fingerprint] = current

    @property
    def events(self) -> tuple[MonitoringEvent, ...]:
        return self._store.read()

    @property
    def observations(self) -> tuple[Observation, ...]:
        return tuple(self._observations)

    def alerts(self, *, target: MonitorTarget | None = None) -> tuple[AlertRecord, ...]:
        alerts = tuple(self._alerts.values())
        if target is not None:
            alerts = tuple(alert for alert in alerts if alert.target.key == target.key)
        return tuple(sorted(alerts, key=lambda alert: alert.alert_id))

    def active_alerts(self, *, target: MonitorTarget | None = None) -> tuple[AlertRecord, ...]:
        return tuple(alert for alert in self.alerts(target=target) if alert.state == "open")

    def _append(self, event: MonitoringEvent) -> None:
        self._store.append(event)

    def _next_sequence(self) -> int:
        return len(self._store.read()) + 1

    @staticmethod
    def _severity(observation: Observation) -> AlertSeverity:
        if observation.check_kind in {"secret", "critical_flow"}:
            return "high"
        if observation.check_kind == "backup" and observation.status == "failed":
            return "critical"
        if observation.status == "failed":
            return "high"
        if observation.status == "degraded":
            return "medium"
        return "low"

    @staticmethod
    def _fingerprint(observation: Observation) -> str:
        return evidence_digest(
            "monitor-alert",
            observation.target.key,
            observation.check_kind,
            observation.reason_code or observation.status,
        )

    def _event_for_observation(self, observation: Observation) -> MonitoringEvent:
        return MonitoringEvent(
            sequence=self._next_sequence(),
            event_type="observation",
            occurred_at=observation.observed_at,
            target=observation.target,
            check_kind=observation.check_kind,
            status=observation.status,
            evidence_ref=observation.evidence_ref,
            summary=observation.summary,
            reason_code=observation.reason_code,
        )

    def _event_for_alert(
        self,
        *,
        event_type: LiteralAlertEvent,
        alert: AlertRecord,
        evidence_ref: str,
        summary: str,
    ) -> MonitoringEvent:
        return MonitoringEvent(
            sequence=self._next_sequence(),
            event_type=event_type,
            occurred_at=alert.last_seen,
            target=alert.target,
            check_kind=alert.check_kind,
            status="failed" if alert.state == "open" else "healthy",
            evidence_ref=evidence_ref,
            summary=summary,
            fingerprint=alert.fingerprint,
            alert_id=alert.alert_id,
            alert_state=alert.state,
            severity=alert.severity,
            occurrences=alert.occurrences,
            suppressed_count=alert.suppressed_count,
        )

    def observe(self, observation: Observation) -> AlertRecord | None:
        """Persist an observation and deduplicate or resolve its incident."""

        self._append(self._event_for_observation(observation))
        if observation.status == "healthy":
            self._resolve_for_observation(observation)
            return None

        fingerprint = self._fingerprint(observation)
        current = self._alerts.get(fingerprint)
        severity = self._severity(observation)
        if current is None or current.state == "resolved":
            alert = AlertRecord(
                alert_id=evidence_digest("monitor-alert-id", fingerprint),
                fingerprint=fingerprint,
                target=observation.target,
                check_kind=observation.check_kind,
                severity=severity,
                state="open",
                first_seen=observation.observed_at,
                last_seen=observation.observed_at,
                occurrences=1,
                suppressed_count=0,
                evidence_refs=(observation.evidence_ref,),
            )
            self._alerts[fingerprint] = alert
            self._append(
                self._event_for_alert(
                    event_type="alert_opened",
                    alert=alert,
                    evidence_ref=observation.evidence_ref,
                    summary="new monitoring incident opened",
                )
            )
            return alert

        within_window = observation.observed_at <= current.last_seen + self._suppression
        alert = replace(
            current,
            last_seen=observation.observed_at,
            occurrences=current.occurrences + 1,
            suppressed_count=current.suppressed_count + (1 if within_window else 0),
            evidence_refs=current.evidence_refs + (observation.evidence_ref,),
        )
        self._alerts[fingerprint] = alert
        event_type: LiteralAlertEvent = "alert_suppressed" if within_window else "alert_repeated"
        self._append(
            self._event_for_alert(
                event_type=event_type,
                alert=alert,
                evidence_ref=observation.evidence_ref,
                summary=(
                    "repeated monitoring incident suppressed"
                    if within_window
                    else "monitoring incident repeated after suppression window"
                ),
            )
        )
        return alert

    def _resolve_for_observation(self, observation: Observation) -> None:
        for fingerprint, current in tuple(self._alerts.items()):
            if (
                current.state == "open"
                and current.target.key == observation.target.key
                and current.check_kind == observation.check_kind
            ):
                resolved = replace(
                    current,
                    state="resolved",
                    last_seen=observation.observed_at,
                    evidence_refs=current.evidence_refs + (observation.evidence_ref,),
                )
                self._alerts[fingerprint] = resolved
                self._append(
                    self._event_for_alert(
                        event_type="alert_resolved",
                        alert=resolved,
                        evidence_ref=observation.evidence_ref,
                        summary="monitoring incident resolved",
                    )
                )

    def record_usage(self, sample: UsageCostSample) -> None:
        self._usage.append(sample)
        self._append(
            MonitoringEvent(
                sequence=self._next_sequence(),
                event_type="usage_recorded",
                occurred_at=sample.observed_at,
                target=sample.target,
                check_kind=None,
                status=None,
                evidence_ref=sample.evidence_ref,
                summary="sanitized usage sample recorded",
                usage=sample,
            )
        )

    def monthly_report(
        self,
        *,
        target: MonitorTarget,
        period_start: datetime,
        period_end: datetime,
    ) -> MonthlyReport:
        start = utc(period_start)
        end = utc(period_end)
        observations = tuple(
            observation
            for observation in self._observations
            if observation.target.key == target.key and start <= observation.observed_at < end
        )
        usage = tuple(
            sample
            for sample in self._usage
            if sample.target.key == target.key and start <= sample.observed_at < end
        )
        relevant_events = tuple(
            event
            for event in self.events
            if event.target.key == target.key and start <= event.occurred_at < end
        )
        findings = sum(
            observation.status != "healthy" and observation.check_kind in _FINDING_KINDS
            for observation in observations
        )
        fixes = sum(
            observation.status == "healthy" and observation.check_kind == "deployment"
            for observation in observations
        )
        backup_verified = sum(
            observation.status == "healthy" and observation.check_kind == "backup"
            for observation in observations
        )
        backup_failures = sum(
            observation.status != "healthy" and observation.check_kind == "backup"
            for observation in observations
        )
        opened = sum(event.event_type == "alert_opened" for event in relevant_events)
        resolved = sum(event.event_type == "alert_resolved" for event in relevant_events)
        evidence_digests = tuple(
            sorted(
                {
                    *(observation.digest for observation in observations),
                    *(event.digest for event in relevant_events),
                    *(sample.digest for sample in usage),
                }
            )
        )
        return MonthlyReport.create(
            target=target,
            period_start=start,
            period_end=end,
            observation_count=len(observations),
            finding_count=findings,
            fix_count=fixes,
            backup_verified_count=backup_verified,
            backup_failure_count=backup_failures,
            incidents_opened=opened,
            incidents_resolved=resolved,
            remaining_risk_count=len(self.active_alerts(target=target)),
            jobs=sum(sample.jobs for sample in usage),
            operator_minutes=sum(sample.operator_minutes for sample in usage),
            provider_cost_cents=sum(sample.provider_cost_cents for sample in usage),
            evidence_digests=evidence_digests,
        )


__all__ = ["LiteralAlertEvent", "MonitoringEngine"]
