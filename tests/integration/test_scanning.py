"""Integration coverage for the BETA-03 deterministic scanning pipeline."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from appcare.scanning import (
    DependencyScannerAdapter,
    FunctionalScannerAdapter,
    ScanContext,
    ScannerObservation,
    SecretScannerAdapter,
    SourceScannerAdapter,
    run_scan,
    suppress_finding,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "scanning"


def _fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _observation(data: Mapping[str, Any]) -> ScannerObservation:
    return ScannerObservation(
        adapter_kind=data["adapter_kind"],
        rule_id=data["rule_id"],
        title=data["title"],
        summary=data["summary"],
        location=data["location"],
        asset_id=data["asset_id"],
        severity=data["severity"],
        confidence=data["confidence"],
        raw_evidence=data.get("raw_evidence", {}),
        metadata=data.get("metadata", {}),
        tenant_id=data.get("tenant_id"),
        target_id=data.get("target_id"),
    )


def _context() -> ScanContext:
    return ScanContext("tenant-appcare-1", "target-appcare-1", scan_id="scan-beta-3")


def test_pipeline_normalizes_deduplicates_and_records_failures_separately() -> None:
    vulnerable = _observation(_fixture("vulnerable.json"))
    duplicates = tuple(_observation(item) for item in _fixture("duplicate.json"))

    def source_scan(_context: ScanContext, _target: Any) -> list[ScannerObservation]:
        return [vulnerable]

    def dependency_scan(_context: ScanContext, _target: Any) -> tuple[ScannerObservation, ...]:
        return duplicates

    def secret_scan(_context: ScanContext, _target: Any) -> list[ScannerObservation]:
        raise TimeoutError

    result = run_scan(
        _context(),
        [
            SourceScannerAdapter(source_scan),
            DependencyScannerAdapter(dependency_scan),
            SecretScannerAdapter(secret_scan),
        ],
    )

    assert len(result.findings) == 2
    assert len(result.failures) == 1
    assert result.failures[0].code == "timeout"
    assert result.failures[0].evidence_id is not None
    assert len(result.evidence) == 3
    assert all(finding.tenant_id == "tenant-appcare-1" for finding in result.findings)
    assert all(finding.target_id == "target-appcare-1" for finding in result.findings)
    duplicate_finding = next(
        finding for finding in result.findings if finding.rule_id == "dependency.outdated"
    )
    assert len(duplicate_finding.evidence_ids) == 1


def test_out_of_scope_observation_becomes_failure_not_finding() -> None:
    observation = _observation(_fixture("out_of_scope.json"))

    result = run_scan(
        _context(),
        [SecretScannerAdapter(lambda _context, _target: [observation])],
    )

    assert result.findings == ()
    assert len(result.failures) == 1
    assert result.failures[0].code == "out_of_scope"
    assert result.evidence[0].kind == "scanner_failure"


def test_malformed_adapter_output_is_not_promoted_to_a_finding() -> None:
    malformed = _fixture("malformed.json")
    result = run_scan(
        _context(),
        [FunctionalScannerAdapter("source", lambda _context, _target: [malformed])],
    )

    assert result.findings == ()
    assert result.failures[0].code == "malformed_output"
    assert result.evidence[0].kind == "scanner_failure"


def test_false_positive_can_be_suppressed_after_deterministic_finding() -> None:
    observation = _observation(_fixture("false_positive.json"))
    result = run_scan(_context(), [SourceScannerAdapter(lambda _context, _target: [observation])])

    assert len(result.findings) == 1
    assert result.findings[0].status == "active"
    suppressed, decision = suppress_finding(
        _context(), result.findings[0], reason="accepted test fixture", actor="reviewer"
    )
    assert suppressed.status == "suppressed"
    assert suppressed.evidence_ids == result.findings[0].evidence_ids
    assert decision.fingerprint == result.findings[0].fingerprint


def test_scanner_failure_fixture_is_not_a_finding() -> None:
    failure_fixture = _fixture("scanner_failure.json")

    def failing_scan(_context: ScanContext, _target: Any) -> list[ScannerObservation]:
        raise TimeoutError(failure_fixture["message"])

    result = run_scan(_context(), [SecretScannerAdapter(failing_scan)])

    assert result.findings == ()
    assert result.failures[0].code == failure_fixture["code"]
    assert result.failures[0].retryable is True


def test_pipeline_rejects_target_before_custom_adapter_execution() -> None:
    called = False

    class RecordingAdapter:
        adapter_kind: Literal["source"] = "source"

        def scan(self, context: ScanContext, target: Any) -> Any:
            nonlocal called
            called = True
            return FunctionalScannerAdapter("source", lambda _context, _target: []).scan(
                context, target
            )

    from appcare.scanning import SanitizedTargetInput, ScopeError

    try:
        run_scan(_context(), [RecordingAdapter()], SanitizedTargetInput("target-other"))
    except ScopeError:
        pass
    else:
        raise AssertionError("out-of-scope target was accepted")
    assert called is False
