"""Unit coverage for deterministic scanning identities and boundaries."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from appcare.scanning import (
    CanonicalizationError,
    SanitizedTargetInput,
    ScanContext,
    ScannerObservation,
    ScopeError,
    build_evidence,
    canonical_json,
    canonicalize,
    finding_fingerprint,
    suppress_finding,
    validate_scope,
)


def _context() -> ScanContext:
    return ScanContext("tenant-appcare-1", "target-appcare-1", scan_id="scan-beta-3")


def _observation(*, observed_at: datetime | None = None) -> ScannerObservation:
    return ScannerObservation(
        adapter_kind="source",
        rule_id="source.debug",
        title="Debug setting enabled",
        summary="A release configuration enables debug behavior.",
        location="config/settings.py",
        asset_id="config-file",
        severity="high",
        confidence="high",
        raw_evidence={"actual": "enabled", "expected": "disabled", "setting": "debug"},
        observed_at=observed_at,
    )


def test_canonicalization_sorts_keys_and_sequence_values() -> None:
    left = {"z": [3, 1], "a": {"B": " value ", "a": True}}
    right = {"a": {"a": True, "b": "value"}, "z": [1, 3]}

    assert canonicalize(left) == canonicalize(right)
    assert canonical_json(left) == canonical_json(right)


def test_canonicalization_rejects_secret_keys_and_credential_shaped_values() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({"api_key": "sample-value"})
    with pytest.raises(CanonicalizationError):
        canonicalize({"value": "https://user:sample@invalid.example"})


def test_evidence_identity_excludes_observation_timestamp() -> None:
    context = _context()
    first = _observation(observed_at=datetime(2026, 8, 17, 12, 0, tzinfo=UTC))
    second = _observation(observed_at=datetime(2026, 8, 17, 12, 1, tzinfo=UTC))

    first_evidence = build_evidence(
        context,
        source="scanner.source",
        kind="observation",
        payload={"rule": first.rule_id, "value": first.raw_evidence},
        observed_at=first.observed_at,
    )
    second_evidence = build_evidence(
        context,
        source="scanner.source",
        kind="observation",
        payload={"rule": second.rule_id, "value": second.raw_evidence},
        observed_at=second.observed_at,
    )

    assert first_evidence.evidence_id == second_evidence.evidence_id
    assert first_evidence.observed_at != second_evidence.observed_at


def test_fingerprint_is_stable_for_the_same_evidence() -> None:
    values: dict[str, str] = {
        "tenant_id": "tenant-appcare-1",
        "target_id": "target-appcare-1",
        "adapter_kind": "source",
        "rule_id": "source.debug",
        "asset_id": "config-file",
        "location": "config/settings.py",
        "severity": "high",
        "confidence": "high",
        "evidence_id": "a" * 64,
    }
    assert finding_fingerprint(**values) == finding_fingerprint(**values)


def test_scope_requires_exact_tenant_target_and_enabled_adapter() -> None:
    context = _context()
    validate_scope(
        context,
        tenant_id=context.tenant_id,
        target_id=context.target_id,
        adapter_kind="source",
    )
    with pytest.raises(ScopeError):
        validate_scope(
            context,
            tenant_id="tenant-other",
            target_id=context.target_id,
            adapter_kind="source",
        )
    with pytest.raises(ScopeError):
        validate_scope(
            context,
            tenant_id=context.tenant_id,
            target_id="target-other",
            adapter_kind="source",
        )


def test_target_payload_is_not_allowed_to_change_target_scope() -> None:
    context = _context()
    with pytest.raises(ScopeError):
        from appcare.scanning import validate_target_input

        validate_target_input(context, SanitizedTargetInput("target-other", {"marker": "sample"}))


def test_suppression_preserves_fingerprint_and_evidence() -> None:
    from appcare.scanning import normalize_observation

    finding, evidence = normalize_observation(_context(), _observation())
    suppressed, decision = suppress_finding(
        _context(), finding, reason="accepted test fixture", actor="reviewer"
    )

    assert suppressed.status == "suppressed"
    assert suppressed.fingerprint == finding.fingerprint
    assert suppressed.evidence_ids == (evidence.evidence_id,)
    assert decision.fingerprint == finding.fingerprint


def test_fixture_payload_shape_is_mapping() -> None:
    payload: dict[str, Any] = {"marker": "sample", "count": 1}
    assert canonicalize(payload) == {"count": 1, "marker": "sample"}
