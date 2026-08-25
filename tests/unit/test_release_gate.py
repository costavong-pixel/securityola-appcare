from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from appcare.deployment.preproduction import PreproductionEvidence
from appcare.release.contracts import (
    DrillEvidence,
    EvidenceReceipt,
    ReleaseEvidence,
    ReleaseEvidenceError,
)
from appcare.release.fixtures import run_adversarial_fixtures
from appcare.release.gate import (
    REQUIRED_AUTHORITATIVE_RECEIPTS,
    REQUIRED_DRILLS,
    ReleaseGate,
    all_drills_passed,
    require_blocked,
)

HEAD = "1814c41c8269ad64fab6df659968550e6e85cb95"


def complete_evidence(*, preproduction_status: str = "pass") -> ReleaseEvidence:
    preproduction = PreproductionEvidence.create(
        tenant_id="tenant-release",
        application_id="application-release",
        provider="securityola-vps",
        target_type="controlled-reference",
        source_revision=HEAD,
        artifact_digest="d" * 64,
        environment_identity="appcare-staging-18567",
        deployment_reference="staging-deployment-release",
        deployment_timestamp=datetime(2026, 8, 25, tzinfo=UTC),
        smoke_test_receipt="smoke-release",
        security_test_receipt="security-release",
        rollback_reference_receipt="rollback-release",
        status=preproduction_status,  # type: ignore[arg-type]
    )
    return ReleaseEvidence(
        exact_head=HEAD,
        ci_passed=True,
        test_count=247,
        codex_security_findings=0,
        tenant_isolation=True,
        backup_restore=True,
        production_rollback=True,
        operator_stop=True,
        customer_report=True,
        dependency_scan=True,
        secret_scan=True,
        pricing_margin=True,
        known_limitations_published=True,
        preproduction_evidence=preproduction,
        drills=run_adversarial_fixtures(),
        authoritative_receipts=tuple(
            EvidenceReceipt(
                kind=kind,
                reference=f"receipt-{kind}",
                exact_head=HEAD,
                digest=(
                    preproduction.authoritative_evidence_digest
                    if kind == "preproduction_environment"
                    else "e" * 64
                ),
                passed=True,
            )
            for kind in REQUIRED_AUTHORITATIVE_RECEIPTS
        ),
    )


def test_all_controlled_adversarial_fixtures_pass_without_network() -> None:
    drills = run_adversarial_fixtures()
    assert tuple(drill.name for drill in drills) == REQUIRED_DRILLS
    assert all_drills_passed(drills)


def test_complete_evidence_is_ready_only_when_preproduction_evidence_passes() -> None:
    decision = ReleaseGate().evaluate(complete_evidence())
    assert decision.ready is True
    assert decision.status == "ready"
    assert decision.reason_codes == ()
    assert decision.live_production_enabled is False
    assert len(decision.evidence_digest) == 64


def test_unverified_preproduction_denies_release_even_when_drills_pass() -> None:
    decision = ReleaseGate().evaluate(complete_evidence(preproduction_status="fail"))
    require_blocked(decision, reason_code="VERIFIED_PREPRODUCTION_ENVIRONMENT_REQUIRED")
    assert decision.ready is False
    assert decision.status == "blocked"
    assert decision.to_public_dict()["live_production_enabled"] is False


def test_missing_and_failed_drills_are_blocking() -> None:
    drills = list(run_adversarial_fixtures())
    drills[-1] = replace(drills[-1], status="failed")
    evidence = replace(complete_evidence(), drills=tuple(drills[:-1]))
    decision = ReleaseGate().evaluate(evidence)
    assert decision.status == "blocked"
    assert "ADVERSARIAL_DRILLS_INCOMPLETE" in decision.reason_codes
    assert "ADVERSARIAL_DRILLS_FAILED" not in decision.reason_codes


def test_security_findings_and_missing_control_block_readiness() -> None:
    evidence = replace(complete_evidence(), codex_security_findings=1, operator_stop=False)
    decision = ReleaseGate().evaluate(evidence)
    assert "UNRESOLVED_CODEX_SECURITY_FINDINGS" in decision.reason_codes
    assert "OPERATOR_STOP_REQUIRED" in decision.reason_codes


def test_stale_authoritative_receipt_blocks_release() -> None:
    evidence = complete_evidence()
    stale = replace(
        evidence.authoritative_receipts[0],
        exact_head="f" * 40,
    )
    changed = replace(
        evidence,
        authoritative_receipts=(stale, *evidence.authoritative_receipts[1:]),
    )

    decision = ReleaseGate().evaluate(changed)

    assert "AUTHORITATIVE_EVIDENCE_HEAD_MISMATCH" in decision.reason_codes
    assert "receipt_head:exact_head_ci" in decision.failed_checks


def test_missing_or_failed_authoritative_receipt_blocks_release() -> None:
    evidence = complete_evidence()
    failed = replace(evidence.authoritative_receipts[1], passed=False)
    changed = replace(
        evidence,
        authoritative_receipts=(evidence.authoritative_receipts[0], failed),
    )

    decision = ReleaseGate().evaluate(changed)

    assert "AUTHORITATIVE_EVIDENCE_INCOMPLETE" in decision.reason_codes
    assert "AUTHORITATIVE_EVIDENCE_FAILED" in decision.reason_codes


def test_evidence_digest_is_deterministic_and_public_output_is_sanitized() -> None:
    first = complete_evidence(preproduction_status="fail")
    second = replace(first, drills=tuple(reversed(first.drills)))
    assert first.evidence_digest == second.evidence_digest
    assert "credential" not in str(ReleaseGate().evaluate(first).to_public_dict()).casefold()


def test_unsafe_drill_evidence_is_rejected() -> None:
    with pytest.raises(ReleaseEvidenceError):
        DrillEvidence(
            name="unsafe",
            status="passed",
            evidence_ref="fixture:unsafe:pass",
            summary="bearer secret-value",
        )
