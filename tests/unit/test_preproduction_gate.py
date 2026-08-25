"""Provider-neutral preproduction evidence and real-adapter boundaries."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from appcare.deployment import (
    VERCEL_CAPABILITIES,
    DeploymentIntent,
    FilesystemReferenceProvider,
    InMemoryPreproductionEvidenceStore,
    PreproductionEvidence,
    ProductionControlError,
    ReferenceDeploymentConfig,
    SqlAlchemyPreproductionEvidenceStore,
)
from tests.control_plane_helpers import create_application, issue_token, new_test_app, seed_user


def _evidence(
    *, tenant_id: str = "tenant-a", application_id: str = "application-a"
) -> PreproductionEvidence:
    return PreproductionEvidence.create(
        tenant_id=tenant_id,
        application_id=application_id,
        provider="securityola-vps",
        target_type="controlled-reference",
        source_revision="a" * 40,
        artifact_digest="b" * 64,
        environment_identity="appcare-staging-18567",
        deployment_reference="deployment-reference-a",
        deployment_timestamp=datetime(2026, 8, 25, tzinfo=UTC),
        smoke_test_receipt="smoke-receipt-a",
        security_test_receipt="security-receipt-a",
        rollback_reference_receipt="rollback-receipt-a",
    )


def test_preproduction_evidence_is_exact_head_bound_and_tamper_evident() -> None:
    evidence = _evidence()
    assert evidence.passed is True
    assert evidence.exact_head == evidence.source_revision
    assert evidence.authoritative_evidence_digest == evidence.compute_digest()

    with pytest.raises(ProductionControlError, match="digest mismatch"):
        replace(evidence, authoritative_evidence_digest="c" * 64)


def test_in_memory_preproduction_store_is_tenant_and_artifact_scoped() -> None:
    store = InMemoryPreproductionEvidenceStore()
    evidence = _evidence()
    store.save(evidence)
    assert (
        store.resolve(
            tenant_id=evidence.tenant_id,
            application_id=evidence.application_id,
            source_revision=evidence.source_revision,
            artifact_digest=evidence.artifact_digest,
            evidence_digest=evidence.authoritative_evidence_digest,
        )
        == evidence
    )
    assert (
        store.resolve(
            tenant_id="tenant-b",
            application_id=evidence.application_id,
            source_revision=evidence.source_revision,
            artifact_digest=evidence.artifact_digest,
            evidence_digest=evidence.authoritative_evidence_digest,
        )
        is None
    )
    assert (
        store.resolve(
            tenant_id=evidence.tenant_id,
            application_id=evidence.application_id,
            source_revision=evidence.source_revision,
            artifact_digest="d" * 64,
            evidence_digest=evidence.authoritative_evidence_digest,
        )
        is None
    )


def test_persisted_preproduction_store_is_exact_and_tenant_scoped() -> None:
    app = new_test_app()
    tenant_a = seed_user(app, "Persisted A")
    tenant_b = seed_user(app, "Persisted B")
    with TestClient(app) as client:
        application = create_application(
            client,
            issue_token(client, tenant_a.email),
            "Persisted AppCare application",
        )

    application_id = str(application["id"])
    evidence = _evidence(tenant_id=tenant_a.tenant_id, application_id=application_id)
    store_a = SqlAlchemyPreproductionEvidenceStore(
        app.state.database.session_factory,
        tenant_id=tenant_a.tenant_id,
    )
    assert store_a.save(evidence) == evidence
    assert (
        store_a.resolve(
            tenant_id=tenant_a.tenant_id,
            application_id=application_id,
            source_revision=evidence.source_revision,
            artifact_digest=evidence.artifact_digest,
            evidence_digest=evidence.authoritative_evidence_digest,
        )
        == evidence
    )

    store_b = SqlAlchemyPreproductionEvidenceStore(
        app.state.database.session_factory,
        tenant_id=tenant_b.tenant_id,
    )
    assert (
        store_b.resolve(
            tenant_id=tenant_b.tenant_id,
            application_id=application_id,
            source_revision=evidence.source_revision,
            artifact_digest=evidence.artifact_digest,
            evidence_digest=evidence.authoritative_evidence_digest,
        )
        is None
    )
    with pytest.raises(ProductionControlError, match="tenant boundary"):
        store_b.save(evidence)


def test_vercel_is_provider_specific_and_does_not_change_global_gate() -> None:
    assert VERCEL_CAPABILITIES.read_only == "supported"
    assert VERCEL_CAPABILITIES.scan == "supported"
    assert VERCEL_CAPABILITIES.preview == "vendor_blocked"
    assert VERCEL_CAPABILITIES.automated_production == "disabled"


def test_reference_adapter_rejects_artifact_symlink_crossing(tmp_path: Path) -> None:
    target = tmp_path / "reference"
    artifact_root = target / "artifacts"
    config = ReferenceDeploymentConfig(
        target_root=target,
        artifact_root=artifact_root,
        service_name="appcare-reference-test",
        health_url="http://127.0.0.1:18568/health/ready",
    )
    artifact_root.mkdir(parents=True)
    digest = "b" * 64
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ".appcare-artifact.json").write_text(
        json.dumps({"source_revision": "a" * 40, "artifact_digest": digest}),
        encoding="utf-8",
    )
    (artifact_root / digest).symlink_to(outside, target_is_directory=True)
    provider = FilesystemReferenceProvider(config)
    intent = DeploymentIntent(
        intent_id="intent-reference",
        tenant_id="tenant-a",
        application_id="application-a",
        artifact_digest=digest,
        source_revision="a" * 40,
        rollback_reference="c" * 40,
        rollback_artifact_digest="d" * 64,
        idempotency_key="idempotency-reference",
        requested_by="operator-reference",
        backup_evidence_ref="backup-reference",
        credential_ref="vault://appcare/reference-test",
        preproduction_evidence_digest=_evidence().authoritative_evidence_digest,
    )
    with pytest.raises(ProductionControlError, match="symlink"):
        provider.deploy(intent)


def test_reference_adapter_rejects_non_loopback_health_url(tmp_path: Path) -> None:
    with pytest.raises(ProductionControlError, match="loopback"):
        ReferenceDeploymentConfig(
            target_root=tmp_path / "reference",
            artifact_root=tmp_path / "reference" / "artifacts",
            service_name="appcare-reference-test",
            health_url="http://127.0.0.1:18568@external.example/health/ready",
        )
