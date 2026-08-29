"""Integration helpers for the existing AppCare backup/readiness systems."""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import UTC, datetime
from typing import Protocol

from ..backups.models import BackupComponent, RecoveryEvidence, VaultReceipt
from ..readiness.contracts import (
    CapabilityEvidence,
    CapabilityStatus,
    CoordinatorApproval,
)
from ..readiness.registry import ApplicationCapabilityRegistry
from .contracts import (
    DatabaseArtifactError,
    DatabaseDumpArtifact,
    DatabaseOperationStatus,
    DatabaseRestoreEvidence,
)


class CapabilityEvidenceSink(Protocol):
    """Minimal persistence boundary supplied by the existing readiness store."""

    def save_capability_evidence(self, evidence: CapabilityEvidence) -> object:
        """Persist one already-normalized capability observation."""


def register_database_capability_evidence(
    artifact: DatabaseDumpArtifact,
    *,
    capability_registry: ApplicationCapabilityRegistry,
    evidence_ref: str,
    coordinator_approval: CoordinatorApproval | None,
    readback_evidence: RecoveryEvidence | None,
    vault_receipt: VaultReceipt | None,
    readiness_store: CapabilityEvidenceSink | None = None,
    observed_at: datetime | None = None,
) -> CapabilityEvidence:
    """Register and optionally persist database evidence through Spec 013.

    ``database_capability_evidence`` remains the pure evidence constructor.
    This explicit bridge is the operational entry point: it adds the result to
    the scope-bound Spec 013 registry before handing it to the existing
    durable readiness store.  The helper records blocked evidence as well as
    supported evidence so the evaluator can fail closed on an incomplete
    database proof.
    """

    evidence = database_capability_evidence(
        artifact,
        evidence_ref=evidence_ref,
        coordinator_approval=coordinator_approval,
        readback_evidence=readback_evidence,
        vault_receipt=vault_receipt,
        observed_at=observed_at,
    )
    capability_registry.add(evidence)
    if readiness_store is not None:
        readiness_store.save_capability_evidence(evidence)
    return evidence


def database_artifact_component(artifact: DatabaseDumpArtifact) -> BackupComponent:
    """Read one verified bounded artifact into the existing backup pipeline."""

    path = artifact.artifact_path
    if path.is_symlink():
        raise DatabaseArtifactError("database artifact is a symlink")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise DatabaseArtifactError("database artifact cannot be opened") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != artifact.manifest.artifact_size_bytes
        ):
            raise DatabaseArtifactError("database artifact size is not manifest-bound")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > artifact.manifest.artifact_size_bytes:
                raise DatabaseArtifactError("database artifact exceeds manifest size")
    except OSError as exc:
        raise DatabaseArtifactError("database artifact cannot be read") from exc
    finally:
        os.close(descriptor)
    if not payload or hashlib.sha256(payload).hexdigest() != artifact.artifact_digest:
        raise DatabaseArtifactError("database artifact checksum mismatch")
    target = artifact.manifest
    component_kind = (
        "mariadb-mysql-logical"
        if target.engine_family.value == "mariadb_mysql"
        else "postgresql-logical"
    )
    return BackupComponent(
        name="database",
        kind=component_kind,
        source_reference=(
            f"database/{target.tenant_id}/{target.application_id}/{target.backup_id}"
        ),
        payload=bytes(payload),
    )


def database_capability_evidence(
    artifact: DatabaseDumpArtifact,
    *,
    evidence_ref: str,
    coordinator_approval: CoordinatorApproval | None,
    readback_evidence: RecoveryEvidence | None,
    vault_receipt: VaultReceipt | None,
    observed_at: datetime | None = None,
) -> CapabilityEvidence:
    """Emit only the scoped ``database_backup`` evidence approved by Luna.

    This helper never emits whole-application readback or restore support.  A
    missing or digest-mismatched approval produces a non-supported result.
    """

    approved = (
        artifact.manifest.source_revision is not None
        and artifact.manifest.application_artifact_digest is not None
        and coordinator_approval is not None
        and coordinator_approval.decision.value == "approve"
        and coordinator_approval.evidence_digest == artifact.evidence_digest
        and readback_evidence is not None
        and readback_evidence.status == "verified"
        and readback_evidence.backup_id == artifact.manifest.backup_id
        and readback_evidence.manifest_digest == artifact.manifest_digest
        and readback_evidence.artifact_digest == artifact.artifact_digest
        and "database" in readback_evidence.component_names
        and vault_receipt is not None
        and vault_receipt.backup_id == artifact.manifest.backup_id
        and vault_receipt.artifact_digest == artifact.artifact_digest
    )
    status = CapabilityStatus.SUPPORTED if approved else CapabilityStatus.BLOCKED_EXTERNAL
    return CapabilityEvidence(
        tenant_id=artifact.manifest.tenant_id,
        application_id=artifact.manifest.application_id,
        stack_id=artifact.manifest.stack_id,
        capability="database_backup",
        status=status,
        evidence_class=artifact.evidence_class,
        evidence_ref=evidence_ref,
        observed_at=observed_at or datetime.now(UTC),
        source_revision=artifact.manifest.source_revision,
        artifact_digest=artifact.manifest.application_artifact_digest,
        coordinator_decision=(coordinator_approval.decision if coordinator_approval else None),
    )


def restore_supporting_evidence(restore: DatabaseRestoreEvidence) -> dict[str, object]:
    """Return sanitized supporting evidence, never a whole-app promotion."""

    return {
        "kind": "database_restore_supporting_evidence",
        "status": "pass" if restore.status == DatabaseOperationStatus.PASSED else "fail",
        "tenant_id": restore.request.target.tenant_id,
        "application_id": restore.request.target.application_id,
        "stack_id": restore.request.target.stack_id,
        "backup_id": restore.request.artifact.manifest.backup_id,
        "artifact_digest": restore.artifact_digest,
        "manifest_digest": restore.manifest_digest,
        "evidence_class": restore.evidence_class.value,
        "isolated_target": restore.request.target.isolated_target_reference,
    }


__all__ = [
    "CapabilityEvidenceSink",
    "database_artifact_component",
    "database_capability_evidence",
    "register_database_capability_evidence",
    "restore_supporting_evidence",
]
