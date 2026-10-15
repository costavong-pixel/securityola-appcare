"""Integration helpers for the existing AppCare backup/readiness systems."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from ..backups.models import BackupComponent, RecoveryEvidence, VaultReceipt
from ..readiness.contracts import (
    CapabilityEvidence,
    CapabilityStatus,
    CoordinatorApproval,
    validate_digest,
    validate_evidence_reference,
    validate_scope_segment,
)
from ..readiness.registry import ApplicationCapabilityRegistry
from ..revision.contracts import CapturedApplicationRevision
from .adapters import LogicalDatabaseAdapter
from .contracts import (
    DatabaseArtifactError,
    DatabaseDumpArtifact,
    DatabaseDumpRequest,
    DatabaseDumpResult,
    DatabaseKind,
    DatabaseOperationStatus,
    DatabaseRestoreEvidence,
    DatabaseTarget,
    validate_database_name,
)


class DatabaseIdentityAttestationError(DatabaseArtifactError):
    """A database identity did not match the application revision context."""


_DATABASE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,63}$")


@dataclass(frozen=True, slots=True)
class DatabaseIdentityAttestation:
    """Sanitized identity observed for one revision-bound database target.

    This object carries no credential material.  It is deliberately only an
    identity assertion: the bridge accepts it when every field matches the
    existing typed target and captured application revision.
    """

    tenant_id: str
    application_id: str
    stack_id: str
    target_reference: str
    engine_family: DatabaseKind
    database_identifier: str
    logical_database_name: str
    database_version: str
    credential_reference: str
    baseline_id: str
    baseline_digest: str
    manifest_digest: str
    evidence_reference: str

    def __post_init__(self) -> None:
        for name in ("tenant_id", "application_id", "stack_id", "baseline_id"):
            object.__setattr__(
                self, name, validate_scope_segment(getattr(self, name), field_name=name)
            )
        object.__setattr__(
            self, "target_reference", validate_evidence_reference(self.target_reference)
        )
        if not isinstance(self.engine_family, DatabaseKind):
            try:
                object.__setattr__(self, "engine_family", DatabaseKind(str(self.engine_family)))
            except ValueError as exc:
                raise DatabaseIdentityAttestationError("database engine is invalid") from exc
        object.__setattr__(
            self,
            "database_identifier",
            validate_database_name(self.database_identifier, field_name="database_identifier"),
        )
        object.__setattr__(
            self,
            "logical_database_name",
            validate_database_name(self.logical_database_name, field_name="logical_database_name"),
        )
        if (
            not isinstance(self.database_version, str)
            or _DATABASE_VERSION.fullmatch(self.database_version.strip()) is None
        ):
            raise DatabaseIdentityAttestationError("database version is invalid")
        object.__setattr__(self, "database_version", self.database_version.strip())
        object.__setattr__(
            self, "credential_reference", validate_evidence_reference(self.credential_reference)
        )
        object.__setattr__(
            self,
            "baseline_digest",
            validate_digest(self.baseline_digest, field_name="baseline_digest"),
        )
        object.__setattr__(
            self,
            "manifest_digest",
            validate_digest(self.manifest_digest, field_name="manifest_digest"),
        )
        object.__setattr__(
            self, "evidence_reference", validate_evidence_reference(self.evidence_reference)
        )

    def validate_for(
        self,
        *,
        revision: CapturedApplicationRevision,
        target: DatabaseTarget,
    ) -> None:
        """Fail closed unless identity and revision bindings are exact."""

        if (
            revision.tenant_id != target.tenant_id
            or revision.application_id != target.application_id
            or revision.target_reference != target.transport.target_reference
        ):
            raise DatabaseIdentityAttestationError(
                "application or target scope does not match revision"
            )
        if (
            self.tenant_id != revision.tenant_id
            or self.application_id != revision.application_id
            or self.stack_id != target.stack_id
            or self.target_reference != target.target_reference
            or self.engine_family != target.engine_family
            or self.database_identifier != target.database_identifier
            or self.logical_database_name != target.logical_database_name
            or self.credential_reference != target.credential.reference
            or self.baseline_id != revision.baseline_id
            or self.baseline_digest != revision.baseline_digest
            or self.manifest_digest != revision.manifest_digest
        ):
            raise DatabaseIdentityAttestationError(
                "database identity is not bound to target revision"
            )

        metadata: Mapping[str, object] = revision.database_metadata
        expected_metadata = {
            "stack_id": target.stack_id,
            "engine_family": target.engine_family.value,
            "database_identifier": target.database_identifier,
            "logical_database_name": target.logical_database_name,
            "database_version": self.database_version,
            # Revision metadata may carry only a non-reversible binding for
            # the opaque reference; the reference itself stays out of the
            # captured application record.
            "db_auth_fingerprint": hashlib.sha256(
                target.credential.reference.encode("utf-8")
            ).hexdigest(),
            "identity_evidence_reference": self.evidence_reference,
        }
        if any(metadata.get(key) != value for key, value in expected_metadata.items()):
            raise DatabaseIdentityAttestationError(
                "database identity/version does not match revision"
            )


@dataclass(frozen=True, slots=True)
class ApplicationDatabaseBackupContext:
    """Existing application/revision/target context for one DB backup."""

    revision: CapturedApplicationRevision
    target: DatabaseTarget
    identity: DatabaseIdentityAttestation

    def validate(self) -> None:
        self.identity.validate_for(revision=self.revision, target=self.target)


class ApplicationDatabaseBackupBridge:
    """Thin application-to-database backup orchestration boundary.

    The existing logical adapter remains responsible for command construction,
    credential custody, staging, checksum sealing, cleanup, and the operation
    ledger.  This bridge only supplies and verifies the application revision
    identity before and after that adapter call.
    """

    def __init__(self, adapter: LogicalDatabaseAdapter) -> None:
        self.adapter = adapter

    def dump(
        self,
        context: ApplicationDatabaseBackupContext,
        *,
        backup_id: str,
        idempotency_key: str,
        job_id: str,
        now: datetime | None = None,
        cancel_event: object | None = None,
    ) -> DatabaseDumpResult:
        context.validate()
        requested_at = now or datetime.now(UTC)
        revision = context.revision
        request = DatabaseDumpRequest(
            target=context.target,
            backup_id=backup_id,
            idempotency_key=idempotency_key,
            job_id=job_id,
            source_revision=revision.source_revision or revision.baseline_digest,
            application_artifact_digest=revision.mirror_digest or revision.baseline_digest,
            requested_at=requested_at,
        )
        result = self.adapter.dump(
            request,
            now=requested_at,
            cancel_event=cancel_event,
        )
        if result.artifact is not None:
            _validate_artifact_revision_binding(result.artifact, context)
        return result


def _validate_artifact_revision_binding(
    artifact: DatabaseDumpArtifact,
    context: ApplicationDatabaseBackupContext,
) -> None:
    """Reject adapter output that is not bound to the exact revision."""

    revision = context.revision
    manifest = artifact.manifest
    expected_source_revision = revision.source_revision or revision.baseline_digest
    expected_artifact_digest = revision.mirror_digest or revision.baseline_digest
    if (
        manifest.tenant_id != revision.tenant_id
        or manifest.application_id != revision.application_id
        or manifest.target_reference != context.target.target_reference
        or manifest.engine_family != context.target.engine_family
        or manifest.database_identifier != context.target.database_identifier
        or manifest.logical_database_name != context.target.logical_database_name
        or manifest.source_revision != expected_source_revision
        or manifest.application_artifact_digest != expected_artifact_digest
    ):
        raise DatabaseArtifactError("database artifact is not bound to application revision")


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
    "ApplicationDatabaseBackupContext",
    "ApplicationDatabaseBackupBridge",
    "CapabilityEvidenceSink",
    "DatabaseIdentityAttestation",
    "DatabaseIdentityAttestationError",
    "database_artifact_component",
    "database_capability_evidence",
    "register_database_capability_evidence",
    "restore_supporting_evidence",
]
