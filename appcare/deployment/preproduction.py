"""Authoritative, provider-neutral preproduction evidence.

The release policy consumes this record, not a caller-supplied preview flag.
The SQLAlchemy store is intentionally tenant/application scoped and returns
only evidence whose exact source and artifact identities match the request.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, cast

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import Application, PreproductionEvidenceRecord
from ..services.security import contains_credential_like
from .contracts import ProductionControlError, _digest, _revision, validate_opaque_reference

PreproductionStatus = Literal["pass", "fail", "unverified"]
_SAFE_STATUS = {"pass", "fail", "unverified"}


def normalize_preproduction_status(value: object) -> PreproductionStatus:
    if not isinstance(value, str) or value.strip().casefold() not in _SAFE_STATUS:
        raise ProductionControlError("preproduction status is invalid")
    return cast(PreproductionStatus, value.strip().casefold())


def _timestamp(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ProductionControlError("preproduction deployment timestamp must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class PreproductionEvidence:
    """One immutable, exact-head-bound preproduction acceptance receipt."""

    tenant_id: str
    application_id: str
    provider: str
    target_type: str
    source_revision: str
    artifact_digest: str
    environment_identity: str
    deployment_reference: str
    deployment_timestamp: datetime
    smoke_test_receipt: str
    security_test_receipt: str
    rollback_reference_receipt: str
    authoritative_evidence_digest: str
    exact_head: str
    status: PreproductionStatus

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "application_id",
            "provider",
            "target_type",
            "environment_identity",
            "deployment_reference",
            "smoke_test_receipt",
            "security_test_receipt",
            "rollback_reference_receipt",
        ):
            object.__setattr__(
                self,
                name,
                validate_opaque_reference(getattr(self, name), field_name=name),
            )
        source_revision = _revision(self.source_revision, field_name="source_revision")
        exact_head = _revision(self.exact_head, field_name="exact_head")
        if source_revision != exact_head:
            raise ProductionControlError("preproduction evidence exact-head binding failed")
        object.__setattr__(self, "source_revision", source_revision)
        object.__setattr__(self, "exact_head", exact_head)
        object.__setattr__(
            self,
            "artifact_digest",
            _digest(self.artifact_digest, field_name="artifact_digest"),
        )
        timestamp = _timestamp(self.deployment_timestamp)
        object.__setattr__(self, "deployment_timestamp", timestamp)
        status = normalize_preproduction_status(self.status)
        object.__setattr__(self, "status", status)
        object.__setattr__(
            self,
            "authoritative_evidence_digest",
            _digest(
                self.authoritative_evidence_digest,
                field_name="authoritative_evidence_digest",
            ),
        )
        if contains_credential_like(json.dumps(self.canonical_payload(), sort_keys=True)):
            raise ProductionControlError("preproduction evidence contains credential-like data")
        if self.authoritative_evidence_digest != self.compute_digest():
            raise ProductionControlError("preproduction authoritative evidence digest mismatch")

    @classmethod
    def create(
        cls,
        *,
        tenant_id: str,
        application_id: str,
        provider: str,
        target_type: str,
        source_revision: str,
        artifact_digest: str,
        environment_identity: str,
        deployment_reference: str,
        deployment_timestamp: datetime,
        smoke_test_receipt: str,
        security_test_receipt: str,
        rollback_reference_receipt: str,
        exact_head: str | None = None,
        status: PreproductionStatus = "pass",
    ) -> PreproductionEvidence:
        candidate = cls.__new__(cls)
        # Build the canonical payload once, then use the normal constructor so
        # persisted and newly-created records share exactly the same checks.
        values = {
            "tenant_id": tenant_id,
            "application_id": application_id,
            "provider": provider,
            "target_type": target_type,
            "source_revision": source_revision,
            "artifact_digest": artifact_digest,
            "environment_identity": environment_identity,
            "deployment_reference": deployment_reference,
            "deployment_timestamp": deployment_timestamp,
            "smoke_test_receipt": smoke_test_receipt,
            "security_test_receipt": security_test_receipt,
            "rollback_reference_receipt": rollback_reference_receipt,
            "authoritative_evidence_digest": "0" * 64,
            "exact_head": exact_head or source_revision,
            "status": status,
        }
        # The temporary object is never returned; it only supplies normalized
        # fields for the canonical digest calculation.
        del candidate
        normalized = cls._normalize_without_digest(values)
        digest = cls._digest_for_values(normalized)
        normalized["authoritative_evidence_digest"] = digest
        return cls(
            tenant_id=cast(str, normalized["tenant_id"]),
            application_id=cast(str, normalized["application_id"]),
            provider=cast(str, normalized["provider"]),
            target_type=cast(str, normalized["target_type"]),
            source_revision=cast(str, normalized["source_revision"]),
            artifact_digest=cast(str, normalized["artifact_digest"]),
            environment_identity=cast(str, normalized["environment_identity"]),
            deployment_reference=cast(str, normalized["deployment_reference"]),
            deployment_timestamp=cast(datetime, normalized["deployment_timestamp"]),
            smoke_test_receipt=cast(str, normalized["smoke_test_receipt"]),
            security_test_receipt=cast(str, normalized["security_test_receipt"]),
            rollback_reference_receipt=cast(str, normalized["rollback_reference_receipt"]),
            authoritative_evidence_digest=digest,
            exact_head=cast(str, normalized["exact_head"]),
            status=cast(PreproductionStatus, normalized["status"]),
        )

    @classmethod
    def _normalize_without_digest(cls, values: dict[str, object]) -> dict[str, object]:
        normalized = dict(values)
        for name in (
            "tenant_id",
            "application_id",
            "provider",
            "target_type",
            "environment_identity",
            "deployment_reference",
            "smoke_test_receipt",
            "security_test_receipt",
            "rollback_reference_receipt",
        ):
            normalized[name] = validate_opaque_reference(normalized[name], field_name=name)
        normalized["source_revision"] = _revision(
            normalized["source_revision"], field_name="source_revision"
        )
        normalized["exact_head"] = _revision(normalized["exact_head"], field_name="exact_head")
        if normalized["source_revision"] != normalized["exact_head"]:
            raise ProductionControlError("preproduction evidence exact-head binding failed")
        normalized["artifact_digest"] = _digest(
            normalized["artifact_digest"], field_name="artifact_digest"
        )
        normalized["deployment_timestamp"] = _timestamp(normalized["deployment_timestamp"])
        normalized["status"] = normalize_preproduction_status(normalized["status"])
        return normalized

    @staticmethod
    def _digest_for_values(values: dict[str, object]) -> str:
        payload = {
            key: (value.isoformat() if isinstance(value, datetime) else value)
            for key, value in values.items()
            if key != "authoritative_evidence_digest"
        }
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def canonical_payload(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "provider": self.provider,
            "target_type": self.target_type,
            "source_revision": self.source_revision,
            "artifact_digest": self.artifact_digest,
            "environment_identity": self.environment_identity,
            "deployment_reference": self.deployment_reference,
            "deployment_timestamp": self.deployment_timestamp.isoformat(),
            "smoke_test_receipt": self.smoke_test_receipt,
            "security_test_receipt": self.security_test_receipt,
            "rollback_reference_receipt": self.rollback_reference_receipt,
            "exact_head": self.exact_head,
            "status": self.status,
        }

    def compute_digest(self) -> str:
        return self._digest_for_values(self.canonical_payload())

    @property
    def passed(self) -> bool:
        return self.status == "pass"


class PreproductionEvidenceStore(Protocol):
    """Authoritative lookup used by release and production controllers."""

    def save(self, evidence: PreproductionEvidence) -> PreproductionEvidence: ...

    def resolve(
        self,
        *,
        tenant_id: str,
        application_id: str,
        source_revision: str,
        artifact_digest: str,
        evidence_digest: str,
    ) -> PreproductionEvidence | None: ...


@dataclass
class InMemoryPreproductionEvidenceStore:
    _records: dict[str, PreproductionEvidence] | None = None

    def __post_init__(self) -> None:
        if self._records is None:
            self._records = {}

    def save(self, evidence: PreproductionEvidence) -> PreproductionEvidence:
        assert self._records is not None
        existing = self._records.get(evidence.authoritative_evidence_digest)
        if existing is not None and existing != evidence:
            raise ProductionControlError("preproduction evidence is immutable")
        self._records[evidence.authoritative_evidence_digest] = evidence
        return evidence

    def resolve(
        self,
        *,
        tenant_id: str,
        application_id: str,
        source_revision: str,
        artifact_digest: str,
        evidence_digest: str,
    ) -> PreproductionEvidence | None:
        assert self._records is not None
        candidate = self._records.get(evidence_digest)
        if candidate is None:
            return None
        if (
            candidate.tenant_id != tenant_id
            or candidate.application_id != application_id
            or candidate.source_revision != source_revision
            or candidate.exact_head != source_revision
            or candidate.artifact_digest != artifact_digest
        ):
            return None
        return candidate


SessionFactory = Callable[[], Session]


class SqlAlchemyPreproductionEvidenceStore:
    """Tenant/application scoped immutable SQLAlchemy evidence store."""

    def __init__(self, session_factory: SessionFactory, *, tenant_id: str) -> None:
        self._session_factory = session_factory
        self._tenant_id = validate_opaque_reference(tenant_id, field_name="tenant_id")

    def save(self, evidence: PreproductionEvidence) -> PreproductionEvidence:
        if evidence.tenant_id != self._tenant_id:
            raise ProductionControlError("preproduction store tenant boundary was crossed")
        with self._session_factory() as session:
            application = session.scalar(
                select(Application).where(
                    Application.id == evidence.application_id,
                    Application.tenant_id == self._tenant_id,
                )
            )
            if application is None:
                raise ProductionControlError("preproduction application boundary was crossed")
            row = session.scalar(
                select(PreproductionEvidenceRecord).where(
                    PreproductionEvidenceRecord.tenant_id == self._tenant_id,
                    PreproductionEvidenceRecord.authoritative_evidence_digest
                    == evidence.authoritative_evidence_digest,
                )
            )
            if row is not None:
                existing = self._from_row(row)
                if existing != evidence:
                    raise ProductionControlError("preproduction evidence is immutable")
                return existing
            session.add(
                PreproductionEvidenceRecord(
                    tenant_id=evidence.tenant_id,
                    application_id=evidence.application_id,
                    provider=evidence.provider,
                    target_type=evidence.target_type,
                    source_revision=evidence.source_revision,
                    artifact_digest=evidence.artifact_digest,
                    environment_identity=evidence.environment_identity,
                    deployment_reference=evidence.deployment_reference,
                    deployment_timestamp=evidence.deployment_timestamp,
                    smoke_test_receipt=evidence.smoke_test_receipt,
                    security_test_receipt=evidence.security_test_receipt,
                    rollback_reference_receipt=evidence.rollback_reference_receipt,
                    authoritative_evidence_digest=evidence.authoritative_evidence_digest,
                    exact_head=evidence.exact_head,
                    status=evidence.status,
                )
            )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise ProductionControlError("preproduction evidence persistence conflict") from exc
        return evidence

    @staticmethod
    def _from_row(row: PreproductionEvidenceRecord) -> PreproductionEvidence:
        deployment_timestamp = row.deployment_timestamp
        if deployment_timestamp.tzinfo is None:
            deployment_timestamp = deployment_timestamp.replace(tzinfo=UTC)
        return PreproductionEvidence(
            tenant_id=row.tenant_id,
            application_id=row.application_id,
            provider=row.provider,
            target_type=row.target_type,
            source_revision=row.source_revision,
            artifact_digest=row.artifact_digest,
            environment_identity=row.environment_identity,
            deployment_reference=row.deployment_reference,
            deployment_timestamp=deployment_timestamp,
            smoke_test_receipt=row.smoke_test_receipt,
            security_test_receipt=row.security_test_receipt,
            rollback_reference_receipt=row.rollback_reference_receipt,
            authoritative_evidence_digest=row.authoritative_evidence_digest,
            exact_head=row.exact_head,
            status=cast(PreproductionStatus, row.status),
        )

    def resolve(
        self,
        *,
        tenant_id: str,
        application_id: str,
        source_revision: str,
        artifact_digest: str,
        evidence_digest: str,
    ) -> PreproductionEvidence | None:
        if tenant_id != self._tenant_id:
            return None
        try:
            normalized_digest = _digest(evidence_digest, field_name="evidence_digest")
            normalized_revision = _revision(source_revision, field_name="source_revision")
            normalized_artifact = _digest(artifact_digest, field_name="artifact_digest")
            normalized_application = validate_opaque_reference(
                application_id, field_name="application_id"
            )
        except ProductionControlError:
            return None
        with self._session_factory() as session:
            row = session.scalar(
                select(PreproductionEvidenceRecord).where(
                    PreproductionEvidenceRecord.tenant_id == self._tenant_id,
                    PreproductionEvidenceRecord.application_id == normalized_application,
                    PreproductionEvidenceRecord.source_revision == normalized_revision,
                    PreproductionEvidenceRecord.exact_head == normalized_revision,
                    PreproductionEvidenceRecord.artifact_digest == normalized_artifact,
                    PreproductionEvidenceRecord.authoritative_evidence_digest == normalized_digest,
                )
            )
            return None if row is None else self._from_row(row)


__all__ = [
    "InMemoryPreproductionEvidenceStore",
    "PreproductionEvidence",
    "PreproductionEvidenceStore",
    "PreproductionStatus",
    "SqlAlchemyPreproductionEvidenceStore",
    "normalize_preproduction_status",
]
