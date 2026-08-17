"""Immutable backup records used by the verification and restore pipeline."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from .contracts import (
    BackupDestination,
    BackupTarget,
    RestoreTarget,
    _safe_reference,
    utc,
    validate_component_name,
    validate_metadata,
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True, slots=True)
class BackupComponent:
    """One source component; payload bytes are encrypted before vault storage."""

    name: str
    kind: str
    source_reference: str
    payload: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", validate_component_name(self.name))
        if not self.kind or len(self.kind) > 100 or not self.kind.replace("-", "").isalnum():
            raise ValueError("backup component kind is invalid")
        _safe_reference(self.source_reference, field="backup component source reference")
        if not isinstance(self.payload, bytes):
            raise TypeError("backup component payload must be bytes")

    @property
    def digest(self) -> str:
        return sha256_bytes(self.payload)


@dataclass(frozen=True, slots=True)
class ComponentDigest:
    name: str
    kind: str
    source_reference: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class BackupManifest:
    """Sanitized, canonical metadata for one encrypted artifact."""

    backup_id: str
    target: BackupTarget
    destination: BackupDestination
    components: tuple[ComponentDigest, ...]
    key_reference: str
    encryption_algorithm: str
    created_at: datetime
    source_captured_at: datetime
    rpo_target_seconds: int
    rto_target_seconds: int

    def __post_init__(self) -> None:
        if not self.backup_id or len(self.backup_id) > 128:
            raise ValueError("backup ID is invalid")
        if not self.components:
            raise ValueError("backup must contain at least one component")
        names = [component.name for component in self.components]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("backup components must be sorted and unique")
        if not self.key_reference.startswith("vault://"):
            raise ValueError("backup key reference must be an opaque vault reference")
        if self.encryption_algorithm != "AES-256-GCM":
            raise ValueError("unsupported backup encryption algorithm")
        if self.rpo_target_seconds < 0 or self.rto_target_seconds < 0:
            raise ValueError("recovery objectives must be non-negative")
        utc(self.created_at)
        utc(self.source_captured_at)

    def as_dict(self) -> dict[str, object]:
        return {
            "backup_id": self.backup_id,
            "target": {
                "tenant_id": self.target.tenant_id,
                "application_id": self.target.application_id,
                "environment": self.target.environment,
                "source_reference": self.target.source_reference,
            },
            "destination": {
                "provider": self.destination.provider,
                "namespace": self.destination.namespace,
                "region": self.destination.region,
                "retention_until": utc(self.destination.retention_until).isoformat(),
                "immutable": self.destination.immutable,
                "credential_reference": self.destination.credential_reference,
            },
            "components": [
                {
                    "name": component.name,
                    "kind": component.kind,
                    "source_reference": component.source_reference,
                    "size_bytes": component.size_bytes,
                    "sha256": component.sha256,
                }
                for component in self.components
            ],
            "key_reference": self.key_reference,
            "encryption_algorithm": self.encryption_algorithm,
            "created_at": utc(self.created_at).isoformat(),
            "source_captured_at": utc(self.source_captured_at).isoformat(),
            "rpo_target_seconds": self.rpo_target_seconds,
            "rto_target_seconds": self.rto_target_seconds,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    @property
    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())


@dataclass(frozen=True, slots=True)
class EncryptedEnvelope:
    algorithm: str
    key_reference: str
    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        if self.algorithm != "AES-256-GCM":
            raise ValueError("unsupported envelope algorithm")
        if not self.key_reference.startswith("vault://"):
            raise ValueError("envelope key reference is unsafe")
        if len(self.nonce) != 12 or not self.ciphertext:
            raise ValueError("encrypted envelope is malformed")

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "algorithm": self.algorithm,
                "key_reference": self.key_reference,
                "nonce": base64.b64encode(self.nonce).decode("ascii"),
                "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class BackupArtifact:
    manifest: BackupManifest
    manifest_bytes: bytes
    envelope: EncryptedEnvelope
    artifact_digest: str

    @classmethod
    def build(cls, manifest: BackupManifest, envelope: EncryptedEnvelope) -> BackupArtifact:
        manifest_bytes = manifest.canonical_bytes()
        digest = sha256_bytes(manifest_bytes + b"\n" + envelope.canonical_bytes())
        return cls(manifest, manifest_bytes, envelope, digest)

    @property
    def computed_digest(self) -> str:
        return sha256_bytes(self.manifest_bytes + b"\n" + self.envelope.canonical_bytes())


@dataclass(frozen=True, slots=True)
class BackupRequest:
    target: BackupTarget
    destination: BackupDestination
    backup_id: str
    idempotency_key: str
    source_captured_at: datetime
    rpo_target_seconds: int = 86_400
    rto_target_seconds: int = 3_600

    def __post_init__(self) -> None:
        if not self.backup_id or len(self.backup_id) > 128:
            raise ValueError("backup ID is invalid")
        if not self.idempotency_key or len(self.idempotency_key) > 200:
            raise ValueError("idempotency key is invalid")
        if self.rpo_target_seconds < 0 or self.rto_target_seconds < 0:
            raise ValueError("recovery objectives must be non-negative")
        utc(self.source_captured_at)


BackupStatus = Literal["requested", "uploading", "verified", "failed", "duplicate"]


@dataclass(frozen=True, slots=True)
class BackupJobEvent:
    job_id: str
    status: BackupStatus
    occurred_at: datetime
    reason_code: str | None = None

    def __post_init__(self) -> None:
        utc(self.occurred_at)
        if self.reason_code is not None and (
            not self.reason_code
            or len(self.reason_code) > 100
            or not all(character.isalnum() or character == "_" for character in self.reason_code)
        ):
            raise ValueError("backup reason code is invalid")


@dataclass(frozen=True, slots=True)
class VaultReceipt:
    backup_id: str
    provider: str
    object_reference: str
    artifact_digest: str
    retained_until: datetime
    idempotent: bool = False

    def __post_init__(self) -> None:
        utc(self.retained_until)


@dataclass(frozen=True, slots=True)
class RecoveryEvidence:
    backup_id: str
    status: Literal["verified", "failed"]
    component_names: tuple[str, ...]
    manifest_digest: str
    artifact_digest: str
    rpo_observed_seconds: int
    rto_observed_seconds: int | None
    controlled_test_only: bool
    failure_code: str | None = None

    def __post_init__(self) -> None:
        if self.rpo_observed_seconds < 0 or (
            self.rto_observed_seconds is not None and self.rto_observed_seconds < 0
        ):
            raise ValueError("recovery timing evidence is invalid")
        if self.status == "verified" and self.failure_code is not None:
            raise ValueError("verified recovery cannot carry a failure")


@dataclass(frozen=True, slots=True)
class BackupOutcome:
    backup_id: str
    status: BackupStatus
    healthy: bool
    evidence: RecoveryEvidence | None
    receipt: VaultReceipt | None
    events: tuple[BackupJobEvent, ...]
    failure_code: str | None = None


@dataclass(frozen=True, slots=True)
class RestoreEvidence:
    backup_id: str
    status: Literal["restore_verified", "restore_failed"]
    tenant_id: str
    application_id: str
    restored_component_names: tuple[str, ...]
    destination: RestoreTarget
    rpo_observed_seconds: int
    rto_observed_seconds: int | None
    controlled_test_only: bool
    failure_code: str | None = None

    def __post_init__(self) -> None:
        if self.status == "restore_verified" and self.failure_code is not None:
            raise ValueError("verified restore cannot carry a failure")
        if self.rpo_observed_seconds < 0 or (
            self.rto_observed_seconds is not None and self.rto_observed_seconds < 0
        ):
            raise ValueError("restore timing evidence is invalid")


def component_digests(components: tuple[BackupComponent, ...]) -> tuple[ComponentDigest, ...]:
    records = tuple(
        ComponentDigest(
            name=component.name,
            kind=component.kind,
            source_reference=component.source_reference,
            size_bytes=len(component.payload),
            sha256=component.digest,
        )
        for component in components
    )
    if len({record.name for record in records}) != len(records):
        raise ValueError("backup component names must be unique")
    return tuple(sorted(records, key=lambda record: record.name))


def validate_artifact_metadata(artifact: BackupArtifact) -> None:
    validate_metadata(artifact.manifest.as_dict())
