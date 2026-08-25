"""Fail-closed backup verification and isolated restore state machine."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from .contracts import (
    BackupBoundaryError,
    BackupSource,
    BackupTarget,
    BackupVault,
    EnvelopeEncryptor,
    RestoreTarget,
    utc,
    validate_backup_id,
    validate_isolated_child,
    validate_isolated_root,
)
from .models import (
    BackupArtifact,
    BackupComponent,
    BackupJobEvent,
    BackupManifest,
    BackupOutcome,
    BackupRequest,
    BackupStatus,
    RecoveryEvidence,
    RestoreEvidence,
    component_digests,
)
from .stores import (
    DuplicateArtifactError,
    RetentionLockedError,
    VaultError,
    VaultUnavailableError,
)


class BackupError(RuntimeError):
    """A backup or restore operation failed closed."""


class ArtifactIntegrityError(BackupError):
    """Manifest, encrypted envelope, or component checksum verification failed."""


def _failure_code(error: BaseException) -> str:
    if isinstance(error, BackupBoundaryError):
        return "boundary_error"
    if isinstance(error, VaultUnavailableError):
        return str(error) or "provider_unavailable"
    if isinstance(error, DuplicateArtifactError):
        return "duplicate_artifact"
    if isinstance(error, RetentionLockedError):
        return "retention_locked"
    if isinstance(error, ArtifactIntegrityError):
        return "checksum_mismatch"
    if isinstance(error, TimeoutError):
        return "upload_interrupted"
    if isinstance(error, VaultError):
        return "vault_failed"
    return "backup_failed"


def _serialize_components(components: Iterable[BackupComponent]) -> bytes:
    payload = [
        {
            "name": component.name,
            "kind": component.kind,
            "source_reference": component.source_reference,
            "payload": base64.b64encode(component.payload).decode("ascii"),
        }
        for component in sorted(components, key=lambda item: item.name)
    ]
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _deserialize_components(payload: bytes) -> tuple[BackupComponent, ...]:
    try:
        records = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactIntegrityError("component payload is malformed") from exc
    if not isinstance(records, list) or not records:
        raise ArtifactIntegrityError("component payload is empty")
    components: list[BackupComponent] = []
    for record in records:
        if not isinstance(record, dict):
            raise ArtifactIntegrityError("component record is malformed")
        try:
            encoded = record["payload"]
            if not isinstance(encoded, str):
                raise TypeError
            component = BackupComponent(
                name=record["name"],
                kind=record["kind"],
                source_reference=record["source_reference"],
                payload=base64.b64decode(encoded, validate=True),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ArtifactIntegrityError("component record is malformed") from exc
        components.append(component)
    names = [component.name for component in components]
    if len(names) != len(set(names)):
        raise ArtifactIntegrityError("component payload contains duplicate names")
    return tuple(sorted(components, key=lambda item: item.name))


class BackupCoordinator:
    """Coordinate one backup and restore without provider-specific side effects."""

    def __init__(self) -> None:
        self._outcomes: dict[str, BackupOutcome] = {}
        self._idempotency: dict[str, str] = {}
        self._events: list[BackupJobEvent] = []

    @property
    def job_history(self) -> tuple[BackupJobEvent, ...]:
        return tuple(self._events)

    def _event(
        self,
        *,
        request: BackupRequest,
        status: BackupStatus,
        now: datetime,
        reason_code: str | None = None,
    ) -> BackupJobEvent:
        event = BackupJobEvent(request.backup_id, status, utc(now), reason_code)
        self._events.append(event)
        return event

    def _failed(
        self,
        *,
        request: BackupRequest,
        now: datetime,
        events: list[BackupJobEvent],
        code: str,
        backup_id: str | None = None,
    ) -> BackupOutcome:
        evidence = RecoveryEvidence(
            backup_id=backup_id or request.backup_id,
            status="failed",
            component_names=(),
            manifest_digest="",
            artifact_digest="",
            rpo_observed_seconds=max(
                0, int((utc(now) - utc(request.source_captured_at)).total_seconds())
            ),
            rto_observed_seconds=None,
            controlled_test_only=not request.destination.external,
            failure_code=code,
        )
        outcome = BackupOutcome(
            backup_id=backup_id or request.backup_id,
            status="failed",
            healthy=False,
            evidence=evidence,
            receipt=None,
            events=tuple(events),
            failure_code=code,
        )
        self._outcomes[request.idempotency_key] = outcome
        return outcome

    def create_backup(
        self,
        request: BackupRequest,
        *,
        source: BackupSource,
        vault: BackupVault,
        encryptor: EnvelopeEncryptor,
        now: datetime,
    ) -> BackupOutcome:
        """Snapshot, encrypt, store, read back, and verify one backup."""

        if vault.destination != request.destination:
            raise BackupError("vault destination does not match backup request")
        # BackupTarget and BackupDestination validate in their constructors;
        # repeat the identity checks before invoking injected source/vault code.
        BackupTarget(
            request.target.tenant_id,
            request.target.application_id,
            request.target.environment,
            request.target.source_reference,
        )
        existing = self._outcomes.get(request.idempotency_key)
        if existing is not None:
            event = self._event(
                request=request, status="duplicate", now=now, reason_code="duplicate_job"
            )
            return BackupOutcome(
                backup_id=existing.backup_id,
                status="duplicate",
                healthy=False,
                evidence=existing.evidence,
                receipt=existing.receipt,
                events=existing.events + (event,),
                failure_code="duplicate_job",
            )

        events = [self._event(request=request, status="requested", now=now)]
        try:
            components = tuple(source.snapshot(request.target))
            if not components:
                raise BackupError("backup source returned no components")
            if len({component.name for component in components}) != len(components):
                raise BackupError("backup source returned duplicate components")
            events.append(self._event(request=request, status="uploading", now=now))
            key_reference = getattr(encryptor, "key_reference", None)
            if not isinstance(key_reference, str):
                raise BackupError("encryption key reference is unavailable")
            manifest = BackupManifest(
                backup_id=request.backup_id,
                target=request.target,
                destination=request.destination,
                components=component_digests(components),
                key_reference=key_reference,
                encryption_algorithm="AES-256-GCM",
                created_at=now,
                source_captured_at=request.source_captured_at,
                rpo_target_seconds=request.rpo_target_seconds,
                rto_target_seconds=request.rto_target_seconds,
            )
            manifest_bytes = manifest.canonical_bytes()
            envelope = encryptor.encrypt(
                _serialize_components(components), associated_data=manifest_bytes
            )
            artifact = BackupArtifact.build(manifest, envelope)
            receipt = vault.put(artifact, idempotency_key=request.idempotency_key)
            stored = vault.get(
                request.backup_id,
                tenant_id=request.target.tenant_id,
                application_id=request.target.application_id,
            )
            if stored.manifest.backup_id != request.backup_id:
                raise ArtifactIntegrityError("stored artifact ID does not match request")
            if stored.manifest.destination != vault.destination:
                raise ArtifactIntegrityError("stored artifact destination does not match vault")
            verified_components = self._verify_artifact(stored, encryptor=encryptor)
            if receipt.artifact_digest != stored.artifact_digest:
                raise ArtifactIntegrityError("vault receipt digest does not match stored artifact")
            events.append(self._event(request=request, status="verified", now=now))
            evidence = RecoveryEvidence(
                backup_id=request.backup_id,
                status="verified",
                component_names=tuple(component.name for component in verified_components),
                manifest_digest=stored.manifest.digest,
                artifact_digest=stored.artifact_digest,
                rpo_observed_seconds=max(
                    0, int((utc(now) - utc(request.source_captured_at)).total_seconds())
                ),
                rto_observed_seconds=None,
                controlled_test_only=not request.destination.external,
            )
            outcome = BackupOutcome(
                request.backup_id,
                "verified",
                True,
                evidence,
                receipt,
                tuple(events),
            )
            self._outcomes[request.idempotency_key] = outcome
            self._idempotency[request.idempotency_key] = request.backup_id
            return outcome
        except Exception as exc:
            code = _failure_code(exc)
            events.append(self._event(request=request, status="failed", now=now, reason_code=code))
            return self._failed(request=request, now=now, events=events, code=code)

    def _verify_artifact(
        self, artifact: BackupArtifact, *, encryptor: EnvelopeEncryptor
    ) -> tuple[BackupComponent, ...]:
        if artifact.manifest_bytes != artifact.manifest.canonical_bytes():
            raise ArtifactIntegrityError("manifest bytes are not canonical")
        if artifact.artifact_digest != artifact.computed_digest:
            raise ArtifactIntegrityError("artifact checksum mismatch")
        try:
            plaintext = encryptor.decrypt(
                artifact.envelope, associated_data=artifact.manifest_bytes
            )
        except Exception as exc:
            raise ArtifactIntegrityError("encrypted payload authentication failed") from exc
        components = _deserialize_components(plaintext)
        expected = {component.name: component for component in artifact.manifest.components}
        actual = {component.name: component for component in components}
        if set(expected) != set(actual):
            raise ArtifactIntegrityError("restored component set does not match manifest")
        for name, digest in expected.items():
            component = actual[name]
            if (
                component.kind != digest.kind
                or component.source_reference != digest.source_reference
                or len(component.payload) != digest.size_bytes
                or component.digest != digest.sha256
            ):
                raise ArtifactIntegrityError("component checksum mismatch")
        return components

    def restore_backup(
        self,
        *,
        backup_id: str,
        vault: BackupVault,
        encryptor: EnvelopeEncryptor,
        target: RestoreTarget,
        now: datetime,
    ) -> RestoreEvidence:
        """Verify and restore to a staging directory before atomic promotion."""

        started = time.monotonic()
        staging: Path | None = None
        try:
            backup_id = validate_backup_id(backup_id)
            artifact = vault.get(
                backup_id,
                tenant_id=target.tenant_id,
                application_id=target.application_id,
            )
            if artifact.manifest.backup_id != backup_id:
                raise BackupError("restore artifact ID does not match request")
            if artifact.manifest.destination != vault.destination:
                raise BackupError("restore vault destination mismatch")
            if artifact.manifest.target.tenant_id != target.tenant_id:
                raise BackupError("restore tenant mismatch")
            if artifact.manifest.target.application_id != target.application_id:
                raise BackupError("restore application mismatch")
            components = self._verify_artifact(artifact, encryptor=encryptor)
            restored_root = validate_isolated_child(
                target.root, "restored", field="restore destination"
            )
            staging_root = validate_isolated_child(
                target.root, "restore-staging", field="restore staging"
            )
            final = validate_isolated_child(
                restored_root, backup_id, field="restore destination artifact"
            )
            if final.exists():
                raise BackupError("restore destination already exists")
            staging_candidate = validate_isolated_child(
                staging_root, backup_id, field="restore staging artifact"
            )
            staging_candidate.mkdir(parents=True, exist_ok=False)
            staging = staging_candidate
            component_dir = staging / "components"
            component_dir.mkdir()
            for component in components:
                (component_dir / f"{component.name}.bin").write_bytes(component.payload)
            restored_root.mkdir(parents=True, exist_ok=True)
            validate_isolated_root(restored_root, field="restore destination")
            staging.replace(final)
            rto = max(0, int(time.monotonic() - started))
            rpo = max(
                0,
                int((utc(now) - utc(artifact.manifest.source_captured_at)).total_seconds()),
            )
            return RestoreEvidence(
                backup_id=backup_id,
                status="restore_verified",
                tenant_id=target.tenant_id,
                application_id=target.application_id,
                restored_component_names=tuple(component.name for component in components),
                destination=target,
                rpo_observed_seconds=rpo,
                rto_observed_seconds=rto,
                controlled_test_only=not vault.destination.external,
            )
        except Exception as exc:
            if staging is not None and staging.exists():
                for path in sorted(staging.rglob("*"), reverse=True):
                    if path.is_file():
                        path.unlink()
                    elif path.is_dir():
                        path.rmdir()
                staging.rmdir()
            code = _failure_code(exc)
            return RestoreEvidence(
                backup_id=backup_id,
                status="restore_failed",
                tenant_id=target.tenant_id,
                application_id=target.application_id,
                restored_component_names=(),
                destination=target,
                rpo_observed_seconds=0,
                rto_observed_seconds=None,
                controlled_test_only=not vault.destination.external,
                failure_code=code,
            )
