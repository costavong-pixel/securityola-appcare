"""Root-controlled attestation service for live Linux inventory receipts.

The SSH connector deliberately sends a complete, canonical receipt message to
this boundary.  The boundary is useful only when it can compare that message
with operation evidence recorded by an independently controlled transport
component.  It therefore refuses to sign merely well-formed caller input.

The service has no network listener, no shell path, and no API for mutating the
source target.  The production entry point is expected to run as root with a
root-owned key, target policy, and evidence ledger.  The in-memory stores in
this module are test fixtures only.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import sqlite3
import stat
import struct
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Protocol, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..readiness.contracts import EvidenceClass, validate_scope_segment
from .linux_ssh_contracts import (
    LIVE_INVENTORY_RECEIPT_ATTESTOR_SOCKET,
    LIVE_RECEIPT_SIGNATURE_ALGORITHM,
    LinuxTarget,
    OperationKind,
    OperationStatus,
    live_snapshot_receipt_path,
    validate_operation_id,
)

ATTESTOR_PRIVATE_KEY_PATH: Final = Path(
    "/etc/securityola/appcare/live-inventory/receipt-signing-private-key"
)
ATTESTOR_POLICY_PATH: Final = Path("/etc/securityola/appcare/live-inventory/attestor-policy.json")
ATTESTOR_EVIDENCE_PATH: Final = Path(
    "/var/lib/securityola/appcare/evidence/live-inventory/operation-evidence.json"
)
ATTESTOR_REPLAY_LEDGER_PATH: Final = Path(
    "/var/lib/securityola/appcare/evidence/live-inventory/attestor-replay.db"
)
ATTESTOR_MAX_MESSAGE_BYTES: Final = 64 * 1024
ATTESTOR_MAX_POLICY_BYTES: Final = 64 * 1024
ATTESTOR_MAX_EVIDENCE_BYTES: Final = 4 * 1024 * 1024
ATTESTOR_MAX_RESPONSE_BYTES: Final = 64
ATTESTOR_MAX_CLOCK_SKEW: Final = timedelta(seconds=30)
ATTESTOR_MAX_EVIDENCE_AGE: Final = timedelta(minutes=10)
_SHA256_HEX_LENGTH = 64
_ED25519_PRIVATE_BYTES = 32
_SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)


class AttestorError(ValueError):
    """The attestor rejected an unsafe or untrusted request."""


class TrustedOperationEvidenceStore(Protocol):
    """Root-controlled evidence source used by the attestor."""

    def lookup(
        self, *, target_reference: str, operation_id: str
    ) -> TrustedOperationEvidence | None:
        """Return independently recorded evidence for one operation."""

    def claim_receipt(self, *, target_reference: str, receipt_digest: str) -> bool:
        """Atomically consume a receipt digest exactly once."""


@dataclass(frozen=True, slots=True)
class RootBinding:
    """The device/inode identity independently observed for an approved root."""

    approved_root: str
    device: int
    inode: int
    record_evidence_digest: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> RootBinding:
        expected = {"approved_root", "device", "inode", "record_evidence_digest"}
        if set(value) != expected:
            raise AttestorError("root binding schema is invalid")
        root = value.get("approved_root")
        device = value.get("device")
        inode = value.get("inode")
        digest = value.get("record_evidence_digest")
        if (
            not isinstance(root, str)
            or not root.startswith("/")
            or isinstance(device, bool)
            or not isinstance(device, int)
            or device < 0
            or isinstance(inode, bool)
            or not isinstance(inode, int)
            or inode < 0
            or not _is_digest(digest)
        ):
            raise AttestorError("root binding values are invalid")
        return cls(root, device, inode, cast(str, digest))

    def to_dict(self) -> dict[str, object]:
        return {
            "approved_root": self.approved_root,
            "device": self.device,
            "inode": self.inode,
            "record_evidence_digest": self.record_evidence_digest,
        }


@dataclass(frozen=True, slots=True)
class TrustedOperationEvidence:
    """A sanitized record emitted by a separate trusted transport boundary."""

    operation_id: str
    operation: OperationKind
    tenant_id: str
    application_id: str
    target_reference: str
    status: OperationStatus
    evidence_digest: str
    transport_run_id: str
    record_evidence_digests: tuple[str, ...]
    host_identity: str
    root_bindings: tuple[RootBinding, ...]
    evidence_class: EvidenceClass
    observed_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        object.__setattr__(
            self, "tenant_id", validate_scope_segment(self.tenant_id, field_name="tenant_id")
        )
        object.__setattr__(
            self,
            "application_id",
            validate_scope_segment(self.application_id, field_name="application_id"),
        )
        object.__setattr__(
            self,
            "target_reference",
            validate_scope_segment(self.target_reference, field_name="target_reference"),
        )
        if not _is_digest(self.evidence_digest):
            raise AttestorError("operation evidence digest is invalid")
        object.__setattr__(self, "transport_run_id", validate_operation_id(self.transport_run_id))
        if len(self.record_evidence_digests) > 128:
            raise AttestorError("operation record evidence is invalid")
        if any(not _is_digest(item) for item in self.record_evidence_digests):
            raise AttestorError("operation record evidence digest is invalid")
        if len(set(self.record_evidence_digests)) != len(self.record_evidence_digests):
            raise AttestorError("operation record evidence contains duplicates")
        if not self.host_identity or len(self.host_identity) > 253:
            raise AttestorError("operation host identity is invalid")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise AttestorError("operation evidence timestamp is invalid")
        if not isinstance(self.operation, OperationKind):
            raise AttestorError("operation kind is invalid")
        if self.operation == OperationKind.HOST_INVENTORY and not self.record_evidence_digests:
            raise AttestorError("inventory record evidence is missing")
        if not isinstance(self.status, OperationStatus):
            raise AttestorError("operation status is invalid")
        if not isinstance(self.evidence_class, EvidenceClass):
            raise AttestorError("operation evidence class is invalid")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> TrustedOperationEvidence:
        expected = {
            "operation_id",
            "operation",
            "tenant_id",
            "application_id",
            "target_reference",
            "status",
            "evidence_digest",
            "transport_run_id",
            "record_evidence_digests",
            "host_identity",
            "root_bindings",
            "evidence_class",
            "observed_at",
        }
        if set(value) != expected:
            raise AttestorError("operation evidence schema is invalid")
        operation_id = value.get("operation_id")
        operation = value.get("operation")
        tenant_id = value.get("tenant_id")
        application_id = value.get("application_id")
        target_reference = value.get("target_reference")
        status = value.get("status")
        evidence_digest = value.get("evidence_digest")
        transport_run_id = value.get("transport_run_id")
        record_digests = value.get("record_evidence_digests")
        host_identity = value.get("host_identity")
        root_values = value.get("root_bindings")
        evidence_class = value.get("evidence_class")
        observed_at = value.get("observed_at")
        if (
            not isinstance(operation_id, str)
            or not isinstance(operation, str)
            or not isinstance(tenant_id, str)
            or not isinstance(application_id, str)
            or not isinstance(target_reference, str)
            or not isinstance(status, str)
            or not isinstance(evidence_digest, str)
            or not isinstance(transport_run_id, str)
            or not isinstance(record_digests, list)
            or not isinstance(host_identity, str)
            or not isinstance(root_values, list)
            or not isinstance(evidence_class, str)
            or not isinstance(observed_at, str)
            or any(not isinstance(item, str) for item in record_digests)
            or any(not isinstance(item, Mapping) for item in root_values)
        ):
            raise AttestorError("operation evidence values are invalid")
        try:
            parsed_time = datetime.fromisoformat(observed_at)
            parsed_operation = OperationKind(operation)
            parsed_status = OperationStatus(status)
            parsed_class = EvidenceClass(evidence_class)
        except (TypeError, ValueError) as exc:
            raise AttestorError("operation evidence values are invalid") from exc
        return cls(
            operation_id=operation_id,
            operation=parsed_operation,
            tenant_id=tenant_id,
            application_id=application_id,
            target_reference=target_reference,
            status=parsed_status,
            evidence_digest=evidence_digest,
            transport_run_id=transport_run_id,
            record_evidence_digests=tuple(record_digests),
            host_identity=host_identity,
            root_bindings=tuple(
                RootBinding.from_mapping(cast(Mapping[str, object], item)) for item in root_values
            ),
            evidence_class=parsed_class,
            observed_at=parsed_time,
        )


class InMemoryTrustedOperationEvidenceStore:
    """Fixture-only evidence store; never use this class for live service state."""

    def __init__(self, records: Sequence[TrustedOperationEvidence] = ()) -> None:
        self._records = {(item.target_reference, item.operation_id): item for item in records}
        self._claimed: set[tuple[str, str]] = set()

    def lookup(
        self, *, target_reference: str, operation_id: str
    ) -> TrustedOperationEvidence | None:
        return self._records.get((target_reference, operation_id))

    def claim_receipt(self, *, target_reference: str, receipt_digest: str) -> bool:
        key = (target_reference, receipt_digest)
        if key in self._claimed:
            return False
        self._claimed.add(key)
        return True


class SqliteAttestorReplayLedger:
    """Root-owned durable single-use receipt ledger."""

    def __init__(self, path: Path = ATTESTOR_REPLAY_LEDGER_PATH) -> None:
        self._path = _validate_private_runtime_path(path, "attestor replay ledger")
        _prepare_private_runtime_file(self._path)
        try:
            with sqlite3.connect(self._path, timeout=5.0) as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS attestor_receipts (
                        target_reference TEXT NOT NULL,
                        receipt_digest TEXT NOT NULL,
                        claimed_at TEXT NOT NULL,
                        PRIMARY KEY (target_reference, receipt_digest)
                    )
                    """
                )
                connection.commit()
        except sqlite3.Error as exc:
            raise AttestorError("attestor replay ledger is unavailable") from exc

    def claim_receipt(self, *, target_reference: str, receipt_digest: str) -> bool:
        if not _is_digest(receipt_digest):
            raise AttestorError("receipt digest is invalid")
        target = validate_scope_segment(target_reference, field_name="target_reference")
        try:
            with sqlite3.connect(self._path, timeout=5.0, isolation_level=None) as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO attestor_receipts
                        (target_reference, receipt_digest, claimed_at)
                    VALUES (?, ?, ?)
                    """,
                    (target, receipt_digest, datetime.now(UTC).isoformat()),
                )
                connection.commit()
                return cursor.rowcount == 1
        except sqlite3.Error as exc:
            raise AttestorError("attestor replay ledger is unavailable") from exc


class JsonTrustedOperationEvidenceStore:
    """Read-only root-owned evidence records plus a durable replay ledger."""

    def __init__(
        self,
        evidence_path: Path = ATTESTOR_EVIDENCE_PATH,
        *,
        replay_ledger: SqliteAttestorReplayLedger | None = None,
    ) -> None:
        self._path = _validate_private_runtime_path(evidence_path, "attestor evidence")
        self._replay = replay_ledger or SqliteAttestorReplayLedger()

    def lookup(
        self, *, target_reference: str, operation_id: str
    ) -> TrustedOperationEvidence | None:
        target = validate_scope_segment(target_reference, field_name="target_reference")
        operation = validate_operation_id(operation_id)
        for record in self._read_records():
            if record.target_reference == target and record.operation_id == operation:
                return record
        return None

    def claim_receipt(self, *, target_reference: str, receipt_digest: str) -> bool:
        return self._replay.claim_receipt(
            target_reference=target_reference, receipt_digest=receipt_digest
        )

    def _read_records(self) -> tuple[TrustedOperationEvidence, ...]:
        raw = _read_trusted_file(self._path, ATTESTOR_MAX_EVIDENCE_BYTES, "attestor evidence")
        try:
            value = _json_loads_strict(raw)
        except (AttestorError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AttestorError("attestor evidence is invalid") from exc
        if not isinstance(value, Mapping) or set(value) != {"schema_version", "operations"}:
            raise AttestorError("attestor evidence schema is invalid")
        if value.get("schema_version") != 1:
            raise AttestorError("attestor evidence schema is invalid")
        operations = value.get("operations")
        if not isinstance(operations, list) or len(operations) > 4096:
            raise AttestorError("attestor evidence operation list is invalid")
        records = tuple(
            TrustedOperationEvidence.from_mapping(item)
            for item in operations
            if isinstance(item, Mapping)
        )
        if len(records) != len(operations):
            raise AttestorError("attestor evidence operation list is invalid")
        identities = {(item.target_reference, item.operation_id) for item in records}
        if len(identities) != len(records):
            raise AttestorError("attestor evidence contains duplicate operations")
        return records


@dataclass(frozen=True, slots=True)
class AttestorPolicy:
    """Exact target and peer boundary loaded from root-owned policy."""

    target: LinuxTarget
    allowed_peer_uid: int
    allowed_peer_gid: int

    def __post_init__(self) -> None:
        for name in ("allowed_peer_uid", "allowed_peer_gid"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise AttestorError(f"{name} is invalid")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> AttestorPolicy:
        expected = {"schema_version", "allowed_peer_uid", "allowed_peer_gid", "target"}
        if set(value) != expected or value.get("schema_version") != 1:
            raise AttestorError("attestor policy schema is invalid")
        peer_uid = value.get("allowed_peer_uid")
        peer_gid = value.get("allowed_peer_gid")
        target_value = value.get("target")
        if (
            isinstance(peer_uid, bool)
            or not isinstance(peer_uid, int)
            or isinstance(peer_gid, bool)
            or not isinstance(peer_gid, int)
            or not isinstance(target_value, Mapping)
        ):
            raise AttestorError("attestor policy values are invalid")
        target = _target_from_mapping(target_value)
        return cls(target=target, allowed_peer_uid=peer_uid, allowed_peer_gid=peer_gid)


class RootControlledLiveInventoryAttestor:
    """Validate a canonical live receipt against independent evidence, then sign it."""

    def __init__(
        self,
        *,
        policy: AttestorPolicy,
        evidence: TrustedOperationEvidenceStore,
        signer: Ed25519PrivateKey,
        clock: Callable[..., datetime] | None = None,
    ) -> None:
        self.policy = policy
        self._evidence = evidence
        self._signer = signer
        self._clock = clock or (lambda: datetime.now(UTC))
        if not isinstance(signer, Ed25519PrivateKey):
            raise AttestorError("attestor signer is invalid")

    def attest(self, message: bytes) -> bytes:
        payload = _parse_canonical_message(message)
        receipt_digest = self._validate_payload(payload)
        if not self._evidence.claim_receipt(
            target_reference=self.policy.target.target_reference,
            receipt_digest=receipt_digest,
        ):
            raise AttestorError("receipt replayed")
        signature = self._signer.sign(message)
        if len(signature) != ATTESTOR_MAX_RESPONSE_BYTES:
            raise AttestorError("attestor signature is malformed")
        return signature

    def _validate_payload(self, payload: Mapping[str, object]) -> str:
        expected = {
            "schema_version",
            "receipt_signature_algorithm",
            "sealed",
            "receipt_path",
            "target",
            "connection_operation_id",
            "connection_evidence_digest",
            "inventory_operation_id",
            "inventory_evidence_digest",
            "transport_run_id",
            "record_evidence_digests",
            "source_binding",
            "evidence_reference",
            "receipt_digest",
        }
        if set(payload) != expected:
            raise AttestorError("receipt schema is invalid")
        if payload.get("schema_version") != 1 or payload.get("sealed") is not True:
            raise AttestorError("receipt state is invalid")
        if payload.get("receipt_signature_algorithm") != LIVE_RECEIPT_SIGNATURE_ALGORITHM:
            raise AttestorError("receipt signature algorithm is invalid")
        supplied_digest = payload.get("receipt_digest")
        if not _is_digest(supplied_digest):
            raise AttestorError("receipt digest is invalid")
        without_digest = dict(payload)
        without_digest.pop("receipt_digest", None)
        expected_digest = hashlib.sha256(_canonical_json(without_digest)).hexdigest()
        if not secrets.compare_digest(cast(str, supplied_digest), expected_digest):
            raise AttestorError("receipt digest mismatch")
        target_value = payload.get("target")
        if not isinstance(target_value, Mapping) or dict(target_value) != _target_payload(
            self.policy.target
        ):
            raise AttestorError("receipt target is not approved")
        connection_id = payload.get("connection_operation_id")
        inventory_id = payload.get("inventory_operation_id")
        connection_digest = payload.get("connection_evidence_digest")
        inventory_digest = payload.get("inventory_evidence_digest")
        transport_run_id = payload.get("transport_run_id")
        record_digests = payload.get("record_evidence_digests")
        if (
            not isinstance(connection_id, str)
            or not isinstance(inventory_id, str)
            or connection_id == inventory_id
            or not _is_digest(connection_digest)
            or not _is_digest(inventory_digest)
            or not isinstance(transport_run_id, str)
            or not isinstance(record_digests, list)
            or not record_digests
            or len(record_digests) > 128
            or any(not _is_digest(item) for item in record_digests)
            or len(set(record_digests)) != len(record_digests)
        ):
            raise AttestorError("receipt operation evidence is malformed")
        connection = self._lookup(connection_id)
        inventory = self._lookup(inventory_id)
        if (
            connection.operation != OperationKind.CONNECTION_PROBE
            or inventory.operation != OperationKind.HOST_INVENTORY
            or connection.status != OperationStatus.PASSED
            or inventory.status != OperationStatus.PASSED
            or connection.evidence_class != EvidenceClass.REAL_TARGET
            or inventory.evidence_class != EvidenceClass.REAL_TARGET
            or connection.evidence_digest != connection_digest
            or inventory.evidence_digest != inventory_digest
            or connection.transport_run_id != transport_run_id
            or inventory.transport_run_id != transport_run_id
            or connection.transport_run_id != inventory.transport_run_id
            or tuple(record_digests) != inventory.record_evidence_digests
        ):
            raise AttestorError("receipt operation evidence does not match")
        self._validate_fresh(connection.observed_at)
        self._validate_fresh(inventory.observed_at)
        if connection.record_evidence_digests:
            raise AttestorError("connection evidence records are unexpected")
        if connection.host_identity != self.policy.target.expected_hostname:
            raise AttestorError("connection host identity is invalid")
        if inventory.host_identity != self.policy.target.expected_hostname:
            raise AttestorError("inventory host identity is invalid")
        source_binding = payload.get("source_binding")
        if not isinstance(source_binding, Mapping):
            raise AttestorError("receipt source binding is malformed")
        self._validate_source_binding(source_binding, inventory)
        if (
            payload.get("receipt_path")
            != live_snapshot_receipt_path(self.policy.target, inventory_id).as_posix()
        ):
            raise AttestorError("receipt path is not approved")
        if payload.get("evidence_reference") != (
            f"live://{self.policy.target.target_reference}/inventory/{inventory_digest}"
        ):
            raise AttestorError("receipt evidence reference is invalid")
        return cast(str, supplied_digest)

    def _lookup(self, operation_id: object) -> TrustedOperationEvidence:
        if not isinstance(operation_id, str):
            raise AttestorError("operation identity is malformed")
        normalized = validate_operation_id(operation_id)
        record = self._evidence.lookup(
            target_reference=self.policy.target.target_reference,
            operation_id=normalized,
        )
        if record is None:
            raise AttestorError("operation evidence is unavailable")
        if (
            record.target_reference != self.policy.target.target_reference
            or record.tenant_id != self.policy.target.tenant_id
            or record.application_id != self.policy.target.application_id
        ):
            raise AttestorError("operation evidence scope is invalid")
        return record

    def _validate_fresh(self, observed_at: datetime) -> None:
        now = _utc_now(self._clock)
        timestamp = observed_at.astimezone(UTC)
        if timestamp < now - ATTESTOR_MAX_EVIDENCE_AGE or timestamp > now + ATTESTOR_MAX_CLOCK_SKEW:
            raise AttestorError("operation evidence is stale")

    def _validate_source_binding(
        self, value: Mapping[str, object], inventory: TrustedOperationEvidence
    ) -> None:
        if set(value) != {"host_identity", "host_record_evidence_digest", "roots"}:
            raise AttestorError("source binding schema is invalid")
        host_identity = value.get("host_identity")
        host_digest = value.get("host_record_evidence_digest")
        roots = value.get("roots")
        if (
            host_identity != self.policy.target.expected_hostname
            or not _is_digest(host_digest)
            or not isinstance(roots, list)
            or len(roots) != len(self.policy.target.approved_application_roots)
            or any(not isinstance(item, Mapping) for item in roots)
        ):
            raise AttestorError("source binding values are invalid")
        if host_digest not in inventory.record_evidence_digests:
            raise AttestorError("source host evidence is not bound")
        parsed = tuple(RootBinding.from_mapping(item) for item in roots)
        expected = inventory.root_bindings
        if parsed != expected:
            raise AttestorError("source root binding does not match")
        if {item.approved_root for item in parsed} != set(
            self.policy.target.approved_application_roots
        ):
            raise AttestorError("source root is not approved")
        if any(
            item.record_evidence_digest not in inventory.record_evidence_digests for item in parsed
        ):
            raise AttestorError("source root evidence is not bound")


def _target_payload(target: LinuxTarget) -> dict[str, object]:
    return {
        "tenant_id": target.tenant_id,
        "application_id": target.application_id,
        "environment": target.environment,
        "host": target.host,
        "expected_hostname": target.expected_hostname,
        "ssh_port": target.ssh_port,
        "expected_host_key_fingerprint": target.expected_host_key_fingerprint,
        "credential_reference": target.credential_reference,
        "remote_user": target.remote_user,
        "approved_application_roots": list(target.approved_application_roots),
        "approved_service_names": list(target.approved_service_names),
        "approved_database_identifiers": list(target.approved_database_identifiers),
        "target_reference": target.target_reference,
    }


def _target_from_mapping(value: Mapping[str, object]) -> LinuxTarget:
    expected = {
        "tenant_id",
        "application_id",
        "environment",
        "host",
        "expected_hostname",
        "ssh_port",
        "expected_host_key_fingerprint",
        "credential_reference",
        "remote_user",
        "approved_application_roots",
        "approved_service_names",
        "approved_database_identifiers",
        "target_reference",
    }
    if set(value) != expected:
        raise AttestorError("attestor target schema is invalid")
    roots = value.get("approved_application_roots")
    services = value.get("approved_service_names")
    databases = value.get("approved_database_identifiers")
    if (
        not isinstance(roots, list)
        or not isinstance(services, list)
        or not isinstance(databases, list)
        or any(not isinstance(item, str) for item in (*roots, *services, *databases))
    ):
        raise AttestorError("attestor target values are invalid")
    try:
        return LinuxTarget(
            tenant_id=value["tenant_id"],  # type: ignore[arg-type]
            application_id=value["application_id"],  # type: ignore[arg-type]
            environment=value["environment"],  # type: ignore[arg-type]
            host=value["host"],  # type: ignore[arg-type]
            expected_hostname=value["expected_hostname"],  # type: ignore[arg-type]
            ssh_port=value["ssh_port"],  # type: ignore[arg-type]
            expected_host_key_fingerprint=value["expected_host_key_fingerprint"],  # type: ignore[arg-type]
            credential_reference=value["credential_reference"],  # type: ignore[arg-type]
            remote_user=value["remote_user"],  # type: ignore[arg-type]
            approved_application_roots=tuple(roots),
            approved_service_names=tuple(services),
            approved_database_identifiers=tuple(databases),
            target_reference=value["target_reference"],  # type: ignore[arg-type]
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise AttestorError("attestor target values are invalid") from exc


def _parse_canonical_message(message: bytes) -> dict[str, object]:
    if not isinstance(message, bytes) or not message or len(message) > ATTESTOR_MAX_MESSAGE_BYTES:
        raise AttestorError("attestor request is too large or empty")
    try:
        value = _json_loads_strict(message)
    except (UnicodeDecodeError, json.JSONDecodeError, AttestorError) as exc:
        raise AttestorError("attestor request is malformed") from exc
    if not isinstance(value, dict) or _canonical_json(value) != message:
        raise AttestorError("attestor request is not canonical")
    return value


def _json_loads_strict(raw: bytes) -> object:
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_json_constant,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AttestorError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise AttestorError(f"JSON constant {value} is not allowed")


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _is_digest(value: object) -> bool:
    if not isinstance(value, str) or len(value) != _SHA256_HEX_LENGTH:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _utc_now(clock: Callable[..., datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime):
        raise AttestorError("attestor clock is invalid")
    if value.tzinfo is None or value.utcoffset() is None:
        raise AttestorError("attestor clock is invalid")
    return value.astimezone(UTC)


def _validate_private_runtime_path(path: Path, name: str) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise AttestorError(f"{name} path is unsafe")
    if os.name == "posix":
        current = Path(path.anchor)
        for part in path.parts[1:-1]:
            current /= part
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise AttestorError(f"{name} parent is unavailable") from exc
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise AttestorError(f"{name} parent is unsafe")
    return path


def _prepare_private_runtime_file(path: Path) -> None:
    if path.is_symlink():
        raise AttestorError("private runtime file is a symlink")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise AttestorError("private runtime file is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise AttestorError("private runtime file is not regular")
    if os.name == "posix" and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise AttestorError("private runtime file permissions are unsafe")


def _read_trusted_file(path: Path, maximum: int, name: str) -> bytes:
    if path.is_symlink():
        raise AttestorError(f"{name} is a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > maximum
            or (
                os.name == "posix"
                and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077)
            )
        ):
            raise AttestorError(f"{name} permissions or type are unsafe")
        content = bytearray()
        while len(content) <= maximum:
            chunk = os.read(descriptor, min(8192, maximum + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) != metadata.st_size or len(content) > maximum:
            raise AttestorError(f"{name} read is incomplete")
        return bytes(content)
    except AttestorError:
        raise
    except OSError as exc:
        raise AttestorError(f"{name} is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_signing_key(path: Path = ATTESTOR_PRIVATE_KEY_PATH) -> Ed25519PrivateKey:
    """Load a raw Ed25519 private key only from the root-owned path boundary."""

    raw = _read_trusted_file(path, _ED25519_PRIVATE_BYTES, "attestor private key")
    if len(raw) != _ED25519_PRIVATE_BYTES:
        raise AttestorError("attestor private key length is invalid")
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:
        raise AttestorError("attestor private key is invalid") from exc


def load_policy(path: Path = ATTESTOR_POLICY_PATH) -> AttestorPolicy:
    raw = _read_trusted_file(path, ATTESTOR_MAX_POLICY_BYTES, "attestor policy")
    try:
        value = _json_loads_strict(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, AttestorError) as exc:
        raise AttestorError("attestor policy is malformed") from exc
    if not isinstance(value, Mapping):
        raise AttestorError("attestor policy is malformed")
    return AttestorPolicy.from_mapping(value)


class UnixSocketAttestorServer:
    """Serve the fixed four-byte-length Unix-socket protocol used by the client."""

    def __init__(
        self,
        *,
        attestor: RootControlledLiveInventoryAttestor,
        socket_path: Path = LIVE_INVENTORY_RECEIPT_ATTESTOR_SOCKET,
        allowed_peer_uid: int,
        allowed_peer_gid: int,
    ) -> None:
        if os.name != "posix":
            raise AttestorError("attestor service requires POSIX")
        if socket_path != LIVE_INVENTORY_RECEIPT_ATTESTOR_SOCKET:
            raise AttestorError("attestor socket path is not fixed")
        if allowed_peer_uid < 0 or allowed_peer_gid < 0:
            raise AttestorError("attestor peer identity is invalid")
        self._attestor = attestor
        self._path = socket_path
        self._peer_uid = allowed_peer_uid
        self._peer_gid = allowed_peer_gid

    def serve_forever(self) -> None:
        listener = self._bind_socket()
        try:
            while True:
                connection, _address = listener.accept()
                with connection:
                    self._handle(connection)
        finally:
            listener.close()
            try:
                self._path.unlink()
            except OSError:
                pass

    def _bind_socket(self) -> socket.socket:
        _validate_socket_parent(self._path.parent)
        if self._path.exists() or self._path.is_symlink():
            try:
                metadata = self._path.lstat()
            except OSError as exc:
                raise AttestorError("attestor socket path is unavailable") from exc
            if (
                not stat.S_ISSOCK(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_nlink != 1
            ):
                raise AttestorError("attestor socket replacement is unsafe")
            self._path.unlink()
        address_family = cast(int, socket.AF_UNIX)  # type: ignore[attr-defined]
        listener = socket.socket(address_family, socket.SOCK_STREAM)
        try:
            listener.bind(self._path.as_posix())
            os.chmod(self._path, 0o660)
            os.chown(self._path, 0, self._peer_gid)  # type: ignore[attr-defined]
            listener.listen(8)
            return listener
        except (OSError, ValueError) as exc:
            listener.close()
            raise AttestorError("attestor socket bind failed") from exc

    def _handle(self, connection: socket.socket) -> None:
        if not _peer_uid_is_allowed(connection, self._peer_uid):
            try:
                connection.sendall(struct.pack("!I", 0))
            except OSError:
                pass
            return
        try:
            connection.settimeout(5.0)
            raw_length = _read_exact(connection, 4)
            length = struct.unpack("!I", raw_length)[0]
            if not 1 <= length <= ATTESTOR_MAX_MESSAGE_BYTES:
                raise AttestorError("attestor request length is invalid")
            message = _read_exact(connection, length)
            _require_frame_eof(connection)
            signature = self._attestor.attest(message)
            connection.sendall(struct.pack("!I", len(signature)) + signature)
        except (AttestorError, OSError, struct.error):
            try:
                connection.sendall(struct.pack("!I", 0))
            except OSError:
                pass


def _require_frame_eof(connection: socket.socket) -> None:
    """Require the client to half-close after exactly one framed request."""

    try:
        extra = connection.recv(1)
    except TimeoutError:
        raise AttestorError("attestor request is not half-closed") from None
    if extra:
        raise AttestorError("attestor request has trailing data")


def _peer_uid_is_allowed(connection: socket.socket, allowed_uid: int) -> bool:
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, 12)
        _pid, uid, _gid = cast(tuple[int, int, int], struct.unpack("3i", raw))
    except (OSError, struct.error):
        return False
    return uid == allowed_uid


def _read_exact(connection: socket.socket, length: int) -> bytes:
    content = bytearray()
    while len(content) < length:
        chunk = connection.recv(length - len(content))
        if not chunk:
            raise AttestorError("attestor frame ended early")
        content.extend(chunk)
    return bytes(content)


def _validate_socket_parent(path: Path) -> None:
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise AttestorError("attestor socket parent is unsafe")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise AttestorError("attestor socket parent is unavailable") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise AttestorError("attestor socket parent is unsafe")


def main() -> int:
    """Run the root-only service with fixed production paths."""

    geteuid = cast(Callable[[], int], getattr(os, "geteuid", lambda: -1))
    if os.name != "posix" or geteuid() != 0:
        return 126
    try:
        policy = load_policy()
        signer = load_signing_key()
        evidence = JsonTrustedOperationEvidenceStore()
        attestor = RootControlledLiveInventoryAttestor(
            policy=policy,
            evidence=evidence,
            signer=signer,
        )
        UnixSocketAttestorServer(
            attestor=attestor,
            allowed_peer_uid=policy.allowed_peer_uid,
            allowed_peer_gid=policy.allowed_peer_gid,
        ).serve_forever()
    except (AttestorError, OSError, ValueError):
        return 126
    return 0


__all__ = [
    "ATTESTOR_EVIDENCE_PATH",
    "ATTESTOR_MAX_EVIDENCE_AGE",
    "ATTESTOR_MAX_MESSAGE_BYTES",
    "ATTESTOR_POLICY_PATH",
    "ATTESTOR_PRIVATE_KEY_PATH",
    "ATTESTOR_REPLAY_LEDGER_PATH",
    "AttestorError",
    "AttestorPolicy",
    "InMemoryTrustedOperationEvidenceStore",
    "JsonTrustedOperationEvidenceStore",
    "RootBinding",
    "RootControlledLiveInventoryAttestor",
    "SqliteAttestorReplayLedger",
    "TrustedOperationEvidence",
    "TrustedOperationEvidenceStore",
    "UnixSocketAttestorServer",
    "load_policy",
    "load_signing_key",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
