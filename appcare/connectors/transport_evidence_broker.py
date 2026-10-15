"""Transport-owned publisher for the root-controlled live evidence boundary.

This module is deliberately narrower than the attestor.  The attestor signs a
receipt only after reading this store; this broker is the only code path that
turns a sealed, live SSH result into the sanitized operation records the
attestor accepts.  It never serializes remote output, target configuration, or
credential material.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC
from pathlib import Path
from typing import Final, cast

from .linux_ssh_contracts import (
    EvidenceClass,
    InventoryRecord,
    LinuxInventorySnapshot,
    LinuxTarget,
    OperationKind,
    OperationLedger,
    OperationStatus,
    RemoteExecutionResult,
    _live_transport_run_id,
    required_inventory_records_complete,
    validate_operation_id,
)
from .live_inventory_attestor import (
    ATTESTOR_EVIDENCE_PATH,
    ATTESTOR_MAX_EVIDENCE_BYTES,
    RootBinding,
    TrustedOperationEvidence,
)

_EVIDENCE_SCHEMA_VERSION: Final = 1
_MAX_RECORDS: Final = 128
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


class TransportEvidenceBrokerError(ValueError):
    """The transport did not produce publishable trusted evidence."""


class TrustedOperationEvidenceBroker:
    """Publish evidence derived from one transport-owned inventory snapshot.

    ``LinuxSSHClient`` marks results with a private per-client authority token
    immediately before returning them.  A result merely labelled
    ``REAL_TARGET`` is not sufficient; caller-created fixture/reference
    objects, or caller-created objects carrying that label, have no token and
    are rejected.
    """

    __slots__ = (
        "_target",
        "_path",
        "_operation_ledger",
        "_max_bytes",
        "_authority",
        "_lock",
    )

    def __init__(
        self,
        target: LinuxTarget,
        *,
        operation_ledger: OperationLedger,
        evidence_path: Path = ATTESTOR_EVIDENCE_PATH,
        max_bytes: int = ATTESTOR_MAX_EVIDENCE_BYTES,
    ) -> None:
        if not isinstance(target, LinuxTarget):
            raise TransportEvidenceBrokerError("broker target is invalid")
        if not getattr(operation_ledger, "durable", False):
            raise TransportEvidenceBrokerError("live evidence requires a durable operation ledger")
        self._target = target
        self._path = self._validate_path(evidence_path)
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or not 1024 <= max_bytes <= ATTESTOR_MAX_EVIDENCE_BYTES
        ):
            raise TransportEvidenceBrokerError("evidence size limit is invalid")
        self._max_bytes = max_bytes
        self._operation_ledger = operation_ledger
        self._authority = object()
        self._lock = threading.RLock()

    @property
    def evidence_path(self) -> Path:
        return self._path

    @property
    def target(self) -> LinuxTarget:
        return self._target

    def _mark_transport_result(self, result: RemoteExecutionResult) -> None:
        """Seal a result created by this broker's owning SSH client."""

        if not isinstance(result, RemoteExecutionResult):
            raise TransportEvidenceBrokerError("transport result is invalid")
        object.__setattr__(result, "_transport_authority", self._authority)

    def publish(self, snapshot: LinuxInventorySnapshot) -> tuple[TrustedOperationEvidence, ...]:
        """Atomically append the connection and complete-inventory evidence."""

        connection, inventory, records, run_id = self._validate_snapshot(snapshot)
        evidence = (
            self._operation_evidence(
                connection,
                transport_run_id=run_id,
                host_identity=self._target.expected_hostname,
                root_bindings=(),
            ),
            self._operation_evidence(
                inventory,
                transport_run_id=run_id,
                host_identity=self._target.expected_hostname,
                root_bindings=self._root_bindings(records),
            ),
        )
        with self._lock, self._file_lock():
            existing = self._read_existing()
            existing_keys = {(item.target_reference, item.operation_id) for item in existing}
            incoming_keys = {(item.target_reference, item.operation_id) for item in evidence}
            if len(incoming_keys) != len(evidence) or existing_keys & incoming_keys:
                raise TransportEvidenceBrokerError("operation evidence replayed")

            # The transport operation ledger is also the durable single-use
            # claim for publication.  It prevents two brokers racing before
            # either one can observe the file replacement.
            claim_id = f"evidence-{inventory.evidence_digest}"
            if not self._operation_ledger.claim(
                target_reference=self._target.target_reference,
                operation_id=validate_operation_id(claim_id),
            ):
                raise TransportEvidenceBrokerError("operation evidence replayed")
            self._atomic_publish((*existing, *evidence), encoded_override=None)
        return evidence

    # Explicit name used by the SSH transport integration and by callers that
    # prefer to make the authority boundary visible in code review.
    publish_snapshot = publish

    def _validate_snapshot(
        self, snapshot: LinuxInventorySnapshot
    ) -> tuple[
        RemoteExecutionResult,
        RemoteExecutionResult,
        tuple[InventoryRecord, ...],
        str,
    ]:
        if not isinstance(snapshot, LinuxInventorySnapshot) or snapshot.target != self._target:
            raise TransportEvidenceBrokerError("inventory snapshot target is not approved")
        connection = snapshot.connection
        inventory = snapshot.inventory
        records = tuple(snapshot.records)
        if not self._is_transport_owned(connection) or not self._is_transport_owned(inventory):
            raise TransportEvidenceBrokerError("operation evidence is not transport-authorized")
        if (
            connection.evidence_class != EvidenceClass.REAL_TARGET
            or inventory.evidence_class != EvidenceClass.REAL_TARGET
            or connection.operation != OperationKind.CONNECTION_PROBE
            or inventory.operation != OperationKind.HOST_INVENTORY
            or connection.status != OperationStatus.PASSED
            or inventory.status != OperationStatus.PASSED
            or connection.records
            or inventory.records != records
            or not records
            or len(records) > _MAX_RECORDS
            or any(record.evidence_class != EvidenceClass.REAL_TARGET for record in records)
        ):
            raise TransportEvidenceBrokerError("live inventory evidence is incomplete")
        if not self._scope_matches(connection) or not self._scope_matches(inventory):
            raise TransportEvidenceBrokerError("operation evidence scope is invalid")
        if any(
            not isinstance(record, InventoryRecord)
            or record.tenant_id != self._target.tenant_id
            or record.application_id != self._target.application_id
            or record.target_reference != self._target.target_reference
            for record in records
        ):
            raise TransportEvidenceBrokerError("inventory evidence scope is invalid")
        if not required_inventory_records_complete(self._target, records):
            raise TransportEvidenceBrokerError("required inventory evidence is incomplete")
        try:
            run_id = _live_transport_run_id(connection.operation_id, inventory.operation_id)
        except (TypeError, ValueError):
            run_id = None
        if run_id is None or not run_id:
            raise TransportEvidenceBrokerError("operation evidence run binding is invalid")
        return connection, inventory, records, run_id

    def _is_transport_owned(self, result: RemoteExecutionResult) -> bool:
        return getattr(result, "_transport_authority", None) is self._authority

    def _scope_matches(self, result: RemoteExecutionResult) -> bool:
        return (
            result.tenant_id == self._target.tenant_id
            and result.application_id == self._target.application_id
            and result.target_reference == self._target.target_reference
        )

    def _root_bindings(self, records: Sequence[InventoryRecord]) -> tuple[RootBinding, ...]:
        bindings: list[RootBinding] = []
        for approved_root in self._target.approved_application_roots:
            matches = tuple(
                record
                for record in records
                if record.source_reference == "linux-ssh/filesystem_metadata_read/metadata"
                and record.record_type == "filesystem"
                and record.identity == approved_root
            )
            if len(matches) != 1:
                raise TransportEvidenceBrokerError("approved root binding is unavailable")
            metadata = matches[0].metadata
            device = metadata.get("device")
            inode = metadata.get("inode")
            if (
                isinstance(device, bool)
                or not isinstance(device, int)
                or device < 0
                or isinstance(inode, bool)
                or not isinstance(inode, int)
                or inode < 0
            ):
                raise TransportEvidenceBrokerError("approved root binding is unverified")
            bindings.append(
                RootBinding(
                    approved_root=approved_root,
                    device=device,
                    inode=inode,
                    record_evidence_digest=matches[0].evidence_digest,
                )
            )
        return tuple(bindings)

    def _operation_evidence(
        self,
        result: RemoteExecutionResult,
        *,
        transport_run_id: str,
        host_identity: str,
        root_bindings: tuple[RootBinding, ...],
    ) -> TrustedOperationEvidence:
        return TrustedOperationEvidence(
            operation_id=result.operation_id,
            operation=result.operation,
            tenant_id=self._target.tenant_id,
            application_id=self._target.application_id,
            target_reference=self._target.target_reference,
            status=OperationStatus.PASSED,
            evidence_digest=result.evidence_digest,
            transport_run_id=transport_run_id,
            record_evidence_digests=tuple(record.evidence_digest for record in result.records),
            host_identity=host_identity,
            root_bindings=root_bindings,
            evidence_class=EvidenceClass.REAL_TARGET,
            observed_at=result.observed_at,
        )

    @staticmethod
    def _operation_payload(item: TrustedOperationEvidence) -> dict[str, object]:
        return {
            "operation_id": item.operation_id,
            "operation": item.operation.value,
            "tenant_id": item.tenant_id,
            "application_id": item.application_id,
            "target_reference": item.target_reference,
            "status": item.status.value,
            "evidence_digest": item.evidence_digest,
            "transport_run_id": item.transport_run_id,
            "record_evidence_digests": list(item.record_evidence_digests),
            "host_identity": item.host_identity,
            "root_bindings": [binding.to_dict() for binding in item.root_bindings],
            "evidence_class": item.evidence_class.value,
            "observed_at": item.observed_at.astimezone(UTC).isoformat(),
        }

    def _encode(self, operations: Sequence[TrustedOperationEvidence]) -> bytes:
        payload = {
            "schema_version": _EVIDENCE_SCHEMA_VERSION,
            "operations": [self._operation_payload(item) for item in operations],
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        if len(encoded) > self._max_bytes:
            raise TransportEvidenceBrokerError("operation evidence is too large")
        return encoded

    def _read_existing(self) -> tuple[TrustedOperationEvidence, ...]:
        try:
            path_metadata = self._path.lstat()
        except FileNotFoundError:
            return ()
        except OSError as exc:
            raise TransportEvidenceBrokerError("operation evidence is unavailable") from exc
        if stat.S_ISLNK(path_metadata.st_mode):
            raise TransportEvidenceBrokerError("operation evidence is a symlink")
        if not stat.S_ISREG(path_metadata.st_mode):
            raise TransportEvidenceBrokerError("operation evidence is not a regular file")
        raw = self._read_file(self._path)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TransportEvidenceBrokerError("operation evidence is malformed") from exc
        if not isinstance(value, dict) or set(value) != {"schema_version", "operations"}:
            raise TransportEvidenceBrokerError("operation evidence schema is invalid")
        if value.get("schema_version") != _EVIDENCE_SCHEMA_VERSION:
            raise TransportEvidenceBrokerError("operation evidence schema is invalid")
        operations = value.get("operations")
        if not isinstance(operations, list) or len(operations) > 4096:
            raise TransportEvidenceBrokerError("operation evidence operation list is invalid")
        if (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )
            != raw
        ):
            raise TransportEvidenceBrokerError("operation evidence is not canonical")
        try:
            records = tuple(
                TrustedOperationEvidence.from_mapping(cast(dict[str, object], item))
                for item in operations
            )
        except (TypeError, ValueError, KeyError) as exc:
            raise TransportEvidenceBrokerError("operation evidence records are invalid") from exc
        if len({(item.target_reference, item.operation_id) for item in records}) != len(records):
            raise TransportEvidenceBrokerError("operation evidence contains duplicates")
        return records

    def _atomic_publish(
        self,
        operations: Sequence[TrustedOperationEvidence],
        *,
        encoded_override: bytes | None,
    ) -> None:
        encoded = encoded_override or self._encode(operations)
        parent = self._path.parent
        temp_path: Path | None = None
        descriptor = -1
        try:
            for attempt in range(16):
                candidate = (
                    parent
                    / f".{self._path.name}.tmp-{os.getpid()}-{threading.get_ident()}-{attempt}"
                )
                try:
                    descriptor = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC,
                        0o600,
                    )
                    temp_path = candidate
                    break
                except FileExistsError:
                    continue
            if descriptor < 0 or temp_path is None:
                raise TransportEvidenceBrokerError(
                    "operation evidence temporary file is unavailable"
                )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise TransportEvidenceBrokerError("operation evidence temporary file is unsafe")
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise TransportEvidenceBrokerError("operation evidence write made no progress")
                view = view[written:]
            os.fsync(descriptor)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o400)
            os.close(descriptor)
            descriptor = -1
            try:
                destination_metadata = self._path.lstat()
            except FileNotFoundError:
                destination_metadata = None
            except OSError as exc:
                raise TransportEvidenceBrokerError(
                    "operation evidence destination is unavailable"
                ) from exc
            if destination_metadata is not None and (
                stat.S_ISLNK(destination_metadata.st_mode) or not self._trusted_file(self._path)
            ):
                raise TransportEvidenceBrokerError("operation evidence destination is unsafe")
            os.replace(temp_path, self._path)
            temp_path = None
            if os.name == "posix":
                directory_descriptor = os.open(parent, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
        except TransportEvidenceBrokerError:
            raise
        except OSError as exc:
            raise TransportEvidenceBrokerError("operation evidence publication failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except OSError:
                    pass

    @contextmanager
    def _file_lock(self) -> Iterator[None]:
        lock_path = self._path.with_name(f".{self._path.name}.lock")
        descriptor = -1
        try:
            descriptor = os.open(
                lock_path,
                os.O_RDWR | os.O_CREAT | _O_NOFOLLOW | _O_CLOEXEC,
                0o600,
            )
            if not self._trusted_open_file(descriptor, allow_empty=True):
                raise TransportEvidenceBrokerError("operation evidence lock is unsafe")
            if os.name == "posix":
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        except OSError as exc:
            raise TransportEvidenceBrokerError("operation evidence lock is unavailable") from exc
        finally:
            if descriptor >= 0:
                if os.name == "posix":
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    @classmethod
    def _validate_path(cls, path: Path) -> Path:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or path == Path(path.anchor)
            or any(part in {".", ".."} for part in path.parts)
        ):
            raise TransportEvidenceBrokerError("operation evidence path is unsafe")
        cls._validate_parent(path.parent)
        return path

    @staticmethod
    def _validate_parent(parent: Path) -> None:
        current = parent
        while True:
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise TransportEvidenceBrokerError(
                    "operation evidence parent is unavailable"
                ) from exc
            if not stat.S_ISDIR(metadata.st_mode) or (
                os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise TransportEvidenceBrokerError("operation evidence parent is unsafe")
            if os.name == "posix" and metadata.st_uid not in {0, os.getuid()}:
                raise TransportEvidenceBrokerError("operation evidence parent owner is unsafe")
            if current == Path(current.anchor):
                return
            current = current.parent

    @classmethod
    def _read_file(cls, path: Path) -> bytes:
        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
            metadata = os.fstat(descriptor)
            if (
                not cls._trusted_open_file(descriptor, allow_empty=False)
                or metadata.st_size > ATTESTOR_MAX_EVIDENCE_BYTES
            ):
                raise TransportEvidenceBrokerError("operation evidence file is unsafe")
            content = bytearray()
            while len(content) <= ATTESTOR_MAX_EVIDENCE_BYTES:
                chunk = os.read(
                    descriptor, min(8192, ATTESTOR_MAX_EVIDENCE_BYTES + 1 - len(content))
                )
                if not chunk:
                    break
                content.extend(chunk)
            if len(content) != metadata.st_size or len(content) > ATTESTOR_MAX_EVIDENCE_BYTES:
                raise TransportEvidenceBrokerError("operation evidence read is incomplete")
            return bytes(content)
        except TransportEvidenceBrokerError:
            raise
        except OSError as exc:
            raise TransportEvidenceBrokerError("operation evidence is unavailable") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _trusted_open_file(descriptor: int, *, allow_empty: bool) -> bool:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            return False
        if not allow_empty and metadata.st_size == 0:
            return False
        return os.name != "posix" or (
            metadata.st_uid in {0, os.getuid()} and not stat.S_IMODE(metadata.st_mode) & 0o077
        )

    @classmethod
    def _trusted_file(cls, path: Path) -> bool:
        try:
            descriptor = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
        except OSError:
            return False
        try:
            return cls._trusted_open_file(descriptor, allow_empty=False)
        finally:
            os.close(descriptor)


TransportEvidenceBroker = TrustedOperationEvidenceBroker

__all__ = [
    "TransportEvidenceBroker",
    "TransportEvidenceBrokerError",
    "TrustedOperationEvidenceBroker",
]
