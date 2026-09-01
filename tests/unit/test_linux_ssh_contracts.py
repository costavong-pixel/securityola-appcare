from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from appcare.connectors.linux_ssh_contracts import (
    BoundedLimits,
    CredentialBoundaryError,
    CredentialStatus,
    LinuxCredentialMetadata,
    LinuxCredentialRegistry,
    LinuxTarget,
    OperationRejected,
    SqliteOperationLedger,
    TargetValidationError,
    join_approved_path,
    parse_host_key_line,
    validate_fingerprint,
    validate_relative_path,
)


def _fingerprint() -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(b"host-key").digest()).decode().rstrip("=")


def _target(**changes: object) -> LinuxTarget:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "application_id": "application-a",
        "environment": "production",
        "host": "192.0.2.10",
        "expected_hostname": "app-a.internal",
        "ssh_port": 22,
        "expected_host_key_fingerprint": _fingerprint(),
        "credential_reference": "vault://appcare/linux-a",
        "remote_user": "appcare",
        "approved_application_roots": ("/srv/app",),
        "approved_service_names": ("app.service",),
        "approved_database_identifiers": ("postgresql",),
        "target_reference": "target-a",
    }
    values.update(changes)
    return LinuxTarget(**cast(Any, values))


def test_linux_target_normalizes_identity_and_rejects_root() -> None:
    target = _target(host="192.0.2.10", expected_hostname="App-A.Internal")
    assert target.expected_hostname == "app-a.internal"
    with pytest.raises(TargetValidationError):
        _target(remote_user="root")


@pytest.mark.parametrize(
    "value",
    [
        "",
        "..",
        "../etc",
        "/etc/shadow",
        "app/../../secret",
        "app\\secret",
        "app%2fsecret",
        ".env",
        "private/key",
    ],
)
def test_relative_paths_are_fail_closed(value: str) -> None:
    with pytest.raises(OperationRejected):
        validate_relative_path(value)


def test_joined_path_stays_under_approved_root() -> None:
    assert join_approved_path("/srv/app", "config/settings.json") == "/srv/app/config/settings.json"
    with pytest.raises(OperationRejected):
        join_approved_path("/srv/app", "../outside")


def test_fingerprint_is_canonical_and_derived_from_key_blob() -> None:
    line = "app-a ssh-ed25519 " + base64.b64encode(b"host-key").decode()
    parsed = parse_host_key_line(line)
    assert parsed.fingerprint == _fingerprint()
    assert validate_fingerprint(parsed.fingerprint) == parsed.fingerprint
    with pytest.raises(ValueError):
        validate_fingerprint("SHA256:not-a-fingerprint")


def test_credential_lifecycle_is_metadata_only_and_scope_bound() -> None:
    now = datetime(2026, 8, 28, tzinfo=UTC)
    registry = LinuxCredentialRegistry()
    first = LinuxCredentialMetadata(
        credential_reference="vault://appcare/linux-a",
        tenant_id="tenant-a",
        application_id="application-a",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    registry.register(first)
    assert (
        registry.get(
            tenant_id="tenant-a",
            application_id="application-a",
            credential_reference=first.credential_reference,
        ).status(now)
        == CredentialStatus.ACTIVE
    )
    revoked = registry.revoke(
        tenant_id="tenant-a",
        application_id="application-a",
        credential_reference=first.credential_reference,
        now=now,
    )
    assert revoked.status(now) == CredentialStatus.REVOKED
    replacement = LinuxCredentialMetadata(
        credential_reference="vault://appcare/linux-a-v2",
        tenant_id="tenant-a",
        application_id="application-a",
        version=2,
        issued_at=now,
    )
    registry.rotate(
        tenant_id="tenant-a",
        application_id="application-a",
        old_credential_reference=first.credential_reference,
        replacement=replacement,
        now=now,
    )
    with pytest.raises(CredentialBoundaryError):
        registry.get(
            tenant_id="tenant-b",
            application_id="application-a",
            credential_reference=replacement.credential_reference,
        )


def test_limits_reject_unbounded_values() -> None:
    with pytest.raises(OperationRejected):
        BoundedLimits(max_stdout_bytes=0)
    with pytest.raises(OperationRejected):
        BoundedLimits(command_timeout_seconds=121)


def test_sqlite_operation_ledger_is_atomic_and_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "operation-ledger.db"
    ledger = SqliteOperationLedger(path)
    assert ledger.durable
    assert ledger.claim(target_reference="target-a", operation_id="operation-a")
    assert not ledger.claim(target_reference="target-a", operation_id="operation-a")

    reopened = SqliteOperationLedger(path)
    assert not reopened.claim(target_reference="target-a", operation_id="operation-a")
    assert reopened.claim(target_reference="target-b", operation_id="operation-a")
