from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import appcare.connectors.credential_vault as credential_vault_module
from appcare.connectors import (
    BootstrapStep,
    CredentialVaultError,
    Ed25519KeyService,
    EncryptedCredentialVault,
    FileMasterKeyProvider,
    LinuxTarget,
    VaultCredentialProvider,
    VaultCredentialRecord,
    VaultCredentialStatus,
)


class TestMasterKeyProvider:
    def load_key(self) -> bytes:
        return b"m" * 32


def _private_key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )


def _target(record: VaultCredentialRecord, **changes: object) -> LinuxTarget:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "application_id": "application-a",
        "environment": "production",
        "host": "192.0.2.10",
        "expected_hostname": "app-a.internal",
        "ssh_port": 22,
        "expected_host_key_fingerprint": "SHA256:"
        + base64.b64encode(hashlib.sha256(b"host-key").digest()).decode().rstrip("="),
        "credential_reference": record.credential_reference,
        "remote_user": record.remote_user,
        "approved_application_roots": ("/srv/app",),
        "approved_service_names": ("app.service",),
        "approved_database_identifiers": ("mysql",),
        "target_reference": record.target_reference,
    }
    values.update(changes)
    return LinuxTarget(**cast(Any, values))


def _vault(tmp_path: Path) -> tuple[EncryptedCredentialVault, Ed25519KeyService]:
    vault = EncryptedCredentialVault(
        tmp_path / "credentials",
        master_key_provider=TestMasterKeyProvider(),
    )
    return vault, Ed25519KeyService(vault)


def test_generated_private_key_is_encrypted_and_metadata_is_public_safe(tmp_path: Path) -> None:
    vault, keys = _vault(tmp_path)
    record = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
        now=datetime(2026, 9, 1, tzinfo=UTC),
    )

    metadata = next((vault.root / "records").glob("*.json")).read_bytes()
    encrypted_blob = next((vault.root / "blobs").glob("*.bin")).read_bytes()
    assert b"BEGIN OPENSSH PRIVATE KEY" not in metadata
    assert b"BEGIN OPENSSH PRIVATE KEY" not in encrypted_blob
    assert record.public_key.startswith("ssh-ed25519 ")
    assert record.fingerprint.startswith("SHA256:")
    assert vault.get(record.credential_reference) == record
    assert record.status() == VaultCredentialStatus.ACTIVE


@pytest.mark.skipif(os.name != "posix", reason="SSH runtime identity paths are POSIX-only")
def test_runtime_resolution_is_scoped_and_release_removes_ephemeral_identity(
    tmp_path: Path,
) -> None:
    vault, keys = _vault(tmp_path)
    record = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    provider = VaultCredentialProvider(vault)
    resolved = provider.resolve(_target(record))
    identity = Path(resolved.identity_file)
    lease = identity.with_suffix(".lease")
    assert identity.is_file()
    assert lease.is_file()
    if os.name == "posix":
        assert identity.stat().st_mode & 0o077 == 0
    provider.release(resolved)
    assert not identity.exists()
    assert not lease.exists()

    with pytest.raises(CredentialVaultError, match="scope"):
        provider.resolve(_target(record, target_reference="other-target"))
    with pytest.raises(CredentialVaultError, match="scope"):
        provider.resolve(_target(record, tenant_id="tenant-b"))
    with pytest.raises(CredentialVaultError, match="scope"):
        provider.resolve(_target(record, remote_user="other-user"))


@pytest.mark.skipif(os.name != "posix", reason="SSH runtime identity paths are POSIX-only")
def test_rotation_revocation_and_offboarding_fail_closed(tmp_path: Path) -> None:
    vault, keys = _vault(tmp_path)
    first = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    replacement = vault.rotate(
        first.credential_reference,
        private_key=_private_key(),
        now=datetime.now(UTC) + timedelta(minutes=1),
    )
    assert replacement.version == 2
    assert vault.get(first.credential_reference).status() == VaultCredentialStatus.REVOKED
    provider = VaultCredentialProvider(vault)
    with pytest.raises(CredentialVaultError, match="not active"):
        provider.resolve(_target(first))

    stale_runtime_identity = Path(provider.resolve(_target(replacement)).identity_file)
    receipt = vault.offboard(
        replacement.credential_reference,
        now=datetime.now(UTC) + timedelta(minutes=2),
    )
    assert receipt.revoked
    assert receipt.encrypted_blob_removed
    assert receipt.runtime_files_removed
    assert receipt.local_private_material_removed
    assert receipt.old_key_usable
    assert not receipt.remote_authorization_revoked
    assert receipt.audit_recorded
    assert not stale_runtime_identity.exists()
    assert vault.get(replacement.credential_reference).status() == VaultCredentialStatus.DESTROYED
    with pytest.raises(CredentialVaultError, match="not active"):
        provider.resolve(_target(replacement))


def test_rotation_journal_recovers_after_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault, keys = _vault(tmp_path)
    first = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    persist = vault._persist_record_unlocked

    def fail_for_replacement(record: VaultCredentialRecord) -> None:
        if record.version == 2:
            raise RuntimeError("simulated interruption")
        persist(record)

    monkeypatch.setattr(vault, "_persist_record_unlocked", fail_for_replacement)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        vault.rotate(
            first.credential_reference,
            private_key=_private_key(),
            now=datetime.now(UTC) + timedelta(minutes=1),
        )
    journal = json.loads(next((vault.root / "rotations").glob("*.json")).read_text())
    replacement_reference = journal["replacement_record"]["credential_reference"]
    monkeypatch.undo()

    assert vault.get(first.credential_reference).status() == VaultCredentialStatus.REVOKED
    assert vault.get(replacement_reference).status() == VaultCredentialStatus.ACTIVE
    assert not any((vault.root / "rotations").iterdir())


def test_rotation_publishes_replacement_before_revoking_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault, keys = _vault(tmp_path)
    first = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    persist = vault._persist_record_unlocked
    writes: list[tuple[int, VaultCredentialStatus]] = []

    def track(record: VaultCredentialRecord) -> None:
        writes.append((record.version, record.status()))
        persist(record)

    monkeypatch.setattr(vault, "_persist_record_unlocked", track)
    replacement = vault.rotate(
        first.credential_reference,
        private_key=_private_key(),
        now=datetime.now(UTC) + timedelta(minutes=1),
    )

    assert replacement.version == 2
    assert writes == [
        (2, VaultCredentialStatus.ACTIVE),
        (1, VaultCredentialStatus.REVOKED),
    ]


@pytest.mark.skipif(os.name != "posix", reason="SSH runtime identity paths are POSIX-only")
def test_startup_reclaims_runtime_material_from_dead_process_lease(tmp_path: Path) -> None:
    vault, keys = _vault(tmp_path)
    record = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    resolved = VaultCredentialProvider(vault).resolve(_target(record))
    identity = Path(resolved.identity_file)
    lease = identity.with_suffix(".lease")
    lease_data = json.loads(lease.read_text())
    lease_data["pid"] = os.getpid()
    lease_data["process_start_time"] = "0"
    lease.write_text(json.dumps(lease_data, sort_keys=True, separators=(",", ":")))
    lease.chmod(0o600)

    EncryptedCredentialVault(
        vault.root,
        master_key_provider=TestMasterKeyProvider(),
    )

    assert not identity.exists()
    assert not lease.exists()


def test_offboarding_retries_missing_audit_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, keys = _vault(tmp_path)
    record = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    append = vault._append_audit_unlocked

    def fail_once(
        event: str, value: VaultCredentialRecord, *, operation_id: str | None = None
    ) -> None:
        if event == "offboarded":
            raise RuntimeError("simulated audit interruption")
        append(event, value, operation_id=operation_id)

    monkeypatch.setattr(vault, "_append_audit_unlocked", fail_once)
    with pytest.raises(RuntimeError, match="simulated audit interruption"):
        vault.offboard(record.credential_reference, now=datetime.now(UTC) + timedelta(minutes=1))
    monkeypatch.undo()

    receipt = vault.offboard(record.credential_reference)
    assert receipt.audit_recorded
    assert receipt.local_private_material_removed


def test_runtime_entry_retry_refsyncs_when_entry_is_already_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, keys = _vault(tmp_path)
    record = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    scope = (
        vault.root
        / "runtime"
        / hashlib.sha256(record.credential_reference.encode("utf-8")).hexdigest()
    )
    scope.mkdir()
    runtime_entry = scope / ("a" * 32 + ".key")
    original_fsync = credential_vault_module._fsync_directory
    calls: list[Path] = []
    fail_once = True

    def fsync_with_one_injected_failure(path: Path) -> None:
        nonlocal fail_once
        calls.append(path)
        if path == scope and fail_once:
            fail_once = False
            raise OSError("simulated directory fsync failure")
        original_fsync(path)

    monkeypatch.setattr(
        credential_vault_module,
        "_fsync_directory",
        fsync_with_one_injected_failure,
    )
    with pytest.raises(CredentialVaultError, match="directory durability"):
        vault._remove_runtime_entry_unlocked(runtime_entry)
    vault._remove_runtime_entry_unlocked(runtime_entry)
    assert calls.count(scope) == 2


def test_runtime_scope_retry_refsyncs_when_scope_is_already_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, keys = _vault(tmp_path)
    record = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    runtime_root = vault.root / "runtime"
    scope = vault._runtime_scope(record.credential_reference)
    original_fsync = credential_vault_module._fsync_directory
    calls: list[Path] = []
    fail_once = True

    def fsync_with_one_injected_failure(path: Path) -> None:
        nonlocal fail_once
        calls.append(path)
        if path == runtime_root and fail_once:
            fail_once = False
            raise OSError("simulated directory fsync failure")
        original_fsync(path)

    monkeypatch.setattr(
        credential_vault_module,
        "_fsync_directory",
        fsync_with_one_injected_failure,
    )
    scope.mkdir()
    scope.rmdir()
    with pytest.raises(CredentialVaultError, match="directory durability"):
        vault._remove_runtime_materializations_unlocked(record)
    vault._remove_runtime_materializations_unlocked(record)
    assert calls.count(runtime_root) == 2


def test_blob_cleanup_retry_refsyncs_when_blob_is_already_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, keys = _vault(tmp_path)
    record = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    blob_root = vault.root / "blobs"
    blob_path = vault._blob_path(record.credential_reference)
    blob_path.unlink()
    original_fsync = credential_vault_module._fsync_directory
    calls: list[Path] = []
    fail_once = True

    def fsync_with_one_injected_failure(path: Path) -> None:
        nonlocal fail_once
        calls.append(path)
        if path == blob_root and fail_once:
            fail_once = False
            raise OSError("simulated directory fsync failure")
        original_fsync(path)

    monkeypatch.setattr(
        credential_vault_module,
        "_fsync_directory",
        fsync_with_one_injected_failure,
    )
    with pytest.raises(CredentialVaultError, match="directory durability"):
        vault._remove_blob_unlocked(record)
    assert not vault._remove_blob_unlocked(record)
    assert calls.count(blob_root) == 2


def test_rotation_journal_retry_refsyncs_when_journal_is_already_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, _ = _vault(tmp_path)
    journal = vault.root / "rotations" / ("a" * 32 + ".json")
    rotations_root = vault.root / "rotations"
    original_fsync = credential_vault_module._fsync_directory
    calls: list[Path] = []
    fail_once = True

    def fsync_with_one_injected_failure(path: Path) -> None:
        nonlocal fail_once
        calls.append(path)
        if path == rotations_root and fail_once:
            fail_once = False
            raise OSError("simulated directory fsync failure")
        original_fsync(path)

    monkeypatch.setattr(
        credential_vault_module,
        "_fsync_directory",
        fsync_with_one_injected_failure,
    )
    with pytest.raises(CredentialVaultError, match="directory durability"):
        vault._remove_rotation_journal_unlocked(journal)
    vault._remove_rotation_journal_unlocked(journal)
    assert calls.count(rotations_root) == 2


def test_existing_audit_event_retry_refsyncs_after_directory_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, keys = _vault(tmp_path)
    record = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    audit_root = vault.root / "audit"
    operation_id = "a" * 32
    original_fsync = credential_vault_module._fsync_directory
    calls: list[Path] = []
    audit_fsync_count = 0

    def fsync_with_one_injected_failure(path: Path) -> None:
        nonlocal audit_fsync_count
        calls.append(path)
        if path == audit_root:
            audit_fsync_count += 1
        if path == audit_root and audit_fsync_count == 2:
            raise OSError("simulated directory fsync failure")
        original_fsync(path)

    monkeypatch.setattr(
        credential_vault_module,
        "_fsync_directory",
        fsync_with_one_injected_failure,
    )
    with pytest.raises(CredentialVaultError, match="audit record could not be written"):
        vault._append_audit_unlocked("offboarded", record, operation_id=operation_id)
    assert vault._audit_event_exists_unlocked("offboarded", record, operation_id=operation_id)
    assert calls.count(audit_root) == 3


def test_rotation_audit_replay_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, keys = _vault(tmp_path)
    record = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )

    def fail_once(path: Path) -> None:
        raise RuntimeError("simulated journal interruption")

    monkeypatch.setattr(vault, "_remove_rotation_journal_unlocked", fail_once)
    with pytest.raises(RuntimeError, match="simulated journal interruption"):
        vault.rotate(
            record.credential_reference,
            private_key=_private_key(),
            now=datetime.now(UTC) + timedelta(minutes=1),
        )
    monkeypatch.undo()
    vault.get(record.credential_reference)

    events = [
        json.loads(line)
        for line in (vault.root / "audit" / "events.jsonl").read_text().splitlines()
        if json.loads(line)["event"] == "rotated"
    ]
    assert len(events) == 1
    assert not any((vault.root / "rotations").iterdir())


def test_tampered_blob_and_non_ed25519_key_are_rejected(tmp_path: Path) -> None:
    vault, keys = _vault(tmp_path)
    record = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    blob_path = next((vault.root / "blobs").glob("*.bin"))
    tampered = bytearray(blob_path.read_bytes())
    tampered[-1] ^= 1
    blob_path.write_bytes(tampered)
    with pytest.raises(CredentialVaultError, match="authentication"):
        VaultCredentialProvider(vault).resolve(_target(record))


def test_manual_onboarding_and_bootstrap_are_public_only(tmp_path: Path) -> None:
    vault, keys = _vault(tmp_path)
    record = keys.generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    instructions = keys.manual_onboarding(record.credential_reference, remote_user="appcare")
    assert instructions.public_key == record.public_key
    assert instructions.authorized_keys_line.endswith(record.public_key)
    assert "PRIVATE KEY" not in repr(instructions)
    assert "BEGIN" not in instructions.instructions

    plan = keys.bootstrap_plan(
        record.credential_reference,
        remote_user="appcare",
        authorization_id="auth-001",
    )
    with pytest.raises(CredentialVaultError, match="out of order"):
        plan.advance(BootstrapStep.INSTALL_EXACT_PUBLIC_KEY)
    for step in (
        BootstrapStep.VERIFY_NON_ROOT_ACCOUNT,
        BootstrapStep.CREATE_SSH_DIRECTORY,
        BootstrapStep.INSTALL_EXACT_PUBLIC_KEY,
        BootstrapStep.APPLY_RESTRICTIONS,
        BootstrapStep.VERIFY_ACCESS,
        BootstrapStep.CLEANUP_AUTHORIZATION,
    ):
        plan = plan.advance(step)
    assert not plan.complete
    assert plan.ready_for_external_verification
    assert "private" not in repr(plan.to_public_dict()).casefold()

    with pytest.raises(CredentialVaultError, match="remote user"):
        keys.manual_onboarding(record.credential_reference, remote_user="other-user")
    with pytest.raises(ValueError, match="non-root"):
        keys.manual_onboarding(record.credential_reference, remote_user="root")


def test_file_master_key_provider_requires_exact_32_bytes(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    path.write_bytes(b"k" * 32)
    if os.name == "posix":
        path.chmod(0o600)
    assert FileMasterKeyProvider(path).load_key() == b"k" * 32

    if os.name == "posix":
        path.chmod(0o640)
        with pytest.raises(CredentialVaultError, match="permissions"):
            FileMasterKeyProvider(path).load_key()
        path.chmod(0o600)

    path.write_bytes(b"too-short")
    with pytest.raises(CredentialVaultError, match="invalid"):
        FileMasterKeyProvider(path).load_key()
