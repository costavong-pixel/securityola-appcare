from __future__ import annotations

import base64
import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
        "remote_user": "appcare",
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
    assert identity.is_file()
    if os.name == "posix":
        assert identity.stat().st_mode & 0o077 == 0
    provider.release(resolved)
    assert not identity.exists()

    with pytest.raises(CredentialVaultError, match="scope"):
        provider.resolve(_target(record, target_reference="other-target"))
    with pytest.raises(CredentialVaultError, match="scope"):
        provider.resolve(_target(record, tenant_id="tenant-b"))


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

    resolved = provider.resolve(_target(replacement))
    provider.release(resolved)
    receipt = vault.offboard(replacement.credential_reference)
    assert receipt.revoked
    assert receipt.encrypted_blob_removed
    assert not receipt.old_key_usable
    assert receipt.audit_recorded
    assert vault.get(replacement.credential_reference).status() == VaultCredentialStatus.DESTROYED
    with pytest.raises(CredentialVaultError, match="not active"):
        provider.resolve(_target(replacement))


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
    assert plan.complete
    assert "private" not in repr(plan.to_public_dict()).casefold()

    with pytest.raises(ValueError, match="non-root"):
        keys.manual_onboarding(record.credential_reference, remote_user="root")


def test_file_master_key_provider_requires_exact_32_bytes(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    path.write_bytes(b"k" * 32)
    if os.name == "posix":
        path.chmod(0o600)
    assert FileMasterKeyProvider(path).load_key() == b"k" * 32

    path.write_bytes(b"too-short")
    with pytest.raises(CredentialVaultError, match="invalid"):
        FileMasterKeyProvider(path).load_key()
