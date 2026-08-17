"""Provider-neutral, fail-closed backup and isolated-restore primitives."""

from .contracts import (
    BackupDestination,
    BackupSource,
    BackupTarget,
    BackupVault,
    EnvelopeEncryptor,
    RestoreTarget,
)
from .crypto import AesGcmEnvelopeEncryptor, EnvelopeEncryptionError
from .models import (
    BackupArtifact,
    BackupComponent,
    BackupJobEvent,
    BackupManifest,
    BackupOutcome,
    BackupRequest,
    EncryptedEnvelope,
    RestoreEvidence,
    VaultReceipt,
)
from .pipeline import BackupCoordinator, BackupError
from .stores import (
    FilesystemImmutableVault,
    InMemoryImmutableVault,
    RetentionLockedError,
    UnavailableCloudVault,
    VaultError,
)

__all__ = [
    "AesGcmEnvelopeEncryptor",
    "BackupArtifact",
    "BackupComponent",
    "BackupCoordinator",
    "BackupDestination",
    "BackupError",
    "BackupJobEvent",
    "BackupManifest",
    "BackupOutcome",
    "BackupRequest",
    "BackupSource",
    "BackupTarget",
    "BackupVault",
    "EncryptedEnvelope",
    "EnvelopeEncryptor",
    "EnvelopeEncryptionError",
    "InMemoryImmutableVault",
    "FilesystemImmutableVault",
    "RestoreEvidence",
    "RestoreTarget",
    "RetentionLockedError",
    "UnavailableCloudVault",
    "VaultError",
    "VaultReceipt",
]
