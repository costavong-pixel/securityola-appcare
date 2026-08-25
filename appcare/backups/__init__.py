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
from .paths import (
    B2_BACKUP_PREFIX,
    BACKUP_CONFIG_ROOT,
    BACKUP_LOG_ROOT,
    BACKUP_ROOT,
    BACKUP_TMP_ROOT,
    GLACIER_ARCHIVE_PREFIX,
    BackupFilesystemBoundary,
    validate_read_only_source,
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
    "BACKUP_CONFIG_ROOT",
    "BACKUP_LOG_ROOT",
    "BACKUP_ROOT",
    "BACKUP_TMP_ROOT",
    "B2_BACKUP_PREFIX",
    "GLACIER_ARCHIVE_PREFIX",
    "BackupFilesystemBoundary",
    "validate_read_only_source",
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
