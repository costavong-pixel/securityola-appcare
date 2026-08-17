# BETA-04 Backup Contracts

```python
class BackupSource(Protocol):
    def snapshot(self, target: BackupTarget) -> tuple[BackupComponent, ...]: ...

class EnvelopeEncryptor(Protocol):
    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> EncryptedEnvelope: ...
    def decrypt(self, envelope: EncryptedEnvelope, *, associated_data: bytes) -> bytes: ...

class BackupVault(Protocol):
    def put(self, artifact: BackupArtifact, *, idempotency_key: str) -> VaultReceipt: ...
    def get(self, backup_id: str) -> BackupArtifact: ...
    def delete(self, backup_id: str, *, now: datetime) -> None: ...
```

The coordinator validates the target and destination before calling any source
or vault method. A healthy result requires vault receipt, artifact checksum,
decrypt success, and every component checksum. Restore validates all components
in a staging directory before atomic promotion.
