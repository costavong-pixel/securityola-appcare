"""Metadata-only credential lifecycle for read-only provider connectors."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime

from ..repositories.tenant_scope import valid_public_id
from .providers import ProviderConfigurationError, canonical_capabilities
from .types import CredentialMetadata

_REFERENCE = re.compile(
    r"^(?:vault|secret|appcare-secret)://[a-z0-9][a-z0-9._/-]{2,240}$|"
    r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$",
    re.IGNORECASE,
)
_SECRET_SHAPED_REFERENCE = re.compile(
    r"(?:bearer|password|private[_-]?key|api[_-]?key|secret|token|ghp_|github_pat_)",
    re.IGNORECASE,
)


class CredentialLifecycleError(ValueError):
    """A credential metadata transition is invalid."""


def _validate_metadata(metadata: CredentialMetadata) -> CredentialMetadata:
    if not valid_public_id(metadata.tenant_id):
        raise CredentialLifecycleError("credential tenant is invalid")
    if not _REFERENCE.fullmatch(metadata.credential_id) or (
        "://" not in metadata.credential_id
        and _SECRET_SHAPED_REFERENCE.search(metadata.credential_id)
    ):
        raise CredentialLifecycleError("credential reference is invalid")
    if metadata.version < 1:
        raise CredentialLifecycleError("credential version is invalid")
    if not metadata.scopes or any(not scope.strip() for scope in metadata.scopes):
        raise CredentialLifecycleError("credential scopes are invalid")
    try:
        canonical_capabilities(metadata.provider, metadata.scopes)
    except (ProviderConfigurationError, ValueError) as exc:
        raise CredentialLifecycleError("credential scopes are invalid") from exc
    if metadata.issued_at.tzinfo is None:
        raise CredentialLifecycleError("credential issue time must be timezone-aware")
    if metadata.expires_at is not None and metadata.expires_at <= metadata.issued_at:
        raise CredentialLifecycleError("credential expiry is invalid")
    return metadata


class CredentialRegistry:
    """Store opaque credential metadata only; raw secrets are not accepted."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], CredentialMetadata] = {}

    def register(self, metadata: CredentialMetadata) -> CredentialMetadata:
        _validate_metadata(metadata)
        key = (metadata.tenant_id, metadata.credential_id)
        if key in self._records:
            raise CredentialLifecycleError("credential reference already exists")
        self._records[key] = metadata
        return metadata

    def get(self, *, tenant_id: str, credential_id: str) -> CredentialMetadata:
        try:
            return self._records[(tenant_id, credential_id)]
        except KeyError as exc:
            raise CredentialLifecycleError("credential reference is unavailable") from exc

    def revoke(
        self, *, tenant_id: str, credential_id: str, now: datetime | None = None
    ) -> CredentialMetadata:
        current = self.get(tenant_id=tenant_id, credential_id=credential_id)
        revoked = replace(current, revoked_at=now or datetime.now(UTC))
        self._records[(tenant_id, credential_id)] = revoked
        return revoked

    def rotate(
        self,
        *,
        tenant_id: str,
        old_credential_id: str,
        replacement: CredentialMetadata,
        now: datetime | None = None,
    ) -> CredentialMetadata:
        old = self.get(tenant_id=tenant_id, credential_id=old_credential_id)
        if replacement.tenant_id != tenant_id:
            raise CredentialLifecycleError("credential tenant cannot change during rotation")
        if old.provider != replacement.provider:
            raise CredentialLifecycleError("credential provider cannot change during rotation")
        if replacement.version <= old.version:
            raise CredentialLifecycleError("replacement credential version must increase")
        _validate_metadata(replacement)
        if (tenant_id, replacement.credential_id) in self._records:
            raise CredentialLifecycleError("credential reference already exists")
        self.revoke(tenant_id=tenant_id, credential_id=old_credential_id, now=now)
        return self.register(replacement)
