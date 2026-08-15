"""Small, provider-neutral contracts for read-only connector execution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

ProviderName = Literal["github", "vercel", "supabase"]
RequestOperation = Literal["health", "permissions", "ownership", "inventory"]
CheckStatus = Literal["passed", "failed", "unknown"]


@dataclass(frozen=True, slots=True)
class CredentialContext:
    """Non-secret credential metadata passed to a connector transport."""

    reference: str
    scopes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReadOnlyRequest:
    """A server-created provider request with no arbitrary method or host."""

    provider: ProviderName
    operation: RequestOperation
    path: str
    query: tuple[tuple[str, str], ...] = ()
    method: Literal["GET"] = "GET"

    def __post_init__(self) -> None:
        if self.method != "GET":
            raise ValueError("connector requests are GET-only")
        if (
            not self.path.startswith("/")
            or "://" in self.path
            or ".." in self.path
            or any(character in "?#%\\" for character in self.path)
        ):
            raise ValueError("connector request path is not safe")
        if any(ord(character) < 32 for character in self.path):
            raise ValueError("connector request path contains control characters")
        for key, value in self.query:
            if (
                not key
                or any(ord(character) < 32 for character in key + value)
                or any(character in "?#%\\" for character in key + value)
            ):
                raise ValueError("connector query contains unsafe characters")


@dataclass(frozen=True, slots=True)
class CheckResult:
    status: CheckStatus
    reason_code: str | None
    evidence: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class ProviderAssetObservation:
    provider_reference: str
    kind: str
    display_name: str
    locator: str
    metadata: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class NormalizedConnectorResult:
    health: CheckResult
    permissions: CheckResult
    ownership: CheckResult
    assets: tuple[ProviderAssetObservation, ...]
    inventory_valid: bool = True
    inventory_reason: str | None = None


class ConnectorAdapter(Protocol):
    provider: ProviderName

    def build_requests(self, resource_reference: str) -> tuple[ReadOnlyRequest, ...]:
        """Build the fixed health/permission/ownership/inventory GET descriptors."""

    def normalize(
        self,
        payloads: Mapping[RequestOperation, Mapping[str, object]],
        *,
        resource_reference: str,
        owner_reference: str,
        configured_scopes: Sequence[str],
    ) -> NormalizedConnectorResult:
        """Normalize provider-shaped data without returning raw provider payloads."""


class ReadOnlyTransport(Protocol):
    def request(
        self, request: ReadOnlyRequest, credential: CredentialContext
    ) -> Mapping[str, object]:
        """Execute one approved GET request without receiving a credential value."""
