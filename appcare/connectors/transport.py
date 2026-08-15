"""Deny-by-default transport implementations."""

from __future__ import annotations

from collections.abc import Mapping

from .contracts import CredentialContext, ReadOnlyRequest


class ProviderTransportError(RuntimeError):
    """A safe provider transport failure with a stable reason code."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class UnavailableTransport:
    """Default runtime transport; live provider access is not enabled in BETA-02."""

    def request(
        self, _request: ReadOnlyRequest, _credential: CredentialContext
    ) -> Mapping[str, object]:
        raise ProviderTransportError("provider_transport_unavailable")
