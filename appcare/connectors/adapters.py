"""Provider adapters that only build fixed GET descriptors and safe observations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ..routes.common import safe_reference
from ..services.audit import contains_credential_like
from .contracts import (
    CheckResult,
    CredentialContext,
    NormalizedConnectorResult,
    ProviderAssetObservation,
    ProviderName,
    ReadOnlyRequest,
    ReadOnlyTransport,
    RequestOperation,
)
from .profiles import PROVIDER_PROFILES, ProviderProfile, validate_scopes
from .transport import ProviderTransportError, UnavailableTransport


def _safe_provider_reference(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("provider reference is unsafe")
    normalized = value.strip()
    if not normalized or len(normalized) > 500 or not safe_reference(normalized):
        raise ValueError("provider reference is unsafe")
    if "://" in normalized or any(
        character.isspace() or character in "?#%\\" for character in normalized
    ):
        raise ValueError("provider reference is unsafe")
    return normalized


def _safe_text(value: object, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError("provider observation is malformed")
    result = value.strip()
    if (
        not result
        or len(result) > maximum
        or not safe_reference(result)
        or contains_credential_like(result)
    ):
        raise ValueError("provider observation is unsafe")
    return result


def _boolean(payload: Mapping[str, object], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise ValueError("provider check evidence is malformed")
    return value


def _string(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError("provider check evidence is malformed")
    return value


def _check(payload: Mapping[str, object], *, reason: str) -> CheckResult:
    try:
        ok = _boolean(payload, "ok")
    except ValueError:
        return CheckResult("failed", "provider_evidence_malformed", {"ok": False})
    return CheckResult(
        "passed" if ok else "failed",
        None if ok else reason,
        {"ok": ok},
    )


def _ownership(
    payload: Mapping[str, object], *, resource_reference: str, owner_reference: str
) -> CheckResult:
    try:
        provider_resource = _safe_provider_reference(_string(payload, "resource_reference"))
        provider_owner = _safe_provider_reference(_string(payload, "owner_reference"))
        credential_owner = _safe_provider_reference(_string(payload, "credential_owner_reference"))
    except ValueError:
        return CheckResult("failed", "ownership_evidence_malformed", {"matched": False})
    matched = (
        provider_resource.casefold() == resource_reference.casefold()
        and provider_owner.casefold() == owner_reference.casefold()
        and credential_owner.casefold() == owner_reference.casefold()
        and credential_owner.casefold() == provider_owner.casefold()
    )
    return CheckResult(
        "passed" if matched else "failed",
        None if matched else "ownership_mismatch",
        {"matched": matched},
    )


def _assets(payload: Mapping[str, object]) -> tuple[ProviderAssetObservation, ...]:
    raw_assets = payload.get("assets")
    if not isinstance(raw_assets, list):
        raise ValueError("provider inventory is malformed")
    observations: list[ProviderAssetObservation] = []
    for raw in raw_assets:
        if not isinstance(raw, Mapping):
            raise ValueError("provider inventory is malformed")
        provider_reference = _safe_provider_reference(raw.get("provider_reference"))
        kind = _safe_text(raw.get("kind"), maximum=100)
        display_name = _safe_text(raw.get("display_name"), maximum=200)
        locator = _safe_text(raw.get("locator"), maximum=500)
        raw_metadata = raw.get("metadata", {})
        if not isinstance(raw_metadata, Mapping):
            raise ValueError("provider inventory metadata is malformed")
        allowed_metadata: dict[str, object] = {}
        for key in ("environment", "status", "region", "framework"):
            value = raw_metadata.get(key)
            if value is None:
                continue
            allowed_metadata[key] = _safe_text(value, maximum=100)
        observations.append(
            ProviderAssetObservation(
                provider_reference=provider_reference,
                kind=kind,
                display_name=display_name,
                locator=locator,
                metadata=allowed_metadata,
            )
        )
    return tuple(observations)


@dataclass(frozen=True, slots=True)
class ProviderAdapter:
    provider: ProviderName
    profile: ProviderProfile
    paths: Mapping[RequestOperation, str]

    def build_requests(self, resource_reference: str) -> tuple[ReadOnlyRequest, ...]:
        reference = _safe_provider_reference(resource_reference)
        return tuple(
            ReadOnlyRequest(
                provider=self.provider,
                operation=operation,
                path=path.replace("{reference}", reference),
            )
            for operation, path in self.paths.items()
        )

    def normalize(
        self,
        payloads: Mapping[RequestOperation, Mapping[str, object]],
        *,
        resource_reference: str,
        owner_reference: str,
        configured_scopes: Sequence[str],
    ) -> NormalizedConnectorResult:
        try:
            scopes = validate_scopes(self.provider, configured_scopes)
            declared = payloads["permissions"].get("scopes")
            if not isinstance(declared, list) or any(
                not isinstance(item, str) for item in declared
            ):
                raise ValueError("permission evidence is malformed")
            provider_scopes = validate_scopes(self.provider, declared)
            permissions = CheckResult(
                "passed" if set(scopes).issubset(provider_scopes) else "failed",
                None if set(scopes).issubset(provider_scopes) else "insufficient_scope",
                {"scopes": list(provider_scopes)},
            )
        except (KeyError, ValueError):
            permissions = CheckResult("failed", "permission_evidence_malformed", {"scopes": []})
        try:
            health = _check(payloads["health"], reason="provider_health_failed")
        except KeyError:
            health = CheckResult("failed", "provider_evidence_missing", {"ok": False})
        try:
            ownership = _ownership(
                payloads["ownership"],
                resource_reference=resource_reference,
                owner_reference=owner_reference,
            )
        except KeyError:
            ownership = CheckResult("failed", "ownership_evidence_missing", {"matched": False})
        inventory_valid = True
        inventory_reason: str | None = None
        try:
            assets = _assets(payloads["inventory"])
        except (KeyError, ValueError):
            assets = ()
            inventory_valid = False
            inventory_reason = "inventory_evidence_malformed"
        return NormalizedConnectorResult(
            health,
            permissions,
            ownership,
            assets,
            inventory_valid,
            inventory_reason,
        )


GITHUB_ADAPTER = ProviderAdapter(
    "github",
    PROVIDER_PROFILES["github"],
    {
        "health": "/installation",
        "permissions": "/installation/repositories",
        "ownership": "/repos/{reference}",
        "inventory": "/installation/repositories",
    },
)
VERCEL_ADAPTER = ProviderAdapter(
    "vercel",
    PROVIDER_PROFILES["vercel"],
    {
        "health": "/v2/user",
        "permissions": "/v9/projects/{reference}",
        "ownership": "/v9/projects/{reference}",
        "inventory": "/v9/projects/{reference}",
    },
)
SUPABASE_ADAPTER = ProviderAdapter(
    "supabase",
    PROVIDER_PROFILES["supabase"],
    {
        "health": "/v1/projects/{reference}",
        "permissions": "/v1/projects/{reference}",
        "ownership": "/v1/projects/{reference}",
        "inventory": "/v1/projects/{reference}",
    },
)


class ConnectorRegistry:
    """Registry of fixed adapters and one injected transport."""

    def __init__(
        self,
        *,
        transport: ReadOnlyTransport | None = None,
        adapters: Mapping[ProviderName, ProviderAdapter] | None = None,
    ) -> None:
        self.transport = transport or UnavailableTransport()
        default_adapters: dict[ProviderName, ProviderAdapter] = {
            "github": GITHUB_ADAPTER,
            "vercel": VERCEL_ADAPTER,
            "supabase": SUPABASE_ADAPTER,
        }
        self.adapters: Mapping[ProviderName, ProviderAdapter] = adapters or default_adapters

    def adapter(self, provider: str) -> ProviderAdapter:
        if provider not in PROVIDER_PROFILES:
            raise ValueError("unsupported connector provider")
        return self.adapters[provider]

    def collect(
        self, provider: str, credential: CredentialContext, resource_reference: str
    ) -> Mapping[RequestOperation, Mapping[str, object]]:
        adapter = self.adapter(provider)
        payloads: dict[RequestOperation, Mapping[str, object]] = {}
        for request in adapter.build_requests(resource_reference):
            try:
                payloads[request.operation] = self.transport.request(request, credential)
            except ProviderTransportError:
                raise
            except Exception as exc:
                raise ProviderTransportError("provider_transport_failed") from exc
        return payloads


class FixtureTransport:
    """Deterministic test transport keyed by provider and operation."""

    def __init__(
        self, fixtures: Mapping[tuple[ProviderName, RequestOperation], Mapping[str, object]]
    ) -> None:
        self.fixtures = dict(fixtures)
        self.requests: list[ReadOnlyRequest] = []

    def request(
        self, request: ReadOnlyRequest, _credential: CredentialContext
    ) -> Mapping[str, object]:
        self.requests.append(request)
        try:
            return self.fixtures[(request.provider, request.operation)]
        except KeyError as exc:
            raise ProviderTransportError("fixture_missing") from exc
