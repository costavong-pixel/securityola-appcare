"""Mandatory application capability registry for Spec 013."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass

from .contracts import (
    CapabilityEvidence,
    EvidenceClass,
    ReadinessValidationError,
    validate_scope_segment,
)

MANDATORY_CAPABILITIES = (
    "connect",
    "inventory",
    "source_revision",
    "filesystem_backup",
    "database_backup",
    "offsite_backup",
    "remote_readback",
    "isolated_restore",
    "security_scan",
    "test_discovery",
    "staging",
    "remediation",
    "deploy",
    "production_verify",
    "database_migration_safety",
    "rollback",
    "monitoring",
    "scheduler",
    "alerting",
    "reporting",
    "credential_rotation",
    "offboarding",
)


@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
    """A capability required by a supported stack."""

    name: str
    minimum_evidence_class: EvidenceClass = EvidenceClass.FIXTURE
    mandatory: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", validate_scope_segment(self.name, field_name="capability"))
        if not isinstance(self.minimum_evidence_class, EvidenceClass):
            try:
                object.__setattr__(
                    self,
                    "minimum_evidence_class",
                    EvidenceClass(str(self.minimum_evidence_class).strip().casefold()),
                )
            except ValueError as exc:
                raise ReadinessValidationError("minimum evidence class is invalid") from exc
        if not isinstance(self.mandatory, bool):
            raise ReadinessValidationError("mandatory flag is invalid")


DEFAULT_CAPABILITY_DEFINITIONS = tuple(
    CapabilityDefinition(name=name) for name in MANDATORY_CAPABILITIES
)


class CapabilityRegistry:
    """Immutable registry of the mandatory capabilities for one stack family."""

    def __init__(
        self,
        definitions: Iterable[CapabilityDefinition] = DEFAULT_CAPABILITY_DEFINITIONS,
    ) -> None:
        normalized = tuple(definitions)
        if not normalized:
            raise ReadinessValidationError("capability registry cannot be empty")
        names = tuple(item.name for item in normalized)
        if len(names) != len(set(names)):
            raise ReadinessValidationError("capability registry contains duplicate names")
        if not all(item.mandatory for item in normalized):
            raise ReadinessValidationError("Spec 013 registry cannot weaken mandatory capabilities")
        self._definitions = tuple(sorted(normalized, key=lambda item: item.name))
        self._by_name = {item.name: item for item in self._definitions}

    @property
    def definitions(self) -> tuple[CapabilityDefinition, ...]:
        return self._definitions

    @property
    def mandatory_capabilities(self) -> tuple[str, ...]:
        return tuple(item.name for item in self._definitions)

    def contains(self, capability: str) -> bool:
        return capability.strip().casefold() in self._by_name

    def definition(self, capability: str) -> CapabilityDefinition:
        normalized = validate_scope_segment(capability, field_name="capability")
        try:
            return self._by_name[normalized]
        except KeyError as exc:
            raise ReadinessValidationError("capability is not registered") from exc

    def required_for(self, stack_id: str) -> tuple[CapabilityDefinition, ...]:
        """Return the same mandatory matrix for a validated stack scope."""

        validate_scope_segment(stack_id, field_name="stack_id")
        return self._definitions

    def mandatory_digest(self, stack_id: str) -> str:
        payload = {
            "stack_id": validate_scope_segment(stack_id, field_name="stack_id"),
            "capabilities": [
                {"name": item.name, "minimum_evidence_class": item.minimum_evidence_class.value}
                for item in self._definitions
            ],
        }
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class ApplicationCapabilityRegistry:
    """Scope-bound evidence collection for one tenant/application/stack."""

    def __init__(
        self,
        *,
        tenant_id: str,
        application_id: str,
        stack_id: str,
        registry: CapabilityRegistry | None = None,
    ) -> None:
        self.tenant_id = validate_scope_segment(tenant_id, field_name="tenant_id")
        self.application_id = validate_scope_segment(application_id, field_name="application_id")
        self.stack_id = validate_scope_segment(stack_id, field_name="stack_id")
        self.registry = registry or CapabilityRegistry()
        self._evidence: dict[str, CapabilityEvidence] = {}

    def add(self, evidence: CapabilityEvidence) -> CapabilityEvidence:
        if (
            evidence.tenant_id != self.tenant_id
            or evidence.application_id != self.application_id
            or evidence.stack_id != self.stack_id
        ):
            raise ReadinessValidationError("capability evidence crosses application scope")
        self.registry.definition(evidence.capability)
        if evidence.capability in self._evidence:
            raise ReadinessValidationError("capability evidence is duplicated")
        self._evidence[evidence.capability] = evidence
        return evidence

    def evidence(self) -> tuple[CapabilityEvidence, ...]:
        return tuple(self._evidence[name] for name in sorted(self._evidence))

    def missing(self) -> tuple[str, ...]:
        return tuple(
            name for name in self.registry.mandatory_capabilities if name not in self._evidence
        )


def default_capability_registry() -> CapabilityRegistry:
    return CapabilityRegistry()


__all__ = [
    "ApplicationCapabilityRegistry",
    "CapabilityDefinition",
    "CapabilityRegistry",
    "DEFAULT_CAPABILITY_DEFINITIONS",
    "MANDATORY_CAPABILITIES",
    "default_capability_registry",
]
