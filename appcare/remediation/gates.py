"""Bounded regression and security gate orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .contracts import (
    GateKind,
    GateResult,
    GateStatus,
    PatchCandidate,
    RemediationBoundaryError,
    RemediationWorkspace,
    evidence_digest,
)


class GateAdapter(Protocol):
    """A deterministic, bounded test adapter."""

    @property
    def kind(self) -> GateKind:
        """Identify the gate without permitting callers to mutate it."""
        ...

    def run(self, patch: PatchCandidate, workspace: RemediationWorkspace) -> GateResult:
        """Return a sanitized result; never receive credentials."""


@dataclass(frozen=True, slots=True)
class GateSummary:
    """Combined result used to decide preview readiness."""

    status: str
    results: tuple[GateResult, ...]
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        results = tuple(self.results)
        if self.status not in {"passed", "blocked"}:
            raise RemediationBoundaryError("gate summary status is unsupported")
        if len(results) != 2 or {result.kind for result in results} != {"regression", "security"}:
            raise RemediationBoundaryError("gate summary must contain both required gates")
        refs = tuple(result.evidence_ref for result in results)
        if tuple(self.evidence_refs) != refs:
            raise RemediationBoundaryError("gate summary evidence does not match results")
        if self.status == "passed" and any(result.status != "passed" for result in results):
            raise RemediationBoundaryError("passed gate summary contains a failed gate")
        object.__setattr__(self, "results", results)
        object.__setattr__(self, "evidence_refs", refs)

    @property
    def promotion_ready(self) -> bool:
        return self.status == "passed" and all(result.status == "passed" for result in self.results)


def _fallback_result(
    patch: PatchCandidate,
    *,
    kind: GateKind,
    status: GateStatus,
    code: str,
    attempts: int,
) -> GateResult:
    return GateResult(
        kind=kind,
        status=status,
        code=code,
        evidence_ref=evidence_digest("gate", patch.patch_id, kind, status, code),
        attempts=attempts,
    )


class GateRunner:
    """Run exactly the bounded regression and security gates."""

    def __init__(self, *, max_attempts: int = 1) -> None:
        if max_attempts < 1 or max_attempts > 3:
            raise ValueError("max_attempts must be between 1 and 3")
        self.max_attempts = max_attempts

    def run(
        self,
        patch: PatchCandidate,
        workspace: RemediationWorkspace,
        adapters: tuple[GateAdapter, ...],
    ) -> GateSummary:
        if len(adapters) != 2 or {adapter.kind for adapter in adapters} != {
            "regression",
            "security",
        }:
            raise ValueError("exactly one regression and one security gate are required")
        results: list[GateResult] = []
        for adapter in adapters:
            result: GateResult | None = None
            for attempt in range(1, self.max_attempts + 1):
                try:
                    candidate = adapter.run(patch, workspace)
                    if candidate.kind != adapter.kind:
                        result = _fallback_result(
                            patch,
                            kind=adapter.kind,
                            status="blocked",
                            code="gate_kind_mismatch",
                            attempts=attempt,
                        )
                    else:
                        result = candidate
                except TimeoutError:
                    result = _fallback_result(
                        patch,
                        kind=adapter.kind,
                        status="unavailable",
                        code="gate_timeout",
                        attempts=attempt,
                    )
                except Exception:
                    result = _fallback_result(
                        patch,
                        kind=adapter.kind,
                        status="unavailable",
                        code="gate_execution_failed",
                        attempts=attempt,
                    )
                if result.status == "passed":
                    break
            if result is None:
                result = _fallback_result(
                    patch,
                    kind=adapter.kind,
                    status="unavailable",
                    code="gate_no_result",
                    attempts=self.max_attempts,
                )
            results.append(result)
        ordered = tuple(sorted(results, key=lambda item: item.kind))
        status = "passed" if all(result.status == "passed" for result in ordered) else "blocked"
        return GateSummary(
            status=status,
            results=ordered,
            evidence_refs=tuple(result.evidence_ref for result in ordered),
        )


__all__ = ["GateAdapter", "GateRunner", "GateSummary"]
