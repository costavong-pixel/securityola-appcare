"""Deterministic scan orchestration: validate, evidence, normalize, deduplicate."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace

from .canonical import (
    CanonicalizationError,
    build_evidence,
    finding_fingerprint,
    observation_payload,
)
from .contracts import ScannerAdapter
from .models import (
    ADAPTER_KINDS,
    AdapterKind,
    AdapterResult,
    EvidenceRecord,
    FailureCode,
    Finding,
    PipelineResult,
    SanitizedTargetInput,
    ScanContext,
    ScannerFailure,
    ScannerObservation,
)
from .scope import ScopeError, validate_scope


def _failure(
    context: ScanContext,
    *,
    adapter_kind: AdapterKind,
    code: FailureCode,
    message: str,
    retryable: bool = False,
) -> ScannerFailure:
    return ScannerFailure(
        failure_id="failure-pending",
        code=code,
        adapter_kind=adapter_kind,
        message=message,
        tenant_id=context.tenant_id,
        target_id=context.target_id,
        retryable=retryable,
    )


def _failure_record(
    context: ScanContext,
    failure: ScannerFailure,
) -> tuple[ScannerFailure, EvidenceRecord]:
    """Create public-safe failure evidence and bind the failure to this scope."""

    evidence = build_evidence(
        context,
        source=f"scanner.{failure.adapter_kind}",
        kind="scanner_failure",
        payload={
            "adapter_kind": failure.adapter_kind,
            "code": failure.code,
            "message": failure.message,
            "retryable": failure.retryable,
        },
    )
    bound = replace(
        failure,
        failure_id=evidence.evidence_id,
        tenant_id=context.tenant_id,
        target_id=context.target_id,
        evidence_id=evidence.evidence_id,
    )
    return bound, evidence


def _observation_failure(
    context: ScanContext,
    observation: ScannerObservation,
    *,
    code: FailureCode = "out_of_scope",
) -> ScannerFailure:
    """Return a sanitized failure without copying untrusted observation text."""

    return _failure(
        context,
        adapter_kind=observation.adapter_kind,
        code=code,
        message="scanner observation failed scope validation",
    )


def normalize_observation(
    context: ScanContext,
    observation: ScannerObservation,
) -> tuple[Finding, EvidenceRecord]:
    """Validate one observation and derive a finding only after evidence exists."""

    validate_scope(
        context,
        tenant_id=observation.tenant_id or context.tenant_id,
        target_id=observation.target_id or context.target_id,
        adapter_kind=observation.adapter_kind,
    )
    evidence = build_evidence(
        context,
        source=f"scanner.{observation.adapter_kind}",
        kind="observation",
        payload=observation_payload(context, observation),
        observed_at=observation.observed_at,
    )
    fingerprint = finding_fingerprint(
        tenant_id=context.tenant_id,
        target_id=context.target_id,
        adapter_kind=observation.adapter_kind,
        rule_id=observation.rule_id,
        asset_id=observation.asset_id,
        location=observation.location,
        severity=observation.severity,
        confidence=observation.confidence,
        evidence_id=evidence.evidence_id,
    )
    finding = Finding(
        fingerprint=fingerprint,
        rule_id=observation.rule_id,
        title=observation.title,
        description=observation.summary,
        location=observation.location,
        asset_id=observation.asset_id,
        adapter_kind=observation.adapter_kind,
        tenant_id=context.tenant_id,
        target_id=context.target_id,
        severity=observation.severity,
        confidence=observation.confidence,
        evidence_ids=(evidence.evidence_id,),
    )
    return finding, evidence


def deduplicate_findings(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """Merge equivalent findings while retaining every deterministic evidence ID."""

    merged: dict[str, Finding] = {}
    for finding in findings:
        existing = merged.get(finding.fingerprint)
        if existing is None:
            merged[finding.fingerprint] = finding
            continue
        merged[finding.fingerprint] = replace(
            existing,
            evidence_ids=tuple(sorted(set(existing.evidence_ids + finding.evidence_ids))),
        )
    return tuple(merged[key] for key in sorted(merged))


@dataclass(frozen=True, slots=True)
class ScanPipeline:
    """Execute read-only adapters inside one tenant and target boundary."""

    adapters: tuple[ScannerAdapter, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "adapters", tuple(self.adapters))
        kinds = [adapter.adapter_kind for adapter in self.adapters]
        if any(kind not in ADAPTER_KINDS for kind in kinds):
            raise ValueError("scanner adapter kind is unsupported")
        if len(kinds) != len(set(kinds)):
            raise ValueError("one adapter per scanner kind is required")

    def run(
        self,
        context: ScanContext,
        target: SanitizedTargetInput | None = None,
    ) -> PipelineResult:
        target_input = target or SanitizedTargetInput(context.target_id)
        findings: list[Finding] = []
        evidence: list[EvidenceRecord] = []
        failures: list[ScannerFailure] = []

        for adapter in self.adapters:
            if adapter.adapter_kind not in context.adapter_allowlist:
                failure, failure_evidence = _failure_record(
                    context,
                    _failure(
                        context,
                        adapter_kind=adapter.adapter_kind,
                        code="out_of_scope",
                        message="scanner adapter is not enabled for this scan",
                    ),
                )
                failures.append(failure)
                evidence.append(failure_evidence)
                continue
            try:
                result = adapter.scan(context, target_input)
            except Exception:
                result = AdapterResult.failed(
                    adapter.adapter_kind,
                    _failure(
                        context,
                        adapter_kind=adapter.adapter_kind,
                        code="execution_error",
                        message="scanner execution failed",
                    ),
                )
            if result.adapter_kind != adapter.adapter_kind:
                result = AdapterResult.failed(
                    adapter.adapter_kind,
                    _failure(
                        context,
                        adapter_kind=adapter.adapter_kind,
                        code="validation_error",
                        message="scanner result adapter mismatch",
                    ),
                )
            if result.failure is not None:
                failure, failure_evidence = _failure_record(context, result.failure)
                failures.append(failure)
                evidence.append(failure_evidence)
                continue
            for observation in result.observations:
                try:
                    finding, observation_evidence = normalize_observation(context, observation)
                except ScopeError:
                    failure, failure_evidence = _failure_record(
                        context,
                        _observation_failure(context, observation),
                    )
                    failures.append(failure)
                    evidence.append(failure_evidence)
                    continue
                except CanonicalizationError:
                    failure, failure_evidence = _failure_record(
                        context,
                        _observation_failure(context, observation, code="secret_rejected"),
                    )
                    failures.append(failure)
                    evidence.append(failure_evidence)
                    continue
                except ValueError:
                    failure, failure_evidence = _failure_record(
                        context,
                        _observation_failure(context, observation, code="validation_error"),
                    )
                    failures.append(failure)
                    evidence.append(failure_evidence)
                    continue
                findings.append(finding)
                evidence.append(observation_evidence)

        unique_findings = deduplicate_findings(findings)
        unique_evidence = tuple({item.evidence_id: item for item in evidence}.values())
        unique_failures = tuple({item.failure_id: item for item in failures}.values())
        return PipelineResult(
            findings=unique_findings,
            evidence=tuple(sorted(unique_evidence, key=lambda item: item.evidence_id)),
            failures=tuple(sorted(unique_failures, key=lambda item: item.failure_id)),
        )


def run_scan(
    context: ScanContext,
    adapters: Sequence[ScannerAdapter],
    target: SanitizedTargetInput | None = None,
) -> PipelineResult:
    """Convenience entry point for a single deterministic scan."""

    return ScanPipeline(tuple(adapters)).run(context, target)
