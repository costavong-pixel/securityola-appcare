"""Deterministic, read-only scanning contracts and normalization pipeline."""

from .adapters import (
    DependencyScannerAdapter,
    FunctionalScannerAdapter,
    SecretScannerAdapter,
    SourceScannerAdapter,
)
from .canonical import (
    CanonicalizationError,
    build_evidence,
    canonical_json,
    canonicalize,
    finding_fingerprint,
    sha256_digest,
)
from .contracts import ScannerAdapter
from .models import (
    AdapterKind,
    AdapterResult,
    Confidence,
    EvidenceKind,
    EvidenceRecord,
    FailureCode,
    Finding,
    FindingStatus,
    PipelineResult,
    SanitizedTargetInput,
    ScanContext,
    ScannerFailure,
    ScannerObservation,
    Severity,
    Suppression,
)
from .pipeline import ScanPipeline, deduplicate_findings, normalize_observation, run_scan
from .scope import ScopeError, validate_scope, validate_target_input
from .suppression import suppress_finding

__all__ = [
    "AdapterKind",
    "AdapterResult",
    "CanonicalizationError",
    "Confidence",
    "DependencyScannerAdapter",
    "EvidenceKind",
    "EvidenceRecord",
    "FailureCode",
    "Finding",
    "FindingStatus",
    "FunctionalScannerAdapter",
    "PipelineResult",
    "ScanContext",
    "ScanPipeline",
    "ScannerAdapter",
    "ScannerFailure",
    "ScannerObservation",
    "SecretScannerAdapter",
    "SanitizedTargetInput",
    "ScopeError",
    "Severity",
    "SourceScannerAdapter",
    "Suppression",
    "build_evidence",
    "canonical_json",
    "canonicalize",
    "deduplicate_findings",
    "finding_fingerprint",
    "normalize_observation",
    "run_scan",
    "sha256_digest",
    "suppress_finding",
    "validate_scope",
    "validate_target_input",
]
