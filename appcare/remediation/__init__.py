"""Safe, deterministic AppCare remediation boundaries."""

from .approval import ApprovalQueue
from .contracts import (
    ApprovalDecision,
    ApprovalRequest,
    FileChange,
    GateResult,
    PatchCandidate,
    PatchValidationResult,
    PreviewPolicy,
    PreviewRequest,
    PreviewResult,
    RemediationContext,
    RemediationWorkspace,
    ReviewEvidence,
)
from .gates import GateRunner
from .patches import PatchBuilder, PatchValidator, apply_patch_atomically
from .preview import FixturePreviewAdapter, UnapprovedVercelPreviewAdapter
from .workspace import WorkspaceBoundaryError, WorkspaceManager

__all__ = [
    "ApprovalDecision",
    "ApprovalQueue",
    "ApprovalRequest",
    "FileChange",
    "FixturePreviewAdapter",
    "GateResult",
    "GateRunner",
    "PatchBuilder",
    "PatchCandidate",
    "PatchValidationResult",
    "PatchValidator",
    "PreviewPolicy",
    "PreviewRequest",
    "PreviewResult",
    "RemediationContext",
    "RemediationWorkspace",
    "ReviewEvidence",
    "UnapprovedVercelPreviewAdapter",
    "WorkspaceBoundaryError",
    "WorkspaceManager",
    "apply_patch_atomically",
]
