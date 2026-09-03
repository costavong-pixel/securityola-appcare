"""P03 immutable application identity and source-mirror boundaries."""

from .capture import FilesystemBaselineCapturer, detect_source_type, read_git_revision
from .contracts import (
    BaselineCaptureError,
    BaselineEntry,
    BaselinePolicy,
    CapturedApplicationRevision,
    EvidenceClass,
    FilesystemBaseline,
    LiveCaptureAuthorization,
    MirrorCaptureError,
    MirrorCaptureOutcome,
    MirrorPolicy,
    MirrorReceipt,
    RevisionError,
    SourceType,
    is_secret_path_name,
)
from .mirror import INTERNAL_MIRROR_ROOT, ImmutableSourceMirror

__all__ = [
    "BaselineCaptureError",
    "BaselineEntry",
    "BaselinePolicy",
    "CapturedApplicationRevision",
    "EvidenceClass",
    "FilesystemBaseline",
    "FilesystemBaselineCapturer",
    "INTERNAL_MIRROR_ROOT",
    "ImmutableSourceMirror",
    "LiveCaptureAuthorization",
    "MirrorCaptureError",
    "MirrorCaptureOutcome",
    "MirrorPolicy",
    "MirrorReceipt",
    "RevisionError",
    "SourceType",
    "detect_source_type",
    "is_secret_path_name",
    "read_git_revision",
]
