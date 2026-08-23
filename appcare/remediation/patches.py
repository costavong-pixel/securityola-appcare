"""Deterministic patch construction, validation, and atomic workspace apply."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from appcare.scanning.models import Finding
from appcare.services.security import contains_credential_like

from .contracts import (
    FileChange,
    PatchCandidate,
    PatchValidationResult,
    RemediationBoundaryError,
    RemediationContext,
    RemediationWorkspace,
    ReviewEvidence,
    evidence_digest,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

_DRIVE_PATH = re.compile(r"^[A-Za-z]:")
_FORBIDDEN_PATH_MARKERS = (
    "wordpress",
    "barnd",
    "shield",
    "api.securityola.com",
    "var/www",
    "production",
    ".env",
    "credential",
    "secret",
    "private",
    "authorized_keys",
    ".ssh",
)
_SECRET_CONTENT = re.compile(
    r"(?i)\b(?:password|secret|token|api[_-]?key|authorization|private[_-]?key)\s*[:=]"
)


class PatchBoundaryError(RemediationBoundaryError):
    """Patch construction or application crossed a bounded safety rule."""


def _path(path: str, *, allowed_prefixes: tuple[str, ...]) -> str:
    if not isinstance(path, str) or not path or "\\" in path:
        raise PatchBoundaryError("patch path is not a normalized relative path")
    if path.startswith("/") or _DRIVE_PATH.match(path) or "\x00" in path:
        raise PatchBoundaryError("patch path is absolute or malformed")
    parsed = PurePosixPath(path)
    if any(part in {"", ".", ".."} for part in parsed.parts):
        raise PatchBoundaryError("patch path contains traversal")
    normalized = parsed.as_posix()
    lowered = normalized.casefold()
    if any(marker in lowered for marker in _FORBIDDEN_PATH_MARKERS):
        raise PatchBoundaryError("patch path is outside the AppCare boundary")
    normalized_prefixes = tuple(prefix.rstrip("/") + "/" for prefix in allowed_prefixes)
    if not any(normalized.startswith(prefix) for prefix in normalized_prefixes):
        raise PatchBoundaryError("patch path is not allowlisted")
    return normalized


def _workspace_path(workspace: RemediationWorkspace, relative_path: str) -> Path:
    root = workspace.root
    if not root.is_absolute() or root.is_symlink():
        raise PatchBoundaryError("workspace root is unsafe")
    canonical_root = root.resolve(strict=False)
    if os.path.normcase(os.fspath(canonical_root)) != os.path.normcase(os.fspath(root)):
        raise PatchBoundaryError("workspace root crosses a symlink")
    candidate = root / PurePosixPath(relative_path)
    if candidate.is_symlink():
        raise PatchBoundaryError("patch path crosses a symlink")
    resolved = candidate.resolve(strict=False)
    if os.path.normcase(os.fspath(resolved)) != os.path.normcase(os.fspath(candidate)):
        raise PatchBoundaryError("patch path crosses a symlink")
    try:
        resolved.relative_to(canonical_root)
    except ValueError as exc:
        raise PatchBoundaryError("patch path escaped the workspace") from exc
    return resolved


def _canonical_changes(changes: Iterable[FileChange]) -> tuple[FileChange, ...]:
    ordered = tuple(sorted(changes, key=lambda item: item.path))
    if not ordered or len(ordered) > 100:
        raise PatchBoundaryError("patch changes are empty or exceed the bound")
    if len({item.path for item in ordered}) != len(ordered):
        raise PatchBoundaryError("patch contains duplicate paths")
    return ordered


def _change_payload(change: FileChange) -> dict[str, str | None]:
    return {
        "path": change.path,
        "operation": change.operation,
        "before_digest": change.before_digest,
        "after_digest": change.after_digest,
    }


def _unsafe_content(content: str) -> bool:
    return contains_credential_like(content) or _SECRET_CONTENT.search(content) is not None


def _patch_digest(changes: tuple[FileChange, ...]) -> str:
    return hashlib.sha256(
        json.dumps(
            [_change_payload(change) for change in changes],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _patch_id(
    context: RemediationContext,
    evidence_refs: tuple[str, ...],
    changes: tuple[FileChange, ...],
    reference_commit: str,
    rollback_reference: str,
) -> str:
    canonical_json = json.dumps(
        {
            "tenant_id": context.tenant_id,
            "application_id": context.application_id,
            "job_id": context.job_id,
            "finding_fingerprint": context.finding_fingerprint,
            "evidence_refs": sorted(evidence_refs),
            "source_revision": context.source_revision,
            "reference_commit": reference_commit,
            "rollback_reference": rollback_reference,
            "changes": [_change_payload(change) for change in changes],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class PatchBuilder:
    """Build a patch only from a tenant-scoped finding and deterministic evidence."""

    def __init__(self, *, allowed_prefixes: tuple[str, ...] = ("appcare/",)) -> None:
        if not allowed_prefixes:
            raise PatchBoundaryError("patch allowlist cannot be empty")
        self.allowed_prefixes = tuple(
            _path(prefix.rstrip("/") + "/example.py", allowed_prefixes=(prefix,)).split(
                "/example.py"
            )[0]
            + "/"
            for prefix in allowed_prefixes
        )

    def build(
        self,
        context: RemediationContext,
        finding: Finding,
        *,
        evidence_refs: tuple[str, ...],
        changes: tuple[FileChange, ...],
        reference_commit: str,
        rollback_reference: str,
    ) -> PatchCandidate:
        if finding.status != "active":
            raise PatchBoundaryError("only active findings can produce remediation")
        if finding.tenant_id != context.tenant_id or finding.target_id != context.application_id:
            raise PatchBoundaryError("finding is outside the remediation scope")
        if finding.fingerprint != context.finding_fingerprint:
            raise PatchBoundaryError("finding fingerprint does not match the remediation scope")
        normalized_evidence_refs = tuple(
            dict.fromkeys(value.strip().casefold() for value in evidence_refs)
        )
        if not set(finding.evidence_ids).issubset(set(normalized_evidence_refs)):
            raise PatchBoundaryError("deterministic finding evidence is incomplete")
        canonical = _canonical_changes(changes)
        for change in canonical:
            if _path(change.path, allowed_prefixes=self.allowed_prefixes) != change.path:
                raise PatchBoundaryError("patch path is not normalized")
            if _unsafe_content(change.content):
                raise PatchBoundaryError("patch content contains credential-like data")
        normalized_reference = reference_commit.strip().casefold()
        normalized_rollback = rollback_reference.strip().casefold()
        patch_id = _patch_id(
            context,
            normalized_evidence_refs,
            canonical,
            normalized_reference,
            normalized_rollback,
        )
        patch_digest = _patch_digest(canonical)
        return PatchCandidate(
            patch_id=patch_id,
            context=context,
            evidence_refs=normalized_evidence_refs,
            changes=canonical,
            source_revision=context.source_revision,
            reference_commit=normalized_reference,
            rollback_reference=normalized_rollback,
            patch_digest=patch_digest,
        )


class PatchValidator:
    """Validate every patch path and preimage before workspace mutation."""

    def __init__(self, *, allowed_prefixes: tuple[str, ...] = ("appcare/",)) -> None:
        self.allowed_prefixes = allowed_prefixes

    def _result(
        self,
        patch: PatchCandidate,
        *,
        status: str,
        code: str,
        paths: tuple[str, ...] = (),
    ) -> PatchValidationResult:
        return PatchValidationResult(
            patch_id=patch.patch_id,
            status=status,  # type: ignore[arg-type]
            code=code,
            evidence_ref=evidence_digest("patch-validation", patch.patch_id, status, code, *paths),
            changed_paths=paths,
        )

    def validate(
        self, workspace: RemediationWorkspace, patch: PatchCandidate
    ) -> PatchValidationResult:
        if workspace.context != patch.context:
            return self._result(patch, status="blocked", code="context_mismatch")
        if patch.patch_digest != _patch_digest(patch.changes):
            return self._result(patch, status="blocked", code="patch_digest_mismatch")
        if patch.patch_id != _patch_id(
            patch.context,
            patch.evidence_refs,
            patch.changes,
            patch.reference_commit,
            patch.rollback_reference,
        ):
            return self._result(patch, status="blocked", code="patch_identity_mismatch")
        paths: list[str] = []
        try:
            for change in patch.changes:
                normalized = _path(change.path, allowed_prefixes=self.allowed_prefixes)
                if normalized != change.path:
                    raise PatchBoundaryError("patch path is not normalized")
                if _unsafe_content(change.content):
                    raise PatchBoundaryError("patch content contains credential-like data")
                target = _workspace_path(workspace, normalized)
                if target.exists() and target.is_symlink():
                    raise PatchBoundaryError("patch target is a symlink")
                if change.operation == "add":
                    if target.exists():
                        raise PatchBoundaryError("patch add target already exists")
                elif not target.is_file():
                    raise PatchBoundaryError("patch modify target is missing")
                elif hashlib.sha256(target.read_bytes()).hexdigest() != change.before_digest:
                    raise PatchBoundaryError("patch preimage does not match workspace")
                paths.append(normalized)
        except (OSError, RemediationBoundaryError) as exc:
            code = str(exc).replace(" ", "_").casefold()[:120]
            if not re.fullmatch(r"[a-z0-9_.:-]{2,127}", code):
                code = "patch_validation_failed"
            return self._result(patch, status="blocked", code=code, paths=tuple(paths))
        return self._result(patch, status="passed", code="patch_validated", paths=tuple(paths))


def review_evidence(patch: PatchCandidate, gate_refs: tuple[str, ...] = ()) -> ReviewEvidence:
    """Create the sanitized reviewer record for a patch."""

    return ReviewEvidence(
        patch_id=patch.patch_id,
        finding_fingerprint=patch.context.finding_fingerprint,
        evidence_refs=patch.evidence_refs,
        source_revision=patch.source_revision,
        reference_commit=patch.reference_commit,
        rollback_reference=patch.rollback_reference,
        patch_digest=patch.patch_digest,
        changed_paths=tuple(change.path for change in patch.changes),
        gate_refs=gate_refs,
    )


def apply_patch_atomically(
    workspace: RemediationWorkspace,
    patch: PatchCandidate,
    *,
    validator: PatchValidator | None = None,
) -> PatchValidationResult:
    """Apply a validated patch with rollback on a local staging failure."""

    active_validator = validator or PatchValidator()
    validation = active_validator.validate(workspace, patch)
    if validation.status != "passed":
        return validation
    staging = Path(tempfile.mkdtemp(prefix=".appcare-stage-", dir=workspace.root))
    originals: dict[Path, bytes | None] = {}
    replaced: list[Path] = []
    try:
        staged: list[tuple[Path, Path, FileChange]] = []
        for index, change in enumerate(patch.changes):
            target = _workspace_path(workspace, change.path)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if target.exists() and target.is_symlink():
                raise PatchBoundaryError("patch target became a symlink")
            if change.operation == "add" and target.exists():
                raise PatchBoundaryError("patch add target appeared during apply")
            originals[target] = target.read_bytes() if target.exists() else None
            staged_path = staging / f"change-{index:03d}.tmp"
            staged_path.write_text(change.content, encoding="utf-8", newline="")
            staged.append((staged_path, target, change))
        for staged_path, target, _change in staged:
            os.replace(staged_path, target)
            replaced.append(target)
    except (OSError, RemediationBoundaryError):
        for target in reversed(replaced):
            original = originals[target]
            if original is None:
                target.unlink(missing_ok=True)
            else:
                restore = target.with_name(f".{target.name}.restore")
                restore.write_bytes(original)
                os.replace(restore, target)
        return PatchValidationResult(
            patch_id=patch.patch_id,
            status="blocked",
            code="patch_apply_failed",
            evidence_ref=evidence_digest("patch-apply", patch.patch_id, "blocked"),
            changed_paths=validation.changed_paths,
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return PatchValidationResult(
        patch_id=patch.patch_id,
        status="passed",
        code="patch_applied",
        evidence_ref=evidence_digest("patch-apply", patch.patch_id, "passed"),
        changed_paths=validation.changed_paths,
    )


__all__ = [
    "PatchBoundaryError",
    "PatchBuilder",
    "PatchValidator",
    "apply_patch_atomically",
    "review_evidence",
]
