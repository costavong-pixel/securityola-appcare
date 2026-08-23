"""Symlink-safe disposable workspace management."""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path, PurePosixPath

from .contracts import RemediationBoundaryError, RemediationContext, RemediationWorkspace

_FORBIDDEN_MARKERS = (
    "wordpress",
    "barnd",
    "shield",
    "api.securityola.com",
    "/var/www",
    "\\var\\www",
    "production",
    "authorized_keys",
    ".env",
    ".ssh",
)


class WorkspaceBoundaryError(RemediationBoundaryError):
    """Workspace path or lifecycle operation is outside AppCare scope."""


_DRIVE_PATH = re.compile(r"^[A-Za-z]:")


def _canonical(path: Path, *, field_name: str) -> Path:
    if not path.is_absolute():
        raise WorkspaceBoundaryError(f"{field_name} must be absolute")
    try:
        absolute = Path(os.path.abspath(path))
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise WorkspaceBoundaryError(f"{field_name} cannot be resolved") from exc
    if os.path.normcase(os.fspath(absolute)) != os.path.normcase(os.fspath(resolved)):
        raise WorkspaceBoundaryError(f"{field_name} crosses a symlink")
    normalized = os.fspath(resolved).casefold().replace("\\", "/")
    if any(marker in normalized for marker in _FORBIDDEN_MARKERS):
        raise WorkspaceBoundaryError(f"{field_name} is outside the AppCare boundary")
    if resolved == Path(resolved.anchor) or resolved.parent == resolved:
        raise WorkspaceBoundaryError(f"{field_name} is too broad")
    return resolved


def _inside(root: Path, child: Path, *, field_name: str) -> Path:
    canonical_root = _canonical(root, field_name=f"{field_name} root")
    if child.is_symlink():
        raise WorkspaceBoundaryError(f"{field_name} crosses a symlink")
    try:
        absolute = Path(os.path.abspath(child))
        resolved = child.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise WorkspaceBoundaryError(f"{field_name} cannot be resolved") from exc
    if os.path.normcase(os.fspath(absolute)) != os.path.normcase(os.fspath(resolved)):
        raise WorkspaceBoundaryError(f"{field_name} crosses a symlink")
    try:
        resolved.relative_to(canonical_root)
    except ValueError as exc:
        raise WorkspaceBoundaryError(f"{field_name} escaped the workspace root") from exc
    return resolved


class WorkspaceManager:
    """Create and destroy only job-scoped disposable AppCare directories."""

    def __init__(self, root: Path) -> None:
        self.root = _canonical(root, field_name="workspace manager root")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink():
            raise WorkspaceBoundaryError("workspace manager root became a symlink")

    def create(self, context: RemediationContext) -> RemediationWorkspace:
        workspace_id = f"ws-{context.tenant_id}-{context.application_id}-{context.job_id}"
        target = self.root / context.tenant_id / context.application_id / context.job_id
        target = _inside(self.root, target, field_name="remediation workspace")
        if target.exists() and not target.is_dir():
            raise WorkspaceBoundaryError("remediation workspace is not a directory")
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.is_symlink():
            raise WorkspaceBoundaryError("remediation workspace became a symlink")
        return RemediationWorkspace(workspace_id=workspace_id, context=context, root=target)

    def child(self, workspace: RemediationWorkspace, relative_path: str) -> Path:
        """Resolve one relative workspace child without following links."""

        if (
            not relative_path
            or relative_path.startswith(("/", "\\"))
            or _DRIVE_PATH.match(relative_path)
            or "\x00" in relative_path
        ):
            raise WorkspaceBoundaryError("workspace child must be relative")
        if "\\" in relative_path:
            raise WorkspaceBoundaryError("workspace child cannot contain backslashes")
        parsed = PurePosixPath(relative_path)
        if any(part in {"", ".", ".."} for part in parsed.parts):
            raise WorkspaceBoundaryError("workspace child contains traversal")
        candidate = workspace.root / Path(parsed)
        return _inside(workspace.root, candidate, field_name="workspace child")

    def destroy(self, workspace: RemediationWorkspace) -> None:
        """Remove only a workspace previously created below this manager root."""

        target = _inside(self.root, workspace.root, field_name="workspace cleanup")
        if target == self.root:
            raise WorkspaceBoundaryError("refusing to remove the manager root")
        if target.exists():
            shutil.rmtree(target)


__all__ = ["WorkspaceBoundaryError", "WorkspaceManager"]
