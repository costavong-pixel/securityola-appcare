"""Snapshot, verify, and promote bounded worker changes in isolation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

IGNORED_LOCAL_DIRS = {
    ".git",
    ".token-saver",
    "graphify-out",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}
IGNORED_CODEX_DIRS = {"checkpoints", "worker-smoke"}
IGNORED_TOOL_STATE_PATHS = {
    (".opencode", "package.json"),
    (".opencode", "package-lock.json"),
    (".codex", "tasks", ".worker-promotion.lock"),
}
IGNORED_TOOL_STATE_PREFIXES = {(".opencode", "node_modules")}


def _is_ignored(relative: Path) -> bool:
    if any(part in IGNORED_LOCAL_DIRS for part in relative.parts):
        return True
    if (
        relative.parts == (".opencode",)
        or relative.parts in IGNORED_TOOL_STATE_PATHS
        or any(relative.parts[: len(prefix)] == prefix for prefix in IGNORED_TOOL_STATE_PREFIXES)
    ):
        return True
    parts = relative.parts
    try:
        codex_index = parts.index(".codex")
    except ValueError:
        return False
    return len(parts) > codex_index + 1 and parts[codex_index + 1] in IGNORED_CODEX_DIRS


def _canonical_file_bytes(path: Path) -> bytes:
    """Hash text independently of Git checkout line-ending representation."""

    data = path.read_bytes()
    if b"\x00" in data:
        return data
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _inventory(root: Path) -> dict[str, dict[str, object]]:
    root = root.resolve()
    entries: dict[str, dict[str, object]] = {}
    for path in root.rglob("*"):
        relative_path = path.relative_to(root)
        if _is_ignored(relative_path):
            continue
        relative = relative_path.as_posix()
        try:
            if path.is_symlink():
                target = path.resolve(strict=False)
                if not target.is_relative_to(root):
                    raise ValueError("repository inventory encountered an escaping symlink")
                entries[relative] = {"kind": "symlink", "target": os.readlink(path)}
            elif path.is_file():
                file_stat = path.stat()
                entries[relative] = {
                    "kind": "file",
                    "sha256": hashlib.sha256(_canonical_file_bytes(path)).hexdigest(),
                    "mode": stat.S_IMODE(file_stat.st_mode),
                }
            elif path.is_dir():
                entries[relative] = {
                    "kind": "directory",
                    "mode": stat.S_IMODE(path.stat().st_mode),
                }
        except OSError as exc:
            raise ValueError("repository inventory encountered an unreadable path") from exc
    return entries


def snapshot(root: Path) -> dict[str, object]:
    return {"schema_version": "3", "files": _inventory(root)}


def _without_coordinator_tasks(value: dict[str, object]) -> dict[str, object]:
    """Remove coordinator-local task packets for target/source content compares."""

    files = value.get("files")
    if not isinstance(files, dict):
        raise ValueError("invalid scope snapshot")
    normalized = dict(value)
    normalized["files"] = {
        path: entry
        for path, entry in files.items()
        if path != ".codex/tasks" and not path.startswith(".codex/tasks/")
    }
    return normalized


def relative_files(root: Path) -> list[tuple[str, Path]]:
    """Return regular non-symlink files for compatibility with earlier callers."""

    return [
        (relative, root / PurePosixPath(relative))
        for relative, entry in _inventory(root).items()
        if entry.get("kind") == "file"
    ]


def allowed_paths(task: Path) -> list[str]:
    lines = task.read_text(encoding="utf-8").splitlines()
    try:
        start = next(
            index
            for index, line in enumerate(lines)
            if line.strip().casefold() in {"allowed files:", "allowed files/paths:"}
        )
    except StopIteration as exc:
        raise ValueError("task packet must contain an Allowed files section") from exc

    paths: list[str] = []
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if not stripped:
            if paths:
                break
            continue
        if stripped.endswith(":") and not stripped.startswith("-"):
            break
        if stripped.startswith("-"):
            value = stripped[1:].strip().strip("`")
            if value:
                paths.append(value.replace("\\", "/"))
    if not paths:
        raise ValueError("Allowed files section must list at least one path")
    return paths


def path_allowed(path: str, patterns: list[str], entry_kind: str = "file") -> bool:
    normalized = PurePosixPath(path)
    for pattern in patterns:
        candidate = PurePosixPath(pattern)
        if ".." in candidate.parts or candidate.is_absolute():
            continue
        if pattern.endswith("/**"):
            base = pattern[:-3].rstrip("/")
            if path == base or path.startswith(base + "/"):
                return True
            continue
        if pattern.endswith("/*"):
            base = pattern[:-2].rstrip("/")
            remainder = path[len(base) + 1 :] if path.startswith(base + "/") else ""
            if remainder and "/" not in remainder:
                return True
            if entry_kind == "directory" and path == base:
                return True
            continue
        if normalized == candidate:
            return True
        if entry_kind == "directory" and pattern.startswith(path.rstrip("/") + "/"):
            return True
    return False


def _patterns_for_task(task: Path, baseline_task: Path | None) -> list[str]:
    return allowed_paths(baseline_task or task)


def _changed_paths(before: dict[str, object], after: dict[str, object]) -> list[str]:
    before_files = before.get("files", {})
    after_files = after.get("files", {})
    if not isinstance(before_files, dict) or not isinstance(after_files, dict):
        raise ValueError("invalid scope snapshot")
    return sorted(
        path
        for path in set(before_files) | set(after_files)
        if before_files.get(path) != after_files.get(path)
    )


def _scope_violations(
    root: Path,
    before: dict[str, object],
    after: dict[str, object],
    patterns: list[str],
    task: Path,
) -> list[str]:
    before_files = before.get("files", {})
    after_files = after.get("files", {})
    if not isinstance(before_files, dict) or not isinstance(after_files, dict):
        raise ValueError("invalid scope snapshot")
    task_relative = task.resolve().relative_to(root.resolve()).as_posix()
    violations: list[str] = []
    for path in _changed_paths(before, after):
        if path == task_relative:
            violations.append(path)
            continue
        entry = after_files.get(path, before_files.get(path, {}))
        entry_kind = entry.get("kind", "file") if isinstance(entry, dict) else "file"
        if not path_allowed(path, patterns, str(entry_kind)):
            violations.append(path)
    return violations


def verify(
    root: Path,
    before_path: Path,
    task: Path,
    baseline_task: Path | None = None,
) -> list[str]:
    before = json.loads(before_path.read_text(encoding="utf-8"))
    after = snapshot(root)
    patterns = _patterns_for_task(task, baseline_task)
    return _scope_violations(root, before, after, patterns, task)


def _safe_target(root: Path, relative: str) -> Path:
    relative_path = PurePosixPath(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError("invalid repository-relative path")
    root = root.resolve()
    target = root.joinpath(*relative_path.parts)
    current = root
    for part in relative_path.parts[:-1]:
        current /= part
        if current.is_symlink():
            raise ValueError("repository path contains a symlinked parent")
    if not target.parent.resolve(strict=False).is_relative_to(root):
        raise ValueError("repository path escapes root")
    return target


def _remove_target(target: Path) -> None:
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.is_dir():
        target.rmdir()


def _path_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


@contextmanager
def _coordinator_lock(target_root: Path) -> Iterator[None]:
    """Serialize worker promotion for cooperating launchers on this host."""

    lock_dir = target_root / ".codex" / "tasks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / ".worker-promotion.lock"
    with lock_path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)  # type: ignore[attr-defined]
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]


def _coordinator_state(target_root: Path) -> tuple[str, str, str]:
    git_executable = shutil.which("git")
    if git_executable is None:
        raise ValueError("Git executable is unavailable")
    head_result = subprocess.run(  # noqa: S603
        [git_executable, "-C", str(target_root), "rev-parse", "HEAD"],  # noqa: S603
        check=False,
        capture_output=True,
        text=True,
    )
    if head_result.returncode != 0:
        raise ValueError("coordinator checkout has no readable Git HEAD")
    branch_result = subprocess.run(  # noqa: S603
        [git_executable, "-C", str(target_root), "branch", "--show-current"],  # noqa: S603
        check=False,
        capture_output=True,
        text=True,
    )
    if branch_result.returncode != 0 or not branch_result.stdout.strip():
        raise ValueError("coordinator checkout is detached or has no readable branch")
    status_result = subprocess.run(  # noqa: S603
        [git_executable, "-C", str(target_root), "status", "--porcelain", "--untracked-files=all"],  # noqa: S603
        check=False,
        capture_output=True,
        text=True,
    )
    if status_result.returncode != 0:
        raise ValueError("coordinator checkout status could not be read")
    return head_result.stdout.strip(), branch_result.stdout.strip(), status_result.stdout


def _validate_removal_targets(
    target_root: Path,
    changed: list[str],
    after_files: dict[str, object],
) -> None:
    """Reject removals that would silently delete untracked target content."""

    planned_deletes = {relative for relative in changed if relative not in after_files}
    for relative in planned_deletes:
        target = _safe_target(target_root, relative)
        if not target.is_dir() or target.is_symlink():
            continue
        for descendant in target.rglob("*"):
            descendant_relative = descendant.relative_to(target_root).as_posix()
            if descendant_relative not in planned_deletes:
                raise ValueError(
                    "refusing to remove a non-empty target directory containing "
                    f"unplanned content: {relative}"
                )

    # Replacing a directory with a file is also a removal operation.  The
    # directory must contain only paths already accounted for by the worker
    # snapshot so promotion cannot erase local state accidentally.
    for relative in changed:
        entry = after_files.get(relative)
        if not isinstance(entry, dict) or entry.get("kind") != "file":
            continue
        target = _safe_target(target_root, relative)
        if not target.is_dir() or target.is_symlink():
            continue
        for descendant in target.rglob("*"):
            descendant_relative = descendant.relative_to(target_root).as_posix()
            if descendant_relative not in planned_deletes:
                raise ValueError(
                    "refusing to replace a non-empty target directory containing "
                    f"unplanned content: {relative}"
                )


def _validate_source_entries(
    source_root: Path,
    changed: list[str],
    after_files: dict[str, object],
) -> None:
    for relative in changed:
        entry = after_files.get(relative)
        if entry is None:
            continue
        if not isinstance(entry, dict):
            raise ValueError("invalid worker inventory entry")
        source = _safe_target(source_root, relative)
        kind = entry.get("kind")
        if kind == "directory":
            if source.is_symlink() or not source.is_dir():
                raise ValueError("refusing to promote a symlink or non-directory worker path")
        elif kind == "file":
            if source.is_symlink() or not source.is_file():
                raise ValueError("refusing to promote a symlink or non-regular worker path")
        else:
            raise ValueError("refusing to promote an unsupported worker path kind")


def _stage_files(
    source_root: Path,
    changed: list[str],
    after_files: dict[str, object],
    stage_root: Path,
) -> dict[str, Path]:
    staged: dict[str, Path] = {}
    for relative in changed:
        entry = after_files.get(relative)
        if not isinstance(entry, dict) or entry.get("kind") != "file":
            continue
        source = _safe_target(source_root, relative)
        staged_path = _safe_target(stage_root, relative)
        staged_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, staged_path)
        shutil.copymode(source, staged_path)
        staged[relative] = staged_path
    return staged


def _backup_target_state(
    target_root: Path,
    changed: list[str],
    backup_root: Path,
) -> dict[str, dict[str, object]]:
    states: dict[str, dict[str, object]] = {}
    for relative in changed:
        target = _safe_target(target_root, relative)
        if target.is_symlink():
            states[relative] = {
                "kind": "symlink",
                "target": os.readlink(target),
                "target_is_directory": target.is_dir(),
            }
        elif target.is_file():
            backup_path = _safe_target(backup_root, relative)
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(target, backup_path)
            shutil.copymode(target, backup_path)
            states[relative] = {
                "kind": "file",
                "backup": backup_path,
                "mode": stat.S_IMODE(target.stat().st_mode),
            }
        elif target.is_dir():
            states[relative] = {
                "kind": "directory",
                "mode": stat.S_IMODE(target.stat().st_mode),
            }
        else:
            states[relative] = {"kind": "absent"}
    return states


def _restore_target_state(
    target_root: Path,
    states: dict[str, dict[str, object]],
) -> None:
    for relative in sorted(states, key=lambda value: (value.count("/"), value), reverse=True):
        target = _safe_target(target_root, relative)
        state = states[relative]
        kind = state["kind"]
        if kind == "absent":
            if _path_exists(target):
                _remove_target(target)
            continue
        if kind == "directory":
            if _path_exists(target) and (target.is_symlink() or not target.is_dir()):
                _remove_target(target)
            if not _path_exists(target):
                target.parent.mkdir(parents=True, exist_ok=True)
                target.mkdir()
            mode = state.get("mode")
            if not isinstance(mode, int):
                raise ValueError("invalid directory backup mode")
            os.chmod(target, mode)
        elif kind == "file":
            if _path_exists(target):
                _remove_target(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            backup_path = state["backup"]
            if not isinstance(backup_path, Path):
                raise ValueError("invalid file backup path")
            shutil.copyfile(backup_path, target)
            mode = state.get("mode")
            if not isinstance(mode, int):
                raise ValueError("invalid file backup mode")
            os.chmod(target, mode)
        elif kind == "symlink":
            if _path_exists(target):
                _remove_target(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(
                str(state["target"]),
                target,
                target_is_directory=bool(state["target_is_directory"]),
            )
        else:
            raise ValueError("invalid target backup kind")


def _apply_staged_changes(
    source_root: Path,
    target_root: Path,
    changed: list[str],
    after_files: dict[str, object],
    staged: dict[str, Path],
) -> None:
    deletions = [relative for relative in changed if relative not in after_files]
    for relative in sorted(deletions, key=lambda value: (value.count("/"), value), reverse=True):
        target = _safe_target(target_root, relative)
        if _path_exists(target):
            _remove_target(target)

    directories: list[str] = []
    for relative in changed:
        entry = after_files.get(relative)
        if isinstance(entry, dict) and entry.get("kind") == "directory":
            directories.append(relative)
    for relative in sorted(directories, key=lambda value: (value.count("/"), value)):
        source = _safe_target(source_root, relative)
        target = _safe_target(target_root, relative)
        if _path_exists(target) and (target.is_symlink() or not target.is_dir()):
            _remove_target(target)
        target.mkdir(parents=True, exist_ok=True)

    files = [relative for relative in changed if relative in staged]
    for relative in sorted(files, key=lambda value: (value.count("/"), value)):
        target = _safe_target(target_root, relative)
        if _path_exists(target):
            _remove_target(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(staged[relative], target)
        shutil.copymode(staged[relative], target)

    # Apply directory modes last so restrictive worker modes cannot prevent
    # creation of the files that belong beneath those directories.
    for relative in sorted(directories, key=lambda value: (value.count("/"), value), reverse=True):
        source = _safe_target(source_root, relative)
        target = _safe_target(target_root, relative)
        shutil.copymode(source, target)


def _promote_unlocked(
    source_root: Path,
    target_root: Path,
    before_path: Path,
    task: Path,
    baseline_task: Path | None = None,
    expected_head: str | None = None,
    expected_branch: str | None = None,
) -> list[str]:
    source_root = source_root.resolve()
    target_root = target_root.resolve()
    if expected_head is not None:
        actual_head, actual_branch, status = _coordinator_state(target_root)
        if (
            actual_head != expected_head
            or (expected_branch is not None and actual_branch != expected_branch)
            or status
        ):
            raise ValueError("coordinator changed before worker promotion")
    before = json.loads(before_path.read_text(encoding="utf-8"))
    after = snapshot(source_root)
    patterns = _patterns_for_task(task, baseline_task)
    violations = _scope_violations(source_root, before, after, patterns, task)
    if violations:
        return violations
    before_files = before.get("files", {})
    after_files = after.get("files", {})
    if not isinstance(before_files, dict) or not isinstance(after_files, dict):
        raise ValueError("invalid scope snapshot")

    changed = _changed_paths(before, after)
    _validate_source_entries(source_root, changed, after_files)
    _validate_removal_targets(target_root, changed, after_files)
    if _without_coordinator_tasks(snapshot(target_root)) != _without_coordinator_tasks(before):
        raise ValueError("coordinator content changed before worker promotion")

    with tempfile.TemporaryDirectory(prefix="securityola-appcare-promote-") as temporary:
        temporary_root = Path(temporary)
        staged = _stage_files(source_root, changed, after_files, temporary_root / "staged")
        states = _backup_target_state(target_root, changed, temporary_root / "backup")
        try:
            _apply_staged_changes(source_root, target_root, changed, after_files, staged)
            if _without_coordinator_tasks(snapshot(target_root)) != _without_coordinator_tasks(
                after
            ):
                raise RuntimeError("coordinator content did not match the worker result")
        except Exception:
            try:
                _restore_target_state(target_root, states)
            except Exception as rollback_exc:
                raise RuntimeError(
                    "worker promotion failed and rollback also failed"
                ) from rollback_exc
            raise
    return []


def promote(
    source_root: Path,
    target_root: Path,
    before_path: Path,
    task: Path,
    baseline_task: Path | None = None,
    expected_head: str | None = None,
    expected_branch: str | None = None,
) -> list[str]:
    with _coordinator_lock(target_root.resolve()):
        return _promote_unlocked(
            source_root,
            target_root,
            before_path,
            task,
            baseline_task,
            expected_head,
            expected_branch,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot_parser = subparsers.add_parser("snapshot")
    snapshot_parser.add_argument("--root", type=Path, required=True)
    snapshot_parser.add_argument("--out", type=Path, required=True)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", type=Path, required=True)
    verify_parser.add_argument("--before", type=Path, required=True)
    verify_parser.add_argument("--task", type=Path, required=True)
    verify_parser.add_argument("--baseline-task", type=Path)

    promote_parser = subparsers.add_parser("promote")
    promote_parser.add_argument("--source-root", type=Path, required=True)
    promote_parser.add_argument("--target-root", type=Path, required=True)
    promote_parser.add_argument("--before", type=Path, required=True)
    promote_parser.add_argument("--task", type=Path, required=True)
    promote_parser.add_argument("--baseline-task", type=Path)
    promote_parser.add_argument("--expected-head")
    promote_parser.add_argument("--expected-branch")

    args = parser.parse_args()
    if args.command == "snapshot":
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(snapshot(args.root), indent=2), encoding="utf-8")
        print("task scope snapshot created")
        return 0

    if args.command == "verify":
        violations = verify(args.root, args.before, args.task, args.baseline_task)
        if violations:
            print("worker changed files outside the task scope:")
            print("\n".join(violations))
            return 1
        print("worker task scope verified")
        return 0

    violations = promote(
        args.source_root,
        args.target_root,
        args.before,
        args.task,
        args.baseline_task,
        args.expected_head,
        args.expected_branch,
    )
    if violations:
        print("worker changed files outside the task scope:")
        print("\n".join(violations))
        return 1
    print("worker task changes promoted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
