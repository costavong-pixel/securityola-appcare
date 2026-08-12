"""Snapshot, verify, and promote bounded worker changes in isolation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path, PurePosixPath

IGNORED_LOCAL_DIRS = {".git", ".token-saver", "graphify-out", "__pycache__"}
IGNORED_CODEX_DIRS = {"checkpoints", "worker-smoke"}


def _is_ignored(relative: Path) -> bool:
    if any(part in IGNORED_LOCAL_DIRS for part in relative.parts):
        return True
    parts = relative.parts
    try:
        codex_index = parts.index(".codex")
    except ValueError:
        return False
    return len(parts) > codex_index + 1 and parts[codex_index + 1] in IGNORED_CODEX_DIRS


def _inventory(root: Path) -> dict[str, dict[str, str]]:
    root = root.resolve()
    entries: dict[str, dict[str, str]] = {}
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
                entries[relative] = {
                    "kind": "file",
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            elif path.is_dir():
                entries[relative] = {"kind": "directory"}
        except OSError as exc:
            raise ValueError("repository inventory encountered an unreadable path") from exc
    return entries


def snapshot(root: Path) -> dict[str, object]:
    return {"schema_version": "3", "files": _inventory(root)}


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


def promote(
    source_root: Path,
    target_root: Path,
    before_path: Path,
    task: Path,
    baseline_task: Path | None = None,
) -> list[str]:
    source_root = source_root.resolve()
    target_root = target_root.resolve()
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
    for relative in sorted(changed, key=lambda value: (value.count("/"), value), reverse=True):
        source = _safe_target(source_root, relative)
        target = _safe_target(target_root, relative)
        entry = after_files.get(relative)
        if entry is None:
            if target.exists() or target.is_symlink():
                _remove_target(target)
            continue
        if not isinstance(entry, dict):
            raise ValueError("invalid worker inventory entry")
        kind = entry.get("kind")
        if kind == "directory":
            target.mkdir(parents=True, exist_ok=True)
            continue
        if kind != "file" or source.is_symlink() or not source.is_file():
            raise ValueError("refusing to promote a symlink or non-regular worker path")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            _remove_target(target)
        shutil.copyfile(source, target)
    return []


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
    )
    if violations:
        print("worker changed files outside the task scope:")
        print("\n".join(violations))
        return 1
    print("worker task changes promoted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
