"""Run the approved deterministic secret scanner on worker-produced files."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from .verify_task_scope import _safe_target, snapshot


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


def _stage_changed_files(root: Path, before: dict[str, object], scan_root: Path) -> int:
    after = snapshot(root)
    after_files = after.get("files", {})
    if not isinstance(after_files, dict):
        raise ValueError("invalid worker snapshot")
    changed = _changed_paths(before, after)
    staged_count = 0
    for relative in changed:
        entry = after_files.get(relative)
        if entry is None:
            continue
        if not isinstance(entry, dict) or entry.get("kind") != "file":
            raise ValueError(f"worker changed a non-regular path: {relative}")
        source = _safe_target(root, relative)
        target = scan_root.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        staged_count += 1
    return staged_count


def find_scanner() -> str | None:
    return shutil.which("gitleaks")


def execute_scanner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - scanner path is resolved from PATH
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )


def scan(root: Path, before_path: Path) -> tuple[int, str]:
    try:
        before = json.loads(before_path.read_text(encoding="utf-8"))
        if not isinstance(before, dict):
            raise ValueError("invalid scope snapshot")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return 2, f"worker secret scan could not read its scope snapshot: {exc}"

    scanner = find_scanner()
    with tempfile.TemporaryDirectory(prefix="securityola-appcare-secret-scan-") as temporary:
        scan_root = Path(temporary) / "changed"
        scan_root.mkdir()
        try:
            changed_count = _stage_changed_files(root, before, scan_root)
        except (OSError, ValueError) as exc:
            return 2, f"worker secret scan staging failed: {exc}"
        if changed_count == 0:
            return 0, "worker secret scan passed: no worker-produced files"
        if scanner is None:
            return 127, "worker secret scan unavailable: gitleaks is not installed"

        report = Path(temporary) / "report.json"
        command = [
            scanner,
            "detect",
            "--source",
            str(scan_root),
            "--no-git",
            "--redact",
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--exit-code",
            "1",
            "--no-banner",
        ]
        try:
            result = execute_scanner(command)
        except (OSError, subprocess.TimeoutExpired):
            return 2, "worker secret scanner failed or timed out"
        if result.returncode == 0:
            return 0, f"worker secret scan passed: {changed_count} changed file(s)"
        if result.returncode == 1:
            finding_count = "unknown"
            try:
                payload = json.loads(report.read_text(encoding="utf-8"))
                if isinstance(payload, list):
                    finding_count = str(len(payload))
            except (OSError, json.JSONDecodeError):
                pass
            return 1, f"worker secret scan rejected {finding_count} finding(s)"
        return result.returncode, f"worker secret scanner failed with exit code {result.returncode}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--before", type=Path, required=True)
    args = parser.parse_args()
    code, message = scan(args.root, args.before)
    if code == 0:
        print(message)
    else:
        print(message, file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
