"""Reject obvious secret and private-infrastructure leaks from tracked files."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

_PRIVATE_IPV4 = (
    r"(?<![\d.])(?:"
    r"(?:10|127)(?:\.\d{1,3}){3}|"
    r"(?:169\.254|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2}"
    r")(?![\d.])"
)
_PRIVATE_IPV4_PATTERN = re.compile(_PRIVATE_IPV4)
MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024


FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private IPv4 address", _PRIVATE_IPV4_PATTERN),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b")),
    (
        "generic secret assignment",
        re.compile(r"(?i)\b(?:password|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
    ),
)


def _is_intentional_loopback_only(line: str, pattern: re.Pattern[str]) -> bool:
    """Allow explicit loopback-only bindings without allowing private peers."""

    matches = pattern.findall(line)
    return bool(matches) and all(match.startswith("127.") for match in matches)


def tracked_files(root: Path) -> list[Path]:
    """Return tracked files without reading Git history or external paths."""

    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git executable is required for the public-safety scan")
    result = subprocess.run(  # noqa: S603 - executable is resolved from PATH
        [git, "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
        text=False,
    )
    names = [item for item in result.stdout.decode("utf-8").split("\0") if item]
    return [root / name for name in names]


def local_artifact_files(root: Path) -> list[Path]:
    """Scan ignored local task/checkpoint artifacts without following symlinks."""

    files: list[Path] = []
    for relative_dir in (
        ".codex/tasks",
        ".codex/checkpoints",
        ".codex/worker-smoke",
        ".token-saver",
    ):
        directory = root / relative_dir
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            relative = path.relative_to(root)
            if "before-files" in relative.parts:
                continue
            if path.is_file() and not path.is_symlink():
                files.append(path)
    return files


def scan(root: Path) -> list[str]:
    """Return redacted finding descriptions; never return matching content."""

    root = root.resolve()
    findings: list[str] = []
    paths = tracked_files(root) + local_artifact_files(root)
    seen: set[str] = set()
    for candidate in paths:
        relative = candidate.relative_to(root).as_posix()
        if relative in seen:
            continue
        seen.add(relative)
        if candidate.is_symlink():
            findings.append(f"{relative}: symlink is not scannable")
            continue
        try:
            path = candidate.resolve(strict=True)
            if not path.is_relative_to(root):
                findings.append(f"{relative}: path escapes repository")
                continue
            stat = path.stat()
        except (OSError, RuntimeError):
            findings.append(f"{relative}: file is not scannable")
            continue
        if not path.is_file():
            findings.append(f"{relative}: path is not a regular file")
            continue
        if stat.st_size > MAX_SCAN_FILE_BYTES:
            findings.append(f"{relative}: file exceeds scan size limit")
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            findings.append(f"{relative}: file is unreadable")
            continue
        if b"\x00" in raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            # Binary-capable secret scanning is a separate CI gate; do not
            # treat ordinary non-text assets as leaked text here.
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for label, pattern in FORBIDDEN_PATTERNS:
                if pattern.search(line):
                    if label == "private IPv4 address" and _is_intentional_loopback_only(
                        line, pattern
                    ):
                        continue
                    findings.append(f"{relative}:{line_number}: {label}")
    return findings


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    findings = scan(root)
    if findings:
        print("Public-safety scan failed:")
        print("\n".join(findings))
        return 1
    print(f"Public-safety scan passed: {len(tracked_files(root))} tracked files checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
