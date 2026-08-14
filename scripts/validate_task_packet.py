"""Reject secrets and private infrastructure data before a task reaches a worker."""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath

MAX_PACKET_BYTES = 64 * 1024
_PRIVATE_IPV4 = (
    r"(?<![\d.])(?:"
    r"(?:10|127)(?:\.\d{1,3}){3}|"
    r"(?:169\.254|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2}"
    r")(?![\d.])"
)
FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("credential URL", re.compile(r"https?://[^/\s:@]+:[^@\s]+@")),
    (
        "generic secret assignment",
        re.compile(
            r"(?i)\b(?:"
            r"password|passphrase|secret|client[_-]?secret|secret[_-]?(?:key|token|value)|"
            r"token|session[_-]?token|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
            r"api[_-]?key|authorization|cookie|private[_-]?key|signing[_-]?key|"
            r"credential(?:s)?|bearer"
            r")\s*[:=]\s*(?:['\"][^'\"]{8,}['\"]|[^\s#]{8,})"
        ),
    ),
    ("private IPv4 address", re.compile(_PRIVATE_IPV4)),
)

_ALLOWED_SECTION_NAMES = {"allowed files:", "allowed files/paths:"}


def allowed_paths(text: str) -> list[str]:
    """Parse and validate the pre-execution worker scope from packet text."""

    lines = text.splitlines()
    try:
        start = next(
            index
            for index, line in enumerate(lines)
            if line.strip().casefold() in _ALLOWED_SECTION_NAMES
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
            value = stripped[1:].strip().strip("`").replace("\\", "/")
            if value:
                candidate = PurePosixPath(value)
                if (
                    candidate.is_absolute()
                    or re.match(r"^(?:[A-Za-z]:/|//)", value)
                    or ".." in candidate.parts
                ):
                    raise ValueError(f"task packet contains an escaping scope path: {value}")
                paths.append(value)
    if not paths:
        raise ValueError("Allowed files section must list at least one path")
    return paths


def _validate_bytes(
    path: Path, data: bytes, *, require_scope: bool = False
) -> tuple[str, list[str]]:
    if path.suffix.casefold() != ".md":
        return "", ["task packet must be Markdown"]
    if len(data) > MAX_PACKET_BYTES:
        return "", ["task packet exceeds the size limit"]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "", ["task packet is unreadable as UTF-8"]

    findings = [label for label, pattern in FORBIDDEN_PATTERNS if pattern.search(text)]
    if require_scope:
        try:
            allowed_paths(text)
        except ValueError as exc:
            findings.append(str(exc))
    return text, findings


def _file_identity(path: Path) -> tuple[int, int, int, int]:
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("task packet is not a regular file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _read_stable(path: Path) -> bytes:
    """Read one packet while rejecting a pathname replacement during the read."""

    before = _file_identity(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        opened_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if opened_identity != before:
            raise ValueError("task packet changed while opening")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            data = stream.read(MAX_PACKET_BYTES + 1)
        after = _file_identity(path)
        if after != before:
            raise ValueError("task packet changed while reading")
        return data
    finally:
        if descriptor != -1:
            os.close(descriptor)


def seal(path: Path, output: Path, repo_root: Path, task_root: Path) -> list[str]:
    """Validate one stable packet and write the exact validated bytes once."""

    repo_root = repo_root.resolve()
    task_root = task_root.resolve()
    if path.is_symlink():
        return ["task packet must not be a symlink"]
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(task_root) or not task_root.is_relative_to(repo_root):
            return ["task packet must remain beneath the repository task directory"]
        data = _read_stable(path)
    except (OSError, RuntimeError, ValueError) as exc:
        return [str(exc)]

    _text, findings = _validate_bytes(path, data, require_scope=True)
    if findings:
        return findings

    output.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(output, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
    finally:
        if descriptor != -1:
            os.close(descriptor)
    return []


def validate(path: Path) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return ["task packet is unreadable"]
    return _validate_bytes(path, data)[1]


def main() -> int:
    expected_flags = ("--seal-output", "--repo-root", "--task-root")
    if len(sys.argv) not in {2, 8} or (
        len(sys.argv) == 8 and tuple(sys.argv[index] for index in (2, 4, 6)) != expected_flags
    ):
        print(
            "usage: validate_task_packet.py <task.md> "
            "[--seal-output <path> --repo-root <path> --task-root <path>]",
            file=sys.stderr,
        )
        return 2
    packet = Path(sys.argv[1])
    if len(sys.argv) == 8:
        output = Path(sys.argv[3])
        repo_root = Path(sys.argv[5])
        task_root = Path(sys.argv[7])
        findings = seal(packet, output, repo_root, task_root)
    else:
        findings = validate(packet)
    if findings:
        print("unsafe task packet: " + ", ".join(findings), file=sys.stderr)
        return 1
    print("task packet safety check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
