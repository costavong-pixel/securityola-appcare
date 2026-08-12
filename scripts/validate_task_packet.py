"""Reject secrets and private infrastructure data before a task reaches a worker."""

from __future__ import annotations

import re
import sys
from pathlib import Path

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
            r"(?i)\b(?:password|secret|token|api[_-]?key|authorization|cookie)\s*[:=]\s*(?:['\"][^'\"]{8,}['\"]|[^\s#]{8,})"
        ),
    ),
    ("private IPv4 address", re.compile(_PRIVATE_IPV4)),
)


def validate(path: Path) -> list[str]:
    if path.suffix.casefold() != ".md":
        return ["task packet must be Markdown"]
    if path.stat().st_size > MAX_PACKET_BYTES:
        return ["task packet exceeds the size limit"]
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ["task packet is unreadable as UTF-8"]

    findings: list[str] = []
    for label, pattern in FORBIDDEN_PATTERNS:
        if pattern.search(text):
            findings.append(label)
    return findings


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_task_packet.py <task.md>", file=sys.stderr)
        return 2
    findings = validate(Path(sys.argv[1]))
    if findings:
        print("unsafe task packet: " + ", ".join(findings), file=sys.stderr)
        return 1
    print("task packet safety check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
