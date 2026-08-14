"""Generate a task-specific deny-by-default OpenCode policy before launch."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .validate_task_packet import allowed_paths, read_only_paths

_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/*-]+$")
_EDIT_ROOTS = ("appcare", "tests", "docs")
_FORBIDDEN_EDIT_PREFIXES = (
    ".codex",
    ".env",
    ".github",
    ".opencode",
    "docs/security",
    "wordpress",
    "barnd",
    "shield",
    "ssh",
)
_FIXED_READS = (
    "AGENTS.md",
    "BETA_LOOP.md",
    "PRODUCT.md",
    "ARCHITECTURE.md",
    "DEVELOPMENT.md",
    "SECURITY.md",
    "WORKER_PROTOCOL.md",
    "CODEX_START.md",
    "CODEX_BOOTSTRAP.md",
)
_EXACT_BASH_ALLOWS = (
    "git status --short --branch",
    "git diff --no-ext-diff --check",
    "git log --oneline -5",
    "git show --stat --oneline HEAD",
    "git branch --show-current",
    "ruff check appcare scripts tests",
    "ruff format --check appcare scripts tests",
    "mypy appcare scripts tests",
)


def _validate_read_paths(paths: list[str]) -> list[str]:
    findings: list[str] = []
    for path in paths:
        normalized = path.replace("\\", "/")
        if (
            not _SAFE_PATH.fullmatch(normalized)
            or normalized.startswith("/")
            or ".." in Path(normalized).parts
        ):
            findings.append(f"task read path is not safe: {path}")
            continue
        lowered = normalized.casefold()
        if any(
            marker in lowered for marker in (".git", ".env", "wordpress", "barnd", "shield", "ssh")
        ):
            findings.append(f"worker read path is forbidden: {path}")
    return findings


def _validate_edit_paths(paths: list[str]) -> list[str]:
    findings: list[str] = []
    for path in paths:
        normalized = path.replace("\\", "/")
        if not _SAFE_PATH.fullmatch(normalized):
            findings.append(f"task path is not safe for a worker policy: {path}")
            continue
        if normalized.startswith("/") or ".." in Path(normalized).parts:
            findings.append(f"task path escapes the repository: {path}")
            continue
        if not any(normalized == root or normalized.startswith(root + "/") for root in _EDIT_ROOTS):
            findings.append(f"worker edit path is outside approved source/test/docs roots: {path}")
        lowered = normalized.casefold()
        if any(
            lowered == prefix or lowered.startswith(prefix + "/")
            for prefix in _FORBIDDEN_EDIT_PREFIXES
        ):
            findings.append(f"worker edit path is forbidden: {path}")
    return findings


def render(task: Path) -> str:
    task_text = task.read_text(encoding="utf-8")
    paths = allowed_paths(task_text)
    read_only = read_only_paths(task_text)
    read_findings = _validate_read_paths(read_only)
    if read_findings:
        raise ValueError("; ".join(read_findings))
    findings = _validate_edit_paths(paths)
    if findings:
        raise ValueError("; ".join(findings))

    read_paths = list(dict.fromkeys((*_FIXED_READS, *read_only, *paths)))
    lines = [
        "---",
        "description: Task-scoped deny-by-default AppCare worker policy",
        "mode: primary",
        "model: opencode/deepseek-v4-flash-free",
        "temperature: 0.1",
        "permission:",
        '  "*": deny',
        "  read:",
        '    "*": deny',
    ]
    lines.extend(f"    {json.dumps(path)}: allow" for path in read_paths)
    lines.extend(
        [
            '    "*.env": deny',
            '    "*.env.*": deny',
            '    "*.pem": deny',
            '    "*.key": deny',
            "  edit:",
            '    "*": deny',
        ]
    )
    lines.extend(f"    {json.dumps(path)}: allow" for path in paths)
    lines.extend(
        [
            '    "docs/security/*": deny',
            '    "*.env": deny',
            '    "*.env.*": deny',
            '    "*.pem": deny',
            '    "*.key": deny',
            "  glob: deny",
            "  grep: deny",
            "  lsp: deny",
            "  external_directory: deny",
            "  question: deny",
            "  webfetch: deny",
            "  websearch: deny",
            "  task: deny",
            "  skill: deny",
            "  doom_loop: deny",
            "  bash:",
            '    "*": deny',
        ]
    )
    lines.extend(f"    {json.dumps(command)}: allow" for command in _EXACT_BASH_ALLOWS)
    lines.extend(["---", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        rendered = render(args.task)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    except (OSError, ValueError) as exc:
        print(f"task policy generation failed: {exc}", file=sys.stderr)
        return 1
    print("task-scoped worker policy generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
