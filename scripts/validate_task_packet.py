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
_READ_ONLY_SECTION_NAMES = {"read-only files:", "read-only files/paths:"}
_DO_NOT_TOUCH_SECTION_NAMES = {"do not touch:"}
_FORBIDDEN_CAPABILITY_SECTION_NAMES = {"forbidden commands/capabilities:"}
_HEAD_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_BRANCH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]+$")
_FORBIDDEN_SCOPE_MARKERS = (
    ".git",
    ".env",
    "wordpress",
    "barnd",
    "shield",
    "ssh",
    "credential",
    "secret",
)
_REQUIRED_FORBIDDEN_MARKERS = ("network", "credential", "production", "deployment")
_REQUIRED_PACKET_FIELDS: tuple[tuple[str, str], ...] = (
    ("phase", "Phase"),
    ("issue", "Issue"),
    ("goal", "Goal"),
    ("coding lane", "Coding lane"),
    ("worker host", "Worker host"),
    ("model provider", "Model provider"),
    ("codex spark quota involved", "Codex Spark quota involved"),
    ("openai api involved", "OpenAI API involved"),
    ("deepseek api involved", "DeepSeek API involved"),
    ("repository root", "Repository root"),
    ("base sha", "Expected base SHA"),
)
_DIRECT_DEEPSEEK_FIELDS = {
    "coding lane": "DIRECT_DEEPSEEK",
    "worker host": "PROMPT_OLA_VPS",
    "model provider": "DEEPSEEK_API",
    "codex spark quota involved": "NO",
    "openai api involved": "NO",
    "deepseek api involved": "YES",
}
_ALLOWED_CODING_LANES = {"SPARK", "DIRECT_DEEPSEEK"}
_ALLOWED_WORKER_HOSTS = {"CODEX_RUNTIME", "PROMPT_OLA_VPS"}
_ALLOWED_MODEL_PROVIDERS = {"OPENAI_INCLUDED_CODEX", "DEEPSEEK_API"}
_BOOLEAN_VALUES = {"YES", "NO"}


def _section_items(text: str, names: set[str]) -> list[str]:
    lines = text.splitlines()
    try:
        start = next(index for index, line in enumerate(lines) if line.strip().casefold() in names)
    except StopIteration as exc:
        raise ValueError(f"task packet must contain a {'/'.join(sorted(names))} section") from exc

    items: list[str] = []
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if not stripped:
            if items:
                break
            continue
        if stripped.endswith(":") and not stripped.startswith("-"):
            break
        if stripped.startswith("-"):
            value = stripped[1:].strip().strip("`")
            if value:
                items.append(value)
    if not items:
        raise ValueError(f"section {sorted(names)[0]!r} must list at least one item")
    return items


def _optional_section_items(text: str, names: set[str]) -> list[str]:
    if not any(line.strip().casefold() in names for line in text.splitlines()):
        return []
    return _section_items(text, names)


def _scope_path_errors(paths: list[str]) -> list[str]:
    findings: list[str] = []
    for raw_path in paths:
        value = raw_path.replace("\\", "/")
        candidate = PurePosixPath(value)
        if (
            candidate.is_absolute()
            or re.match(r"^(?:[A-Za-z]:/|//)", value)
            or ".." in candidate.parts
            or not re.fullmatch(r"[A-Za-z0-9._/*-]+", value)
        ):
            findings.append(f"task packet contains an invalid scope path: {raw_path}")
            continue
        lowered = value.casefold()
        if any(marker in lowered for marker in _FORBIDDEN_SCOPE_MARKERS):
            findings.append(f"task packet scope names a forbidden path: {raw_path}")
    return findings


def _field_values(text: str, field_names: tuple[str, ...]) -> list[str]:
    """Read one-line packet fields while accepting the documented ':'/'=' forms."""

    values: list[str] = []
    normalized_names = tuple(name.casefold() for name in field_names)
    for line in text.splitlines():
        stripped = line.strip()
        lowered = stripped.casefold()
        for name in normalized_names:
            if not lowered.startswith(name):
                continue
            remainder = stripped[len(name) :]
            if remainder.startswith((":", "=")):
                values.append(remainder[1:].strip())
            break
    return values


def _packet_metadata_errors(text: str) -> list[str]:
    """Enforce the routing metadata that the worker receives and reports."""

    findings: list[str] = []
    fields: dict[str, str] = {}
    labels = dict(_REQUIRED_PACKET_FIELDS)
    for key, label in _REQUIRED_PACKET_FIELDS:
        names = (label,)
        values = _field_values(text, names)
        if len(values) != 1 or not values[0]:
            findings.append(f"task packet must declare exactly one {label} field")
            continue
        fields[key] = values[0]

    coding_lane = fields.get("coding lane", "")
    if coding_lane and coding_lane not in _ALLOWED_CODING_LANES:
        findings.append("task packet Coding lane must be SPARK or DIRECT_DEEPSEEK")

    worker_host = fields.get("worker host", "")
    if worker_host and worker_host not in _ALLOWED_WORKER_HOSTS:
        findings.append("task packet Worker host must be CODEX_RUNTIME or PROMPT_OLA_VPS")

    model_provider = fields.get("model provider", "")
    if model_provider and model_provider not in _ALLOWED_MODEL_PROVIDERS:
        findings.append("task packet Model provider must be OPENAI_INCLUDED_CODEX or DEEPSEEK_API")

    for key, label in (
        ("codex spark quota involved", "Codex Spark quota involved"),
        ("openai api involved", "OpenAI API involved"),
        ("deepseek api involved", "DeepSeek API involved"),
    ):
        value = fields.get(key, "")
        if value and value not in _BOOLEAN_VALUES:
            findings.append(f"task packet {label} must be YES or NO")

    if coding_lane == "DIRECT_DEEPSEEK":
        for key, expected in _DIRECT_DEEPSEEK_FIELDS.items():
            actual = fields.get(key)
            if actual is not None and actual != expected:
                findings.append(
                    f"direct DeepSeek task packet must declare {labels[key]}={expected}"
                )
    return findings


def _validate_context(
    text: str,
    *,
    expected_head: str | None = None,
    expected_branch: str | None = None,
) -> list[str]:
    findings: list[str] = _packet_metadata_errors(text)
    lines = [line.strip() for line in text.splitlines()]

    target_values = [
        line.split("=", 1)[1].strip() for line in lines if line.casefold().startswith("target=")
    ]
    target_values.extend(
        line.split(":", 1)[1].strip() for line in lines if line.casefold().startswith("target:")
    )
    if target_values != ["AppCare"]:
        findings.append("task packet must declare exactly TARGET=AppCare")

    repository_values = [
        line.split(":", 1)[1].strip()
        for line in lines
        if line.casefold().startswith("repository root:")
    ]
    if repository_values != ["."]:
        findings.append("task packet repository root must be exactly .")

    branch_values = [
        line.split(":", 1)[1].strip() for line in lines if line.casefold().startswith("branch:")
    ]
    if len(branch_values) != 1 or not _BRANCH_PATTERN.fullmatch(branch_values[0]):
        findings.append("task packet must declare one safe, non-detached branch")
    elif expected_branch is not None and branch_values[0] != expected_branch:
        findings.append("task packet branch does not match the coordinator branch")

    head_values = _field_values(text, ("Expected base SHA",))
    if len(head_values) != 1 or not _HEAD_PATTERN.fullmatch(head_values[0].casefold()):
        findings.append("task packet must declare one full Git HEAD SHA")
    elif expected_head is not None and head_values[0].casefold() != expected_head.casefold():
        findings.append("task packet HEAD does not match the coordinator HEAD")

    try:
        scope_paths = allowed_paths(text)
    except ValueError as exc:
        findings.append(str(exc))
    else:
        findings.extend(_scope_path_errors(scope_paths))

    findings.extend(_scope_path_errors(_optional_section_items(text, _READ_ONLY_SECTION_NAMES)))

    try:
        do_not_touch = _section_items(text, _DO_NOT_TOUCH_SECTION_NAMES)
    except ValueError as exc:
        findings.append(str(exc))
    else:
        joined = " ".join(do_not_touch).casefold()
        if "wordpress security" not in joined:
            findings.append("Do not touch section must explicitly exclude WordPress Security")

    try:
        forbidden_capabilities = _section_items(text, _FORBIDDEN_CAPABILITY_SECTION_NAMES)
    except ValueError as exc:
        findings.append(str(exc))
    else:
        joined = " ".join(forbidden_capabilities).casefold()
        for marker in _REQUIRED_FORBIDDEN_MARKERS:
            if marker not in joined:
                findings.append(f"forbidden commands/capabilities section must include {marker}")
    return findings


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


def read_only_paths(text: str) -> list[str]:
    """Parse optional paths the worker may inspect but must not modify."""

    return _optional_section_items(text, _READ_ONLY_SECTION_NAMES)


def _validate_bytes(
    path: Path,
    data: bytes,
    *,
    require_scope: bool = False,
    require_context: bool = False,
    expected_head: str | None = None,
    expected_branch: str | None = None,
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
    if require_context:
        findings.extend(
            finding
            for finding in _validate_context(
                text,
                expected_head=expected_head,
                expected_branch=expected_branch,
            )
            if finding not in findings
        )
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


def seal(
    path: Path,
    output: Path,
    repo_root: Path,
    task_root: Path,
    *,
    expected_head: str | None = None,
    expected_branch: str | None = None,
) -> list[str]:
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

    _text, findings = _validate_bytes(
        path,
        data,
        require_scope=True,
        require_context=True,
        expected_head=expected_head,
        expected_branch=expected_branch,
    )
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
    expected_flags = (
        "--seal-output",
        "--repo-root",
        "--task-root",
        "--expected-head",
        "--expected-branch",
    )
    if len(sys.argv) not in {2, 12} or (
        len(sys.argv) == 12
        and tuple(sys.argv[index] for index in (2, 4, 6, 8, 10)) != expected_flags
    ):
        print(
            "usage: validate_task_packet.py <task.md> "
            "[--seal-output <path> --repo-root <path> --task-root <path> "
            "--expected-head <sha> --expected-branch <branch>]",
            file=sys.stderr,
        )
        return 2
    packet = Path(sys.argv[1])
    if len(sys.argv) == 12:
        output = Path(sys.argv[3])
        repo_root = Path(sys.argv[5])
        task_root = Path(sys.argv[7])
        findings = seal(
            packet,
            output,
            repo_root,
            task_root,
            expected_head=sys.argv[9],
            expected_branch=sys.argv[11],
        )
    else:
        findings = validate(packet)
    if findings:
        print("unsafe task packet: " + ", ".join(findings), file=sys.stderr)
        return 1
    print("task packet safety check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
