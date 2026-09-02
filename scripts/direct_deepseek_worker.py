"""Isolated, direct DeepSeek API worker for bounded AppCare task packets.

This module is deliberately independent of the OpenCode launcher.  It accepts
only a sealed coordinator packet, talks to the fixed DeepSeek endpoint, and
returns a validated patch bundle.  The model never supplies a command,
endpoint, path, or test command to this process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, OpenerDirector, ProxyHandler, Request, build_opener

if __package__ in {None, ""}:
    # The production service starts this file with Python isolated mode.  The
    # repository root is added explicitly so the existing packet/scope tools
    # can be reused without importing any customer application code.
    _repository_for_import = Path(__file__).resolve().parents[1]
    if str(_repository_for_import) not in sys.path:
        sys.path.insert(0, str(_repository_for_import))

from scripts import (  # noqa: E402, I001
    scan_worker_changes,
    validate_task_packet,
    verify_task_scope,
)


DEEPSEEK_API_ORIGIN = "https://api.deepseek.com"
DEEPSEEK_CHAT_ENDPOINT = f"{DEEPSEEK_API_ORIGIN}/chat/completions"
DEEPSEEK_API_KEY_PATH = Path("/etc/securityola/appcare-deepseek-worker/deepseek-api-key")
DEEPSEEK_MODEL_PATH = Path("/etc/securityola/appcare-deepseek-worker/model")
WORKER_REPOSITORY_ROOT = Path("/opt/securityola/appcare-deepseek-worker/repository")
WORKER_STATE_ROOT = Path("/var/lib/securityola/appcare-deepseek-worker")

MAX_API_KEY_BYTES = 256
MAX_MODEL_BYTES = 128
MAX_PACKET_PROMPT_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_TEXT_BYTES = 1 * 1024 * 1024
MAX_DIFF_BYTES = 2 * 1024 * 1024
MAX_PATCH_FILES = 64
MAX_SUMMARY_BYTES = 4 * 1024
MAX_LIST_ITEMS = 32
MAX_LIST_ITEM_BYTES = 512
MAX_PROCESS_OUTPUT_BYTES = 256 * 1024
MAX_TEST_TIMEOUT_SECONDS = 900
MAX_API_TIMEOUT_SECONDS = 120

_SAFE_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SAFE_RELATIVE_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
_SAFE_BRANCH = re.compile(r"^[A-Za-z0-9._/-]+$")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIFF_HEADER = re.compile(r"^diff --git a/([^\t\r\n ]+) b/([^\t\r\n ]+)$")
_PATCH_FILE_HEADER = re.compile(r"^(?:---|\+\+\+) (.+?)(?:\t.*)?$")
_FORBIDDEN_PATH_MARKERS = (
    ".git",
    ".env",
    "wordpress",
    "woocommerce",
    "production",
    "deploy",
    "credential",
    "secret",
)
_WORKTREE_PREFIX = "securityola-appcare-worker."
_REQUESTS_DIRECTORY = "requests"
_RESULTS_DIRECTORY = "results"
_TASK_FILENAME = "task.md"
_COMPLETION_FILENAME = "completion.json"
_RUN_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")

_OUTPUT_KEYS = frozenset(
    {
        "analysis_summary",
        "files_to_change",
        "unified_diff",
        "tests_to_run",
        "risks",
        "assumptions",
    }
)


class WorkerError(RuntimeError):
    """A sanitized, reportable worker failure code."""

    def __init__(self, code: str) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,79}", code):
            code = "worker_failed"
        self.code = code
        super().__init__(code)


class ResponseOpener(Protocol):
    def open(self, request: Request, *, timeout: float) -> object:
        """Open one fixed endpoint without exposing request details."""


@dataclass(frozen=True)
class DeepSeekCompletion:
    content: str
    actual_model: str


@dataclass(frozen=True)
class WorkerOutput:
    analysis_summary: str
    files_to_change: tuple[str, ...]
    unified_diff: str
    tests_to_run: tuple[str, ...]
    risks: tuple[str, ...]
    assumptions: tuple[str, ...]


@dataclass(frozen=True)
class TaskPacket:
    text: str
    branch: str
    expected_head: str
    allowed_paths: tuple[str, ...]


@dataclass(frozen=True)
class StoredRequest:
    packet: TaskPacket
    output: WorkerOutput
    actual_model: str
    api_auth: str
    api_response: str


@dataclass(frozen=True)
class ProcessStatus:
    returncode: int
    timed_out: bool
    output_limited: bool
    resource_limits_applied: bool


@dataclass
class WorkerWorkspace:
    run_id: str
    run_root: Path
    worktree: Path
    cleanup_status: str = "NOT_RUN"


@dataclass(frozen=True)
class WorkerReceipt:
    schema_version: int
    run_id: str
    status: str
    failure_code: str | None
    endpoint: str
    requested_model: str
    actual_model: str | None
    model_attested: str
    routing_metadata_validated: str
    base_sha: str
    branch: str
    files_to_change: tuple[str, ...]
    patch_sha256: str | None
    tests: str
    secret_scan: str
    api_auth: str
    api_response: str
    openai_api_request_count: int
    spark_worker_request_count: int
    codex_spark_quota_involved: str
    openai_api_involved: str
    deepseek_api_involved: str
    api_key_logged: str
    api_key_in_task_packet: str
    api_key_in_git: str
    api_key_in_ci: str
    production_touched: str
    temporary_worker_state_removed: str
    cleanup_status: str


def _failure(code: str) -> WorkerError:
    return WorkerError(code)


def _assert_non_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise _failure("worker_must_not_run_as_root")


def _assert_virtualenv() -> None:
    if sys.prefix == sys.base_prefix:
        raise _failure("isolated_virtualenv_required")


def _secure_path(path: Path, *, field: str, require_root_owner: bool) -> tuple[os.stat_result, ...]:
    """Validate every fixed-path component without following symlinks."""

    if not path.is_absolute() or path.is_symlink():
        raise _failure(f"{field}_path_invalid")
    components = path.parts
    if len(components) < 2:
        raise _failure(f"{field}_path_invalid")
    inspected: list[os.stat_result] = []
    current = Path(path.anchor)
    for component in components[1:-1]:
        current /= component
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise _failure(f"{field}_path_unavailable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise _failure(f"{field}_parent_invalid")
        if require_root_owner and info.st_mode & 0o022:
            raise _failure(f"{field}_parent_writable")
        if require_root_owner and hasattr(os, "getuid") and info.st_uid != 0:
            raise _failure(f"{field}_parent_owner_invalid")
        inspected.append(info)
    return tuple(inspected)


def _read_trusted_file(
    path: Path,
    *,
    field: str,
    maximum_bytes: int,
    require_root_owner: bool,
    reject_other_read: bool,
) -> bytes:
    _secure_path(path, field=field, require_root_owner=require_root_owner)
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise _failure(f"{field}_unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise _failure(f"{field}_file_invalid")
    if before.st_mode & 0o022 or (reject_other_read and before.st_mode & 0o004):
        raise _failure(f"{field}_file_permissions_invalid")
    if require_root_owner and hasattr(os, "getuid") and before.st_uid != 0:
        raise _failure(f"{field}_file_owner_invalid")
    if before.st_size > maximum_bytes:
        raise _failure(f"{field}_too_large")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _failure(f"{field}_unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise _failure(f"{field}_changed")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise _failure(f"{field}_too_large")
        try:
            after = os.lstat(path)
        except OSError as exc:
            raise _failure(f"{field}_changed") from exc
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise _failure(f"{field}_changed")
        return b"".join(chunks)
    except OSError as exc:
        raise _failure(f"{field}_unavailable") from exc
    finally:
        os.close(descriptor)


def load_api_key(path: Path = DEEPSEEK_API_KEY_PATH, *, require_root_owner: bool = True) -> str:
    """Load the API key only from the fixed protected file boundary."""

    raw = _read_trusted_file(
        path,
        field="deepseek_api_key",
        maximum_bytes=MAX_API_KEY_BYTES,
        require_root_owner=require_root_owner,
        reject_other_read=True,
    )
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise _failure("deepseek_api_key_invalid") from exc
    if not value or any(character.isspace() or ord(character) < 32 for character in value):
        raise _failure("deepseek_api_key_invalid")
    if len(value) > MAX_API_KEY_BYTES:
        raise _failure("deepseek_api_key_invalid")
    return value


def load_model(path: Path = DEEPSEEK_MODEL_PATH, *, require_root_owner: bool = True) -> str:
    raw = _read_trusted_file(
        path,
        field="deepseek_model",
        maximum_bytes=MAX_MODEL_BYTES,
        require_root_owner=require_root_owner,
        reject_other_read=False,
    )
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise _failure("deepseek_model_invalid") from exc
    if _SAFE_MODEL.fullmatch(value) is None:
        raise _failure("deepseek_model_invalid")
    return value


def validate_endpoint(endpoint: str) -> str:
    if endpoint != DEEPSEEK_CHAT_ENDPOINT:
        raise _failure("deepseek_endpoint_rejected")
    try:
        parsed = urlsplit(endpoint)
    except ValueError as exc:
        raise _failure("deepseek_endpoint_rejected") from exc
    if parsed.scheme != "https" or parsed.hostname != "api.deepseek.com" or parsed.port is not None:
        raise _failure("deepseek_endpoint_rejected")
    return endpoint


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self,
        request: Request,
        _response: object,
        _code: int,
        _message: str,
        _headers: object,
    ) -> None:
        del request
        raise _failure("deepseek_redirect_rejected")


def _direct_opener() -> OpenerDirector:
    # An empty ProxyHandler disables HTTP(S)_PROXY and ALL_PROXY environment
    # processing.  Redirects are rejected rather than followed.
    return build_opener(ProxyHandler({}), _NoRedirectHandler())


def _read_bounded(stream: BinaryIO, maximum_bytes: int) -> bytes:
    raw = stream.read(maximum_bytes + 1)
    if len(raw) > maximum_bytes:
        raise _failure("deepseek_response_too_large")
    return raw


def _secret_labels(text: str) -> tuple[str, ...]:
    findings: list[str] = []
    for label, pattern in validate_task_packet.FORBIDDEN_PATTERNS:
        if pattern.search(text):
            findings.append(label)
    return tuple(findings)


def _assert_secret_free(text: str, *, code: str) -> None:
    if _secret_labels(text):
        raise _failure(code)


class DirectDeepSeekClient:
    """Small OpenAI-compatible client pinned to api.deepseek.com only."""

    def __init__(
        self,
        *,
        model: str,
        api_key_loader: Callable[[], str] = load_api_key,
        endpoint: str = DEEPSEEK_CHAT_ENDPOINT,
        opener: ResponseOpener | None = None,
        timeout_seconds: int = MAX_API_TIMEOUT_SECONDS,
    ) -> None:
        self.endpoint = validate_endpoint(endpoint)
        if _SAFE_MODEL.fullmatch(model) is None:
            raise _failure("deepseek_model_invalid")
        if timeout_seconds < 1 or timeout_seconds > MAX_API_TIMEOUT_SECONDS:
            raise _failure("deepseek_timeout_invalid")
        self.model = model
        self._api_key_loader = api_key_loader
        self._opener = opener or _direct_opener()
        self.timeout_seconds = timeout_seconds

    def complete(self, prompt: str) -> DeepSeekCompletion:
        if not prompt or len(prompt.encode("utf-8")) > MAX_PACKET_PROMPT_BYTES:
            raise _failure("task_prompt_invalid")
        _assert_secret_free(prompt, code="task_prompt_contains_secret")
        api_key = self._api_key_loader()
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "stream": False,
        }
        request = Request(  # noqa: S310 - the endpoint is validated above
            self.endpoint,
            data=json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        del api_key
        response: object | None = None
        try:
            response = self._opener.open(request, timeout=float(self.timeout_seconds))
            status = int(getattr(response, "status", 200))
            raw = _read_bounded(cast(BinaryIO, response), MAX_RESPONSE_BYTES)
        except HTTPError as exc:
            try:
                exc.close()
            except OSError:
                pass
            raise _failure("deepseek_http_error") from exc
        except (OSError, URLError, TimeoutError) as exc:
            raise _failure("deepseek_transport_error") from exc
        finally:
            if response is not None:
                close = getattr(response, "close", None)
                if callable(close):
                    close()
        if status < 200 or status >= 300:
            raise _failure("deepseek_http_error")
        try:
            decoded = raw.decode("utf-8")
            document = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _failure("deepseek_response_invalid") from exc
        if not isinstance(document, dict):
            raise _failure("deepseek_response_invalid")
        choices = document.get("choices")
        if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
            raise _failure("deepseek_response_invalid")
        message = choices[0].get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise _failure("deepseek_response_invalid")
        content = message["content"]
        if len(content.encode("utf-8")) > MAX_RESPONSE_TEXT_BYTES:
            raise _failure("deepseek_response_too_large")
        actual_model = document.get("model")
        if not isinstance(actual_model, str) or _SAFE_MODEL.fullmatch(actual_model) is None:
            raise _failure("deepseek_response_invalid")
        return DeepSeekCompletion(content=content, actual_model=actual_model)


def _bounded_text(value: object, *, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _failure(f"worker_output_{field}_invalid")
    value = value.strip()
    if len(value.encode("utf-8")) > maximum or "\x00" in value:
        raise _failure(f"worker_output_{field}_invalid")
    _assert_secret_free(value, code="worker_output_contains_secret")
    return value


def _bounded_text_list(value: object, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        raise _failure(f"worker_output_{field}_invalid")
    values: list[str] = []
    for item in value:
        values.append(_bounded_text(item, field=field, maximum=MAX_LIST_ITEM_BYTES))
    return tuple(values)


def _validate_relative_path(value: object, *, allowed_paths: Sequence[str]) -> str:
    if not isinstance(value, str):
        raise _failure("worker_output_path_invalid")
    normalized = value.replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if (
        _SAFE_RELATIVE_PATH.fullmatch(normalized) is None
        or candidate.is_absolute()
        or ".." in candidate.parts
        or "\\" in value
        or candidate.as_posix() != normalized
        or any(marker in normalized.casefold() for marker in _FORBIDDEN_PATH_MARKERS)
        or not verify_task_scope.path_allowed(normalized, list(allowed_paths))
    ):
        raise _failure("worker_output_path_out_of_scope")
    return normalized


def _diff_paths(diff: str) -> tuple[str, ...]:
    paths: list[str] = []
    headers = 0
    for line in diff.splitlines():
        if line.startswith("GIT binary patch") or line.startswith("Binary files "):
            raise _failure("worker_output_binary_patch_rejected")
        if line.startswith("deleted file mode") or line.startswith("similarity index"):
            raise _failure("worker_output_delete_or_rename_rejected")
        match = _DIFF_HEADER.fullmatch(line)
        if match is not None:
            headers += 1
            left, right = match.groups()
            if left != right or left.startswith("/") or "\\" in left:
                raise _failure("worker_output_diff_path_invalid")
            paths.append(left)
    if headers == 0 or len(paths) > MAX_PATCH_FILES:
        raise _failure("worker_output_diff_invalid")
    if len(set(paths)) != len(paths):
        raise _failure("worker_output_duplicate_path")
    file_headers = [
        match.group(1)
        for line in diff.splitlines()
        if (match := _PATCH_FILE_HEADER.fullmatch(line))
    ]
    for header in file_headers:
        if header == "/dev/null":
            continue
        path = header[2:] if header[:2] in {"a/", "b/"} else header
        if not _SAFE_RELATIVE_PATH.fullmatch(path) or ".." in PurePosixPath(path).parts:
            raise _failure("worker_output_diff_path_invalid")
    return tuple(paths)


def _strip_json_fence(content: str) -> str:
    stripped = content.strip()
    if stripped.startswith("```") or stripped.endswith("```"):
        raise _failure("worker_output_must_be_json")
    return stripped


def parse_worker_output(content: str, *, allowed_paths: Sequence[str]) -> WorkerOutput:
    try:
        document = json.loads(_strip_json_fence(content))
    except json.JSONDecodeError as exc:
        raise _failure("worker_output_must_be_json") from exc
    if not isinstance(document, dict) or set(document) != _OUTPUT_KEYS:
        raise _failure("worker_output_schema_invalid")
    summary = _bounded_text(
        document["analysis_summary"], field="analysis_summary", maximum=MAX_SUMMARY_BYTES
    )
    files_raw = document["files_to_change"]
    if not isinstance(files_raw, list) or not files_raw or len(files_raw) > MAX_PATCH_FILES:
        raise _failure("worker_output_files_invalid")
    files = tuple(_validate_relative_path(item, allowed_paths=allowed_paths) for item in files_raw)
    if len(set(files)) != len(files):
        raise _failure("worker_output_duplicate_path")
    diff = document["unified_diff"]
    if not isinstance(diff, str) or not diff.strip() or len(diff.encode("utf-8")) > MAX_DIFF_BYTES:
        raise _failure("worker_output_diff_invalid")
    if "\x00" in diff:
        raise _failure("worker_output_diff_invalid")
    _assert_secret_free(diff, code="worker_output_contains_secret")
    diff_files = _diff_paths(diff)
    if set(diff_files) != set(files):
        raise _failure("worker_output_files_do_not_match_diff")
    return WorkerOutput(
        analysis_summary=summary,
        files_to_change=files,
        unified_diff=diff,
        tests_to_run=_bounded_text_list(document["tests_to_run"], field="tests"),
        risks=_bounded_text_list(document["risks"], field="risks"),
        assumptions=_bounded_text_list(document["assumptions"], field="assumptions"),
    )


def _packet_from_sealed_text(text: str, *, expected_head: str, expected_branch: str) -> TaskPacket:
    if not text or len(text.encode("utf-8")) > validate_task_packet.MAX_PACKET_BYTES:
        raise _failure("task_packet_invalid")
    _assert_secret_free(text, code="task_packet_contains_secret")
    _validated_text, findings = validate_task_packet._validate_bytes(
        Path("sealed-task.md"),
        text.encode("utf-8"),
        require_scope=True,
        require_context=True,
        expected_head=expected_head,
        expected_branch=expected_branch,
    )
    if findings:
        raise _failure("task_packet_rejected")
    branch = _field(text, "Branch")
    head = _field(text, "Expected base SHA").casefold()
    try:
        allowed = tuple(validate_task_packet.allowed_paths(text))
    except ValueError as exc:
        raise _failure("task_packet_scope_invalid") from exc
    if head != expected_head.casefold() or branch != expected_branch:
        raise _failure("task_packet_context_changed")
    return TaskPacket(text=text, branch=branch, expected_head=head, allowed_paths=allowed)


def _completion_document(output: WorkerOutput, *, actual_model: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "actual_model": actual_model,
        "api_auth": "PASS",
        "api_response": "PASS",
        "analysis_summary": output.analysis_summary,
        "files_to_change": list(output.files_to_change),
        "unified_diff": output.unified_diff,
        "tests_to_run": list(output.tests_to_run),
        "risks": list(output.risks),
        "assumptions": list(output.assumptions),
    }


def _parse_completion_document(
    text: str, *, allowed_paths: Sequence[str]
) -> tuple[WorkerOutput, str, str, str]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _failure("worker_completion_invalid") from exc
    expected_keys = _OUTPUT_KEYS | {"schema_version", "actual_model", "api_auth", "api_response"}
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise _failure("worker_completion_invalid")
    if document.get("schema_version") != 1:
        raise _failure("worker_completion_invalid")
    actual_model = document.get("actual_model")
    if not isinstance(actual_model, str) or _SAFE_MODEL.fullmatch(actual_model) is None:
        raise _failure("worker_completion_invalid")
    api_auth = document.get("api_auth")
    api_response = document.get("api_response")
    if api_auth != "PASS" or api_response != "PASS":
        raise _failure("worker_completion_invalid")
    output_document = {key: document[key] for key in _OUTPUT_KEYS}
    output = parse_worker_output(
        json.dumps(output_document, separators=(",", ":")),
        allowed_paths=allowed_paths,
    )
    _assert_secret_free(text, code="worker_completion_contains_secret")
    return output, actual_model, api_auth, api_response


def _field(text: str, label: str) -> str:
    values = [
        line[len(label) + 1 :].strip()
        for line in text.splitlines()
        if line.casefold().startswith(label.casefold() + ":")
    ]
    if len(values) != 1 or not values[0]:
        raise _failure("task_packet_context_invalid")
    return values[0]


def seal_task_packet(
    path: Path,
    *,
    repo_root: Path,
    output: Path,
    expected_head: str,
    expected_branch: str,
) -> TaskPacket:
    task_root = repo_root / ".codex" / "tasks"
    findings = validate_task_packet.seal(
        path,
        output,
        repo_root,
        task_root,
        expected_head=expected_head,
        expected_branch=expected_branch,
    )
    if findings:
        raise _failure("task_packet_rejected")
    try:
        text = output.read_text(encoding="utf-8")
        os.chmod(output, 0o660)
    except OSError as exc:
        raise _failure("task_packet_write_failed") from exc
    return _packet_from_sealed_text(
        text,
        expected_head=expected_head,
        expected_branch=expected_branch,
    )


def _git_path() -> str:
    executable = shutil.which("git")
    if executable is None:
        raise _failure("git_unavailable")
    return str(Path(executable).resolve(strict=True))


def _run_process(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    environment: Mapping[str, str] | None = None,
    limit_resources: bool = False,
) -> ProcessStatus:
    if not command or any(not isinstance(item, str) or not item for item in command):
        raise _failure("fixed_command_invalid")
    try:
        process = subprocess.Popen(  # noqa: S603 - command is created by fixed worker code
            list(command),
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        raise _failure("fixed_command_unavailable") from exc
    stdout = bytearray()
    stderr = bytearray()
    overflow = [False]

    def collect(stream: BinaryIO | None, target: bytearray) -> None:
        if stream is None:
            return
        while True:
            chunk = stream.read(16_384)
            if not chunk:
                return
            if len(target) + len(chunk) > MAX_PROCESS_OUTPUT_BYTES:
                overflow[0] = True
                return
            target.extend(chunk)

    readers = [
        threading.Thread(target=collect, args=(process.stdout, stdout), daemon=True),
        threading.Thread(target=collect, args=(process.stderr, stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    resource_limits_applied = True
    if limit_resources:
        resource_limits_applied = _apply_resource_limits(process.pid)
        if not resource_limits_applied:
            _terminate_process(process)
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    while process.poll() is None:
        if overflow[0] or time.monotonic() >= deadline:
            timed_out = not overflow[0]
            _terminate_process(process)
            break
        time.sleep(0.01)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _kill_process(process)
        process.wait(timeout=10)
    for reader in readers:
        reader.join(timeout=2)
    return ProcessStatus(
        returncode=int(process.returncode or 0),
        timed_out=timed_out,
        output_limited=overflow[0],
        resource_limits_applied=resource_limits_applied,
    )


def _apply_resource_limits(pid: int) -> bool:
    if os.name == "nt":
        return False
    try:
        import resource

        resource_api = cast(Any, resource)
        prlimit = getattr(resource_api, "prlimit", None)
        if prlimit is None:
            return False
        limits = (
            (resource_api.RLIMIT_CPU, 900),
            (resource_api.RLIMIT_AS, 1_073_741_824),
            (resource_api.RLIMIT_FSIZE, 16 * 1024 * 1024),
        )
        for resource_kind, maximum in limits:
            prlimit(pid, resource_kind, (maximum, maximum))
    except (ImportError, OSError, ValueError):
        return False
    return True


def _terminate_process(process: subprocess.Popen[bytes]) -> None:  # noqa: S603
    try:
        if os.name != "nt":
            cast(Any, os).killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except (OSError, ProcessLookupError):
        pass


def _kill_process(process: subprocess.Popen[bytes]) -> None:  # noqa: S603
    try:
        if os.name != "nt":
            cast(Any, os).killpg(process.pid, cast(Any, signal).SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        pass


def _git_command(*arguments: str) -> tuple[str, ...]:
    return (_git_path(), *arguments)


def _git_status(repo_root: Path) -> tuple[str, str, str]:
    head_text = _git_scalar(repo_root, ("rev-parse", "HEAD"), maximum_bytes=64)
    branch_text = _git_scalar(repo_root, ("branch", "--show-current"), maximum_bytes=512)
    dirty = False
    for arguments in (
        ("diff", "--quiet"),
        ("diff", "--cached", "--quiet"),
    ):
        result = _run_process(
            _git_command("-C", str(repo_root), *arguments),
            cwd=repo_root,
            timeout_seconds=30,
            environment=_git_environment(repo_root),
        )
        if result.timed_out or result.output_limited or result.returncode > 1:
            raise _failure("coordinator_git_state_unavailable")
        dirty = dirty or result.returncode == 1
    dirty = dirty or _git_has_output(
        repo_root,
        ("ls-files", "--others", "--exclude-standard", "-z"),
    )
    if (
        _FULL_SHA.fullmatch(head_text.casefold()) is None
        or _SAFE_BRANCH.fullmatch(branch_text) is None
    ):
        raise _failure("coordinator_git_state_invalid")
    return head_text.casefold(), branch_text, "dirty" if dirty else ""


def _git_scalar(repo_root: Path, arguments: Sequence[str], *, maximum_bytes: int) -> str:
    try:
        process = subprocess.Popen(  # noqa: S603 - arguments are fixed by this module
            list(_git_command("-C", str(repo_root), *arguments)),
            cwd=repo_root,
            env=_git_environment(repo_root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        raise _failure("coordinator_git_state_unavailable") from exc
    try:
        output = process.stdout.read(maximum_bytes + 1) if process.stdout is not None else b""
        process.wait(timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        _terminate_process(process)
        raise _failure("coordinator_git_state_unavailable") from exc
    if process.returncode != 0 or len(output) > maximum_bytes:
        raise _failure("coordinator_git_state_unavailable")
    try:
        return output.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise _failure("coordinator_git_state_invalid") from exc


def _git_has_output(repo_root: Path, arguments: Sequence[str]) -> bool:
    try:
        process = subprocess.Popen(  # noqa: S603 - arguments are fixed by this module
            list(_git_command("-C", str(repo_root), *arguments)),
            cwd=repo_root,
            env=_git_environment(repo_root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        raise _failure("coordinator_git_state_unavailable") from exc
    try:
        first = process.stdout.read(1) if process.stdout is not None else b""
        if first:
            _terminate_process(process)
        process.wait(timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        _terminate_process(process)
        raise _failure("coordinator_git_state_unavailable") from exc
    if not first and process.returncode != 0:
        raise _failure("coordinator_git_state_unavailable")
    return bool(first)


def _git_environment(repo_root: Path) -> dict[str, str]:
    return {
        "PATH": os.pathsep.join((str(Path(sys.executable).resolve().parent), "/usr/bin", "/bin")),
        "HOME": str(repo_root),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _validate_worker_roots(repo_root: Path, state_root: Path) -> tuple[Path, Path]:
    if repo_root.is_symlink() or state_root.is_symlink():
        raise _failure("worker_root_symlink")
    try:
        repo = repo_root.resolve(strict=True)
    except OSError as exc:
        raise _failure("worker_repository_unavailable") from exc
    if not repo.is_dir():
        raise _failure("worker_repository_invalid")
    lowered = repo.as_posix().casefold()
    if any(marker in lowered for marker in ("wordpress", "woocommerce", "production", "deploy")):
        raise _failure("worker_repository_boundary")
    expected_parent = WORKER_REPOSITORY_ROOT.parent.resolve(strict=False)
    if not repo.is_relative_to(expected_parent):
        raise _failure("worker_repository_boundary")
    state = state_root.resolve(strict=False)
    if state != WORKER_STATE_ROOT:
        raise _failure("worker_state_boundary")
    state_created = not state.exists()
    state.mkdir(parents=True, exist_ok=True, mode=0o770)
    if state_created:
        try:
            os.chmod(state, 0o770)  # noqa: S103 - shared state is group-restricted
        except OSError as exc:
            raise _failure("worker_state_invalid") from exc
    if state.is_symlink() or not state.is_dir():
        raise _failure("worker_state_invalid")
    try:
        state_mode = stat.S_IMODE(os.lstat(state).st_mode)
    except OSError as exc:
        raise _failure("worker_state_invalid") from exc
    if state_mode & 0o007 or state_mode & 0o070 != 0o070:
        raise _failure("worker_state_permissions_invalid")
    return repo, state


def _ensure_directory(path: Path, *, mode: int, code: str) -> None:
    if path.is_symlink() or path.exists() and not path.is_dir():
        raise _failure(code)
    created = not path.exists()
    try:
        path.mkdir(parents=True, exist_ok=True, mode=mode)
        if created:
            os.chmod(path, mode)
    except OSError as exc:
        raise _failure(code) from exc
    if path.is_symlink() or not path.is_dir():
        raise _failure(code)
    try:
        directory_mode = stat.S_IMODE(os.lstat(path).st_mode)
    except OSError as exc:
        raise _failure(code) from exc
    if directory_mode & 0o007:
        raise _failure(code)


def _ensure_shared_state(state_root: Path) -> None:
    directory = state_root / _REQUESTS_DIRECTORY
    _ensure_directory(directory, mode=0o770, code="worker_state_invalid")
    try:
        directory_mode = stat.S_IMODE(os.lstat(directory).st_mode)
    except OSError as exc:
        raise _failure("worker_state_invalid") from exc
    if directory_mode & 0o007 or directory_mode & 0o070 != 0o070:
        raise _failure("worker_state_permissions_invalid")


def _validate_run_id(run_id: str) -> str:
    if _RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise _failure("worker_run_id_invalid")
    return run_id


@contextmanager
def _one_writer_lock(path: Path) -> Iterator[None]:
    if path.is_symlink():
        raise _failure("worker_lock_invalid")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o770)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o660)
    except OSError as exc:
        raise _failure("worker_lock_unavailable") from exc
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt_api = cast(Any, msvcrt)
            try:
                msvcrt_api.locking(descriptor, msvcrt_api.LK_NBLCK, 1)
            except OSError as exc:
                raise _failure("worker_already_running") from exc
        else:
            import fcntl

            fcntl_api = cast(Any, fcntl)
            try:
                fcntl_api.flock(descriptor, fcntl_api.LOCK_EX | fcntl_api.LOCK_NB)
            except OSError as exc:
                raise _failure("worker_already_running") from exc
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt_api = cast(Any, msvcrt)
                msvcrt_api.locking(descriptor, msvcrt_api.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl_api = cast(Any, fcntl)
                fcntl_api.flock(descriptor, fcntl_api.LOCK_UN)
        except OSError:
            pass
        os.close(descriptor)


def _new_run_root(state_root: Path) -> tuple[str, Path]:
    runs = state_root / "runs"
    runs.mkdir(parents=True, exist_ok=True, mode=0o700)
    if runs.is_symlink() or not runs.is_dir():
        raise _failure("worker_run_root_invalid")
    run_id = uuid.uuid4().hex
    run_root = runs / f"{_WORKTREE_PREFIX}{run_id}"
    run_root.mkdir(mode=0o700)
    return run_id, run_root


def _new_request_root(state_root: Path, run_id: str) -> Path:
    _validate_run_id(run_id)
    requests = state_root / _REQUESTS_DIRECTORY
    _ensure_directory(requests, mode=0o770, code="worker_state_invalid")
    request_root = requests / run_id
    if request_root.is_symlink() or request_root.exists():
        raise _failure("worker_request_already_exists")
    try:
        request_root.mkdir(mode=0o770)
    except OSError as exc:
        raise _failure("worker_request_create_failed") from exc
    if request_root.is_symlink() or not request_root.is_dir():
        raise _failure("worker_request_invalid")
    return request_root


def _read_shared_file(path: Path, *, maximum_bytes: int, code: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise _failure(code)
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise _failure(code) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise _failure(code)
    if before.st_mode & 0o002 or before.st_size > maximum_bytes:
        raise _failure(code)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _failure(code) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise _failure(code)
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise _failure(code)
        after = os.lstat(path)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise _failure(code)
        return b"".join(chunks)
    except OSError as exc:
        raise _failure(code) from exc
    finally:
        os.close(descriptor)


def _cleanup_request_root(state_root: Path, run_id: str) -> bool:
    _validate_run_id(run_id)
    requests = state_root / _REQUESTS_DIRECTORY
    root = requests / run_id
    if (
        requests.is_symlink()
        or not requests.is_dir()
        or root.is_symlink()
        or not root.is_dir()
        or root.parent != requests
    ):
        return False
    try:
        shutil.rmtree(root)
    except OSError:
        return False
    return not root.exists() and not root.is_symlink()


def _remove_worktree(repo_root: Path, workspace: WorkerWorkspace) -> bool:
    del repo_root
    worktree = workspace.worktree
    if worktree.parent != workspace.run_root:
        return False
    if worktree.is_symlink():
        return False
    if not worktree.exists():
        return True
    if not worktree.is_dir():
        return False
    try:
        shutil.rmtree(worktree)
    except OSError:
        return False
    return not worktree.exists() and not worktree.is_symlink()


def _cleanup_run_root(workspace: WorkerWorkspace) -> bool:
    root = workspace.run_root
    parent = root.parent
    if (
        parent.name != "runs"
        or not parent.is_dir()
        or root.name[: len(_WORKTREE_PREFIX)] != _WORKTREE_PREFIX
    ):
        return False
    if root.is_symlink():
        return False
    try:
        shutil.rmtree(root)
    except OSError:
        return False
    return not root.exists()


def _create_worktree(repo_root: Path, workspace: WorkerWorkspace, expected_head: str) -> None:
    if workspace.worktree.exists() or workspace.worktree.is_symlink():
        raise _failure("worker_worktree_invalid")
    result = _run_process(
        _git_command(
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--no-local",
            "--no-hardlinks",
            "--no-checkout",
            "--",
            str(repo_root),
            str(workspace.worktree),
        ),
        cwd=repo_root,
        timeout_seconds=90,
        environment=_git_environment(repo_root),
    )
    if result.returncode != 0 or result.timed_out or result.output_limited:
        raise _failure("worker_worktree_create_failed")
    if workspace.worktree.is_symlink() or not workspace.worktree.is_dir():
        raise _failure("worker_worktree_invalid")
    checkout = _run_process(
        _git_command(
            "-C",
            str(workspace.worktree),
            "-c",
            "core.hooksPath=/dev/null",
            "checkout",
            "--detach",
            expected_head,
        ),
        cwd=workspace.worktree,
        timeout_seconds=90,
        environment=_git_environment(workspace.worktree),
    )
    if checkout.returncode != 0 or checkout.timed_out or checkout.output_limited:
        raise _failure("worker_worktree_create_failed")


def _copy_sealed_packet(worktree: Path, packet: TaskPacket) -> Path:
    if worktree.is_symlink() or not worktree.is_dir():
        raise _failure("worker_worktree_invalid")
    codex_directory = worktree / ".codex"
    tasks_directory = codex_directory / "tasks"
    for directory in (codex_directory, tasks_directory):
        if directory.is_symlink() or directory.exists() and not directory.is_dir():
            raise _failure("worker_task_directory_invalid")
        directory.mkdir(exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise _failure("worker_task_directory_invalid")
    task_path = tasks_directory / "direct-worker-task.md"
    if task_path.is_symlink() or task_path.exists():
        raise _failure("worker_task_copy_failed")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(task_path, flags, 0o600)
    except OSError as exc:
        raise _failure("worker_task_copy_failed") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            descriptor = -1
            stream.write(packet.text)
            stream.flush()
    finally:
        if descriptor != -1:
            os.close(descriptor)
    return task_path


def _apply_diff(worktree: Path, run_root: Path, diff: str) -> None:
    patch_path = run_root / "validated.patch"
    patch_path.write_text(diff, encoding="utf-8", newline="")
    os.chmod(patch_path, 0o600)
    for check in (True, False):
        arguments = [
            "-C",
            str(worktree),
            "apply",
            "--recount",
            "--whitespace=error-all",
        ]
        if check:
            arguments.append("--check")
        arguments.append(str(patch_path))
        result = _run_process(
            _git_command(*arguments),
            cwd=worktree,
            timeout_seconds=60,
            environment=_git_environment(worktree),
        )
        if result.returncode != 0 or result.timed_out or result.output_limited:
            raise _failure(
                "worker_patch_apply_failed" if not check else "worker_patch_check_failed"
            )


def _changed_paths(before: Mapping[str, object], after: Mapping[str, object]) -> tuple[str, ...]:
    before_files = before.get("files")
    after_files = after.get("files")
    if not isinstance(before_files, dict) or not isinstance(after_files, dict):
        raise _failure("worker_scope_snapshot_invalid")
    return tuple(
        sorted(
            path
            for path in set(before_files) | set(after_files)
            if before_files.get(path) != after_files.get(path)
        )
    )


def _validate_applied_scope(
    worktree: Path,
    *,
    before_path: Path,
    task_path: Path,
    expected_paths: Sequence[str],
) -> None:
    violations = verify_task_scope.verify(worktree, before_path, task_path)
    if violations:
        raise _failure("worker_scope_violation")
    before = json.loads(before_path.read_text(encoding="utf-8"))
    after = verify_task_scope.snapshot(worktree)
    changed = _changed_paths(before, after)
    if set(changed) != set(expected_paths):
        raise _failure("worker_scope_diff_mismatch")
    after_files = after.get("files")
    if not isinstance(after_files, dict):
        raise _failure("worker_scope_snapshot_invalid")
    for path in changed:
        entry = after_files.get(path)
        if not isinstance(entry, dict) or entry.get("kind") != "file":
            raise _failure("worker_non_regular_change")


def _run_secret_scan(worktree: Path, before_path: Path) -> None:
    status, _message = scan_worker_changes.scan(worktree, before_path)
    if status != 0:
        raise _failure("worker_secret_scan_failed")


def _test_environment(worktree: Path) -> dict[str, str]:
    executable = str(Path(sys.executable).resolve(strict=True))
    bin_directory = str(Path(executable).parent)
    return {
        "PATH": os.pathsep.join((bin_directory, "/usr/local/bin", "/usr/bin", "/bin")),
        "HOME": str(worktree / ".worker-home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TARGET": "AppCare",
        "APPCARE_DIRECT_DEEPSEEK_WORKER": "1",
    }


def run_deterministic_tests(
    worktree: Path, *, timeout_seconds: int = MAX_TEST_TIMEOUT_SECONDS
) -> None:
    if timeout_seconds < 30 or timeout_seconds > MAX_TEST_TIMEOUT_SECONDS:
        raise _failure("test_timeout_invalid")
    commands = (
        (sys.executable, "-m", "ruff", "format", "--check", "appcare", "scripts", "tests"),
        (sys.executable, "-m", "ruff", "check", "appcare", "scripts", "tests"),
        (sys.executable, "-m", "mypy", "appcare", "scripts", "tests"),
        (sys.executable, "-m", "pytest", "-q"),
    )
    environment = _test_environment(worktree)
    for command in commands:
        result = _run_process(
            command,
            cwd=worktree,
            timeout_seconds=timeout_seconds,
            environment=environment,
            limit_resources=True,
        )
        if (
            result.returncode != 0
            or result.timed_out
            or result.output_limited
            or not result.resource_limits_applied
        ):
            raise _failure("deterministic_tests_failed")


def _atomic_write(
    path: Path,
    payload: bytes,
    *,
    directory_mode: int = 0o700,
    file_mode: int = 0o600,
) -> None:
    if path.is_symlink() or path.exists() and not path.is_file():
        raise _failure("worker_result_path_invalid")
    if path.parent.exists() and path.parent.is_symlink():
        raise _failure("worker_result_path_invalid")
    path.parent.mkdir(parents=True, exist_ok=True, mode=directory_mode)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise _failure("worker_result_path_invalid")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        file_mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, file_mode)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if temporary.exists() or temporary.is_symlink():
            try:
                temporary.unlink()
            except OSError:
                pass


def _receipt_bytes(receipt: WorkerReceipt) -> bytes:
    payload = {
        key: (list(value) if isinstance(value, tuple) else value)
        for key, value in receipt.__dict__.items()
    }
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _write_result_bundle(
    state_root: Path,
    *,
    receipt: WorkerReceipt,
    patch: str | None,
) -> Path:
    result_directory = state_root / _RESULTS_DIRECTORY
    if result_directory.is_symlink():
        raise _failure("worker_result_path_invalid")
    result_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if result_directory.is_symlink() or not result_directory.is_dir():
        raise _failure("worker_result_path_invalid")
    os.chmod(result_directory, 0o700)
    receipt_path = result_directory / f"{receipt.run_id}.json"
    if patch is not None:
        patch_path = result_directory / f"{receipt.run_id}.patch"
        _atomic_write(patch_path, patch.encode("utf-8"))
    _atomic_write(receipt_path, _receipt_bytes(receipt))
    return receipt_path


def _base_receipt(
    *,
    run_id: str,
    base_sha: str,
    branch: str,
    model: str,
    failure_code: str | None = None,
    status: str = "FAILED",
    actual_model: str | None = None,
    routing_metadata_validated: str = "NO",
    files: tuple[str, ...] = (),
    patch_sha256: str | None = None,
    tests: str = "NOT_RUN",
    scan_status: str = "NOT_RUN",
    api_auth: str = "NOT_RUN",
    api_response: str = "NOT_RUN",
    cleanup_status: str = "NOT_RUN",
    temporary_worker_state_removed: str = "NO",
) -> WorkerReceipt:
    return WorkerReceipt(
        schema_version=1,
        run_id=run_id,
        status=status,
        failure_code=failure_code,
        endpoint=DEEPSEEK_CHAT_ENDPOINT,
        requested_model=model,
        actual_model=actual_model,
        model_attested="YES" if actual_model == model else "NO",
        routing_metadata_validated=routing_metadata_validated,
        base_sha=base_sha,
        branch=branch,
        files_to_change=files,
        patch_sha256=patch_sha256,
        tests=tests,
        secret_scan=scan_status,
        api_auth=api_auth,
        api_response=api_response,
        openai_api_request_count=0,
        spark_worker_request_count=0,
        codex_spark_quota_involved="NO",
        openai_api_involved="NO",
        deepseek_api_involved="YES",
        api_key_logged="NO",
        api_key_in_task_packet="NO",
        api_key_in_git="NO",
        api_key_in_ci="NO",
        production_touched="NO",
        temporary_worker_state_removed=temporary_worker_state_removed,
        cleanup_status=cleanup_status,
    )


def _request_root(state_root: Path, run_id: str) -> Path:
    _validate_run_id(run_id)
    requests = state_root / _REQUESTS_DIRECTORY
    if requests.is_symlink() or not requests.is_dir():
        raise _failure("worker_state_invalid")
    root = requests / run_id
    if root.is_symlink() or not root.is_dir() or root.parent != requests:
        raise _failure("worker_request_invalid")
    return root


def _read_utf8_file(path: Path, *, maximum_bytes: int, code: str) -> str:
    try:
        raw = _read_shared_file(path, maximum_bytes=maximum_bytes, code=code)
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _failure(code) from exc


def _load_stored_request(
    state_root: Path,
    run_id: str,
    *,
    expected_head: str,
    expected_branch: str,
) -> StoredRequest:
    request_root = _request_root(state_root, run_id)
    packet = _packet_from_sealed_text(
        _read_utf8_file(
            request_root / _TASK_FILENAME,
            maximum_bytes=MAX_PACKET_PROMPT_BYTES,
            code="worker_task_artifact_invalid",
        ),
        expected_head=expected_head,
        expected_branch=expected_branch,
    )
    completion_text = _read_utf8_file(
        request_root / _COMPLETION_FILENAME,
        maximum_bytes=MAX_RESPONSE_BYTES,
        code="worker_completion_invalid",
    )
    output, actual_model, api_auth, api_response = _parse_completion_document(
        completion_text,
        allowed_paths=packet.allowed_paths,
    )
    return StoredRequest(
        packet=packet,
        output=output,
        actual_model=actual_model,
        api_auth=api_auth,
        api_response=api_response,
    )


def request_completion(
    task_file: Path,
    *,
    run_id: str,
    repo_root: Path = WORKER_REPOSITORY_ROOT,
    state_root: Path = WORKER_STATE_ROOT,
    client: DirectDeepSeekClient | None = None,
) -> Path:
    """Perform only the API stage; never apply or execute the returned patch."""

    _assert_non_root()
    _assert_virtualenv()
    repo, state = _validate_worker_roots(repo_root, state_root)
    _validate_run_id(run_id)
    _ensure_shared_state(state)
    base_sha, branch, status = _git_status(repo)
    if status:
        raise _failure("coordinator_checkout_not_clean")
    model = load_model()
    request_root: Path | None = None
    try:
        with _one_writer_lock(state / "worker.lock"):
            current_sha, current_branch, current_status = _git_status(repo)
            if current_sha != base_sha or current_branch != branch or current_status:
                raise _failure("coordinator_checkout_changed")
            request_root = _new_request_root(state, run_id)
            packet = seal_task_packet(
                task_file,
                repo_root=repo,
                output=request_root / _TASK_FILENAME,
                expected_head=base_sha,
                expected_branch=branch,
            )
            active_client = client or DirectDeepSeekClient(model=model)
            if active_client.model != model:
                raise _failure("worker_model_binding_invalid")
            completion = active_client.complete(packet.text)
            if completion.actual_model != model:
                raise _failure("worker_model_attestation_failed")
            output = parse_worker_output(completion.content, allowed_paths=packet.allowed_paths)
            _atomic_write(
                request_root / _COMPLETION_FILENAME,
                (
                    json.dumps(
                        _completion_document(output, actual_model=completion.actual_model),
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8"),
                directory_mode=0o770,
                file_mode=0o660,
            )
    except BaseException:
        if request_root is not None:
            _cleanup_request_root(state, run_id)
        raise
    if request_root is None:
        raise _failure("worker_request_failed")
    return request_root / _COMPLETION_FILENAME


def execute_stored_worker(
    run_id: str,
    *,
    repo_root: Path = WORKER_REPOSITORY_ROOT,
    state_root: Path = WORKER_STATE_ROOT,
    test_runner: Callable[[Path], None] = run_deterministic_tests,
    secret_scanner: Callable[[Path, Path], None] = _run_secret_scan,
) -> Path:
    """Apply a previously normalized API response in the no-network worker stage."""

    _assert_non_root()
    _assert_virtualenv()
    repo, state = _validate_worker_roots(repo_root, state_root)
    _validate_run_id(run_id)
    _ensure_shared_state(state)
    base_sha, branch, status = _git_status(repo)
    if status:
        raise _failure("coordinator_checkout_not_clean")
    disposable_id, run_root = _new_run_root(state)
    workspace = WorkerWorkspace(
        run_id=disposable_id,
        run_root=run_root,
        worktree=run_root / "worktree",
    )
    model = "unknown"
    patch: str | None = None
    receipt: WorkerReceipt | None = None
    actual_model: str | None = None
    request_existed = False
    try:
        request_existed = (state / _REQUESTS_DIRECTORY / run_id).exists()
        with _one_writer_lock(state / "worker.lock"):
            current_sha, current_branch, current_status = _git_status(repo)
            if current_sha != base_sha or current_branch != branch or current_status:
                raise _failure("coordinator_checkout_changed")
            model = load_model()
            stored = _load_stored_request(
                state,
                run_id,
                expected_head=base_sha,
                expected_branch=branch,
            )
            actual_model = stored.actual_model
            if actual_model != model:
                raise _failure("worker_model_attestation_failed")
            _create_worktree(repo, workspace, base_sha)
            task_in_worktree = _copy_sealed_packet(workspace.worktree, stored.packet)
            before = verify_task_scope.snapshot(workspace.worktree)
            before_path = run_root / "before.json"
            _atomic_write(before_path, json.dumps(before, sort_keys=True).encode("utf-8"))
            _apply_diff(workspace.worktree, run_root, stored.output.unified_diff)
            _validate_applied_scope(
                workspace.worktree,
                before_path=before_path,
                task_path=task_in_worktree,
                expected_paths=stored.output.files_to_change,
            )
            secret_scanner(workspace.worktree, before_path)
            test_runner(workspace.worktree)
            patch = stored.output.unified_diff
            receipt = _base_receipt(
                run_id=run_id,
                base_sha=base_sha,
                branch=branch,
                model=model,
                status="PASS",
                actual_model=actual_model,
                routing_metadata_validated="YES",
                files=stored.output.files_to_change,
                patch_sha256=hashlib.sha256(patch.encode("utf-8")).hexdigest(),
                tests="PASS",
                scan_status="PASS",
                api_auth=stored.api_auth,
                api_response=stored.api_response,
            )
    except WorkerError as exc:
        receipt = _base_receipt(
            run_id=run_id,
            base_sha=base_sha,
            branch=branch,
            model=model,
            failure_code=exc.code,
            actual_model=actual_model,
            routing_metadata_validated="NO",
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        receipt = _base_receipt(
            run_id=run_id,
            base_sha=base_sha,
            branch=branch,
            model=model,
            failure_code="worker_failed",
            actual_model=actual_model,
            routing_metadata_validated="NO",
        )
    finally:
        if workspace.worktree.exists() or workspace.worktree.is_symlink():
            try:
                removed_worktree = _remove_worktree(repo, workspace)
            except WorkerError:
                removed_worktree = False
        else:
            removed_worktree = True
        removed_root = _cleanup_run_root(workspace) if removed_worktree else False
        removed_request = _cleanup_request_root(state, run_id) if request_existed else True
        workspace.cleanup_status = (
            "PASS" if removed_worktree and removed_root and removed_request else "FAIL"
        )
        if receipt is not None:
            cleanup_failed = workspace.cleanup_status != "PASS"
            receipt = replace(
                receipt,
                status="FAILED" if cleanup_failed else receipt.status,
                failure_code="worker_cleanup_failed" if cleanup_failed else receipt.failure_code,
                cleanup_status=workspace.cleanup_status,
                temporary_worker_state_removed=("YES" if not cleanup_failed else "NO"),
            )
    if receipt is None:
        raise _failure("worker_failed")
    return _write_result_bundle(
        state,
        receipt=receipt,
        patch=patch if receipt.status == "PASS" else None,
    )


def check_environment(*, role: str = "api") -> int:
    try:
        _assert_non_root()
        _assert_virtualenv()
        _validate_worker_roots(WORKER_REPOSITORY_ROOT, WORKER_STATE_ROOT)
        if role not in {"api", "worker"}:
            raise _failure("worker_role_invalid")
        key_state = "NOT_ACCESSED"
        if role == "api":
            key_state = "PRESENT"
            try:
                load_api_key()
            except WorkerError:
                key_state = "ABSENT"
        model_state = "PRESENT"
        try:
            load_model()
        except WorkerError:
            model_state = "ABSENT"
        print("PYTHON_RUNTIME=PASS")
        print("VENV=PASS")
        print(f"DEEPSEEK_API_KEY={key_state}")
        print(f"DEEPSEEK_MODEL={model_state}")
        print(f"DEEPSEEK_ENDPOINT={DEEPSEEK_CHAT_ENDPOINT}")
        return 0 if model_state == "PRESENT" and (role == "worker" or key_state == "PRESENT") else 1
    except WorkerError:
        print("PYTHON_RUNTIME=FAIL")
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AppCare direct DeepSeek worker")
    subparsers = parser.add_subparsers(dest="command", required=True)
    environment_parser = subparsers.add_parser("check-environment")
    environment_parser.add_argument("--role", choices=("api", "worker"), default="api")
    request_parser = subparsers.add_parser("request")
    request_parser.add_argument("--task-file", type=Path, required=True)
    request_parser.add_argument("--run-id", required=True)
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    if args.command == "check-environment":
        return check_environment(role=args.role)
    try:
        if args.command == "request":
            completion_path = request_completion(args.task_file, run_id=args.run_id)
            print("DIRECT_DEEPSEEK_API=PASS")
            print(f"COMPLETION_ARTIFACT={completion_path.name}")
            return 0
        receipt = execute_stored_worker(args.run_id)
    except WorkerError:
        print("DIRECT_DEEPSEEK_WORKER=FAIL")
        return 1
    print("DIRECT_DEEPSEEK_WORKER=PASS")
    print(f"AUDIT_RECEIPT={receipt.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
