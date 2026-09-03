"""Verify the direct DeepSeek worker's static isolation contract."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REQUIRED_SOURCE_MARKERS = (
    'DEEPSEEK_CHAT_ENDPOINT = f"{DEEPSEEK_API_ORIGIN}/chat/completions"',
    'DEEPSEEK_API_KEY_PATH = Path("/etc/securityola/appcare-deepseek-worker/deepseek-api-key")',
    'DEEPSEEK_MODEL_PATH = Path("/etc/securityola/appcare-deepseek-worker/model")',
    "ProxyHandler({})",
    "class _NoRedirectHandler",
    'getattr(os, "O_NOFOLLOW", 0)',
    "_assert_non_root()",
    "_assert_virtualenv()",
    '"--no-local",',
    '"--no-hardlinks",',
    '"--no-checkout",',
    "def request_completion(",
    "def execute_stored_worker(",
    '"apply",',
    '"--check"',
    "scan_worker_changes.scan",
    "run_deterministic_tests",
    "resource_limits_applied",
    "temporary_worker_state_removed",
    "api_key_logged",
    "production_touched",
    "_claim_run_id",
    "_atomic_create",
    "_TEST_IDENTITY_USER",
    "_TEST_IDENTITY_GROUP",
    "isolate_to_test_identity",
    "test_root",
)
FORBIDDEN_SOURCE_MARKERS = (
    "api.openai.com",
    "openrouter",
    "localhost",
    "127.0.0.1",
    "os.system(",
    "shell=True",
    "eval(",
    "exec(",
    "execute_worker(",
)
REQUIRED_API_SERVICE_MARKERS = (
    "User=appcare-deepseek-api",
    "Group=appcare-deepseek-worker",
    "SupplementaryGroups=appcare-deepseek-api",
    "WorkingDirectory=/opt/securityola/appcare-deepseek-worker/repository",
    "/opt/securityola/appcare-deepseek-worker/venv/bin/python",
    "request --task-file",
    "--run-id %i",
    "NoNewPrivileges=true",
    "PrivateTmp=true",
    "PrivateDevices=true",
    "ProtectSystem=strict",
    "ProtectHome=true",
    "ReadOnlyPaths=/etc/securityola/appcare-deepseek-worker",
    "ReadWritePaths=/var/lib/securityola/appcare-deepseek-worker",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    "CapabilityBoundingSet=",
)
REQUIRED_WORKER_SERVICE_MARKERS = (
    "Requires=securityola-appcare-deepseek-api@%i.service",
    "User=appcare-deepseek-worker",
    "Group=appcare-deepseek-worker",
    "WorkingDirectory=/opt/securityola/appcare-deepseek-worker/repository",
    "/opt/securityola/appcare-deepseek-worker/venv/bin/python",
    "apply --run-id %i",
    "NoNewPrivileges=true",
    "PrivateTmp=true",
    "PrivateNetwork=true",
    "ProtectSystem=strict",
    "ProtectHome=true",
    "ProtectProc=invisible",
    "ProcSubset=pid",
    "ReadWritePaths=/var/lib/securityola/appcare-deepseek-worker",
    "RestrictAddressFamilies=AF_UNIX",
    "CapabilityBoundingSet=CAP_SETUID CAP_SETGID",
    "AmbientCapabilities=CAP_SETUID CAP_SETGID",
    "InaccessiblePaths=/etc/securityola/appcare-deepseek-worker/deepseek-api-key",
    "TasksMax=64",
    "MemoryMax=1G",
    "CPUQuota=100%",
    "LimitNOFILE=256",
    "LimitNPROC=64",
    "RestrictSUIDSGID=true",
)


def _call_name(node: ast.Call) -> str:
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return ""


def _ast_findings(tree: ast.AST) -> list[str]:
    findings: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name in {"system", "eval", "exec"}:
            findings.append(f"forbidden dynamic execution call: {name}")
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                if keyword.value.value is True:
                    findings.append("subprocess shell execution is enabled")
    return findings


def _systemd_path_values(service: str, directive: str) -> tuple[str, ...]:
    values: list[str] = []
    prefix = f"{directive}="
    for raw_line in service.splitlines():
        line = raw_line.strip()
        if line.startswith(prefix):
            values.extend(line[len(prefix) :].split())
    return tuple(values)


def _exact_paths(actual: tuple[str, ...], expected: tuple[str, ...]) -> bool:
    return len(actual) == len(expected) and set(actual) == set(expected)


def verify(root: Path) -> list[str]:
    source_path = root / "scripts" / "direct_deepseek_worker.py"
    api_service_path = root / "ops" / "worker" / "securityola-appcare-deepseek-api@.service"
    worker_service_path = root / "ops" / "worker" / "securityola-appcare-deepseek-worker@.service"
    findings: list[str] = []
    try:
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(source_path))
        api_service = api_service_path.read_text(encoding="utf-8")
        worker_service = worker_service_path.read_text(encoding="utf-8")
    except (OSError, SyntaxError):
        return ["direct worker source or service units are unreadable"]
    findings.extend(_ast_findings(tree))
    for marker in REQUIRED_SOURCE_MARKERS:
        if marker not in source:
            findings.append(f"missing direct worker guard: {marker}")
    for marker in FORBIDDEN_SOURCE_MARKERS:
        if marker in source.casefold():
            findings.append(f"forbidden direct worker marker: {marker}")
    for marker in REQUIRED_API_SERVICE_MARKERS:
        if marker not in api_service:
            findings.append(f"missing direct API service guard: {marker}")
    for marker in REQUIRED_WORKER_SERVICE_MARKERS:
        if marker not in worker_service:
            findings.append(f"missing direct worker service guard: {marker}")
    if not _exact_paths(
        _systemd_path_values(api_service, "ReadOnlyPaths"),
        ("/etc/securityola/appcare-deepseek-worker",),
    ):
        findings.append("direct API service ReadOnlyPaths must match the key directory exactly")
    if not _exact_paths(
        _systemd_path_values(api_service, "ReadWritePaths"),
        ("/var/lib/securityola/appcare-deepseek-worker",),
    ):
        findings.append("direct API service ReadWritePaths must match the state root exactly")
    if not _exact_paths(
        _systemd_path_values(worker_service, "ReadOnlyPaths"),
        (),
    ):
        findings.append("apply worker ReadOnlyPaths must be empty")
    if not _exact_paths(
        _systemd_path_values(worker_service, "ReadWritePaths"),
        ("/var/lib/securityola/appcare-deepseek-worker",),
    ):
        findings.append("apply worker ReadWritePaths must match the state root exactly")
    if not _exact_paths(
        _systemd_path_values(
            worker_service,
            "InaccessiblePaths",
        ),
        ("/etc/securityola/appcare-deepseek-worker/deepseek-api-key",),
    ):
        findings.append("apply worker InaccessiblePaths must hide the API key exactly")
    if "DEEPSEEK_API_KEY" in api_service or "Authorization=" in api_service:
        findings.append("API service unit must not contain credential material")
    worker_access_lines = "\n".join(
        line for line in worker_service.splitlines() if not line.startswith("InaccessiblePaths=")
    )
    if (
        "deepseek-api-key" in worker_access_lines.casefold()
        or "Authorization=" in worker_access_lines
        or "AF_INET" in worker_access_lines
        or "request --task-file" in worker_access_lines
    ):
        findings.append("apply worker service must not access the API or credential")
    return findings


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    findings = verify(root)
    if findings:
        print("Direct-worker policy verification failed:")
        print("\n".join(findings))
        return 1
    print(
        "Direct-worker policy verification passed: fixed endpoint and isolated controls are present"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
