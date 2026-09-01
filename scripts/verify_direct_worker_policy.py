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
    '"worktree",\n            "add",',
    '"apply",',
    '"--check"',
    "scan_worker_changes.scan",
    "run_deterministic_tests",
    "resource_limits_applied",
    "temporary_worker_state_removed",
    "api_key_logged",
    "production_touched",
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
)
REQUIRED_SERVICE_MARKERS = (
    "User=appcare-deepseek-worker",
    "Group=appcare-deepseek-worker",
    "WorkingDirectory=/opt/securityola/appcare-deepseek-worker/repository",
    "/opt/securityola/appcare-deepseek-worker/venv/bin/python",
    "-I -B",
    "NoNewPrivileges=true",
    "PrivateTmp=true",
    "ProtectSystem=strict",
    "ProtectHome=true",
    "ReadWritePaths=/var/lib/securityola/appcare-deepseek-worker",
    "RestrictAddressFamilies=AF_INET AF_INET6",
    "CapabilityBoundingSet=",
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


def verify(root: Path) -> list[str]:
    source_path = root / "scripts" / "direct_deepseek_worker.py"
    service_path = root / "ops" / "worker" / "securityola-appcare-deepseek-worker@.service"
    findings: list[str] = []
    try:
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(source_path))
        service = service_path.read_text(encoding="utf-8")
    except (OSError, SyntaxError):
        return ["direct worker source or service unit is unreadable"]
    findings.extend(_ast_findings(tree))
    for marker in REQUIRED_SOURCE_MARKERS:
        if marker not in source:
            findings.append(f"missing direct worker guard: {marker}")
    for marker in FORBIDDEN_SOURCE_MARKERS:
        if marker in source.casefold():
            findings.append(f"forbidden direct worker marker: {marker}")
    for marker in REQUIRED_SERVICE_MARKERS:
        if marker not in service:
            findings.append(f"missing direct worker service guard: {marker}")
    if "DEEPSEEK_API_KEY" in service or "Authorization=" in service:
        findings.append("service unit must not contain credential material")
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
