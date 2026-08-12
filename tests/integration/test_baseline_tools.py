import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from scripts import check_public_safety
from scripts.validate_task_packet import validate
from scripts.verify_task_scope import promote, snapshot, verify

ROOT = Path(__file__).resolve().parents[2]


def test_public_safety_cli_runs_in_an_isolated_checkout() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_public_safety.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_worker_policy_cli_runs_without_network_or_credentials() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify_worker_policy.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_public_safety_scans_ignored_task_artifacts(tmp_path: Path, monkeypatch: Any) -> None:
    task = tmp_path / ".codex" / "tasks" / "unsafe.md"
    task.parent.mkdir(parents=True)
    payload = "credential " + "ghp_" + ("1" * 32)
    task.write_text(payload, encoding="utf-8")

    def no_tracked_files(_root: Path) -> list[Path]:
        return []

    monkeypatch.setattr(check_public_safety, "tracked_files", no_tracked_files)
    findings = check_public_safety.scan(tmp_path)
    assert findings == [".codex/tasks/unsafe.md:1: GitHub token"]


def test_public_safety_does_not_treat_version_text_as_private_ip(
    tmp_path: Path, monkeypatch: Any
) -> None:
    task = tmp_path / ".codex" / "tasks" / "version.md"
    task.parent.mkdir(parents=True)
    task.write_text("supported version 10.1.2", encoding="utf-8")

    monkeypatch.setattr(check_public_safety, "tracked_files", lambda _root: [])
    assert check_public_safety.scan(tmp_path) == []


def test_task_packet_validator_rejects_private_data(tmp_path: Path) -> None:
    packet = tmp_path / "task.md"
    packet.write_text("endpoint = 'https://user:password@example.test'", encoding="utf-8")
    assert validate(packet) == ["credential URL"]


def test_task_packet_validator_allows_public_documentation_address(tmp_path: Path) -> None:
    packet = tmp_path / "task.md"
    packet.write_text("test endpoint 203.0.113.10", encoding="utf-8")
    assert validate(packet) == []


def test_public_safety_skips_binary_artifacts(tmp_path: Path, monkeypatch: Any) -> None:
    asset = tmp_path / ".codex" / "tasks" / "fixture.bin"
    asset.parent.mkdir(parents=True)
    asset.write_bytes(b"\x00\xff\x00private-looking-bytes")

    monkeypatch.setattr(check_public_safety, "tracked_files", lambda _root: [])
    assert check_public_safety.scan(tmp_path) == []


def test_task_scope_detects_out_of_scope_changes(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    allowed = root / "allowed.md"
    outside = root / "outside.md"
    allowed.write_text("before", encoding="utf-8")
    outside.write_text("original", encoding="utf-8")
    task = root / ".codex" / "tasks" / "task.md"
    task.parent.mkdir(parents=True)
    task.write_text(
        "Allowed files:\n- allowed.md\n\nDo not touch:\n- outside.md\n", encoding="utf-8"
    )

    before_path = tmp_path / "before.json"
    baseline_task = tmp_path / "task-before.md"
    before_path.write_text(json.dumps(snapshot(root)), encoding="utf-8")
    baseline_task.write_text(task.read_text(encoding="utf-8"), encoding="utf-8")
    allowed.write_text("worker change", encoding="utf-8")
    outside.write_text("unauthorized change", encoding="utf-8")
    new_file = root / "unauthorized.txt"
    new_file.write_text("new", encoding="utf-8")

    assert verify(root, before_path, task, baseline_task) == ["outside.md", "unauthorized.txt"]
    assert allowed.read_text(encoding="utf-8") == "worker change"


def test_task_scope_ignores_opencode_managed_node_modules(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    task = root / ".codex" / "tasks" / "task.md"
    task.parent.mkdir(parents=True)
    task.write_text("Allowed files/paths:\n- allowed.md\n", encoding="utf-8")

    before_path = tmp_path / "before.json"
    baseline_task = tmp_path / "task-before.md"
    before_path.write_text(json.dumps(snapshot(root)), encoding="utf-8")
    baseline_task.write_text(task.read_text(encoding="utf-8"), encoding="utf-8")
    generated = root / ".opencode" / "node_modules" / "provider" / "index.js"
    generated.parent.mkdir(parents=True)
    generated.write_text("generated", encoding="utf-8")

    assert verify(root, before_path, task, baseline_task) == []


def test_task_scope_promotes_allowed_new_tree(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    allowed = root / "allowed.md"
    allowed.write_text("before", encoding="utf-8")
    task = root / ".codex" / "tasks" / "task.md"
    task.parent.mkdir(parents=True)
    task.write_text("Allowed files/paths:\n- allowed.md\n- new-tree/**\n", encoding="utf-8")

    target = tmp_path / "target"
    shutil.copytree(root, target)
    before_path = tmp_path / "before.json"
    baseline_task = tmp_path / "task-before.md"
    before_path.write_text(json.dumps(snapshot(root)), encoding="utf-8")
    baseline_task.write_text(task.read_text(encoding="utf-8"), encoding="utf-8")
    new_file = root / "new-tree" / "child.md"
    new_file.parent.mkdir()
    new_file.write_text("created", encoding="utf-8")

    assert verify(root, before_path, task, baseline_task) == []
    assert promote(root, target, before_path, task, baseline_task) == []
    assert (target / "new-tree" / "child.md").read_text(encoding="utf-8") == "created"


def test_task_scope_uses_the_pre_worker_packet_rules(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = root / "outside.md"
    outside.write_text("original", encoding="utf-8")
    task = root / ".codex" / "tasks" / "task.md"
    task.parent.mkdir(parents=True)
    original_packet = "Allowed files/paths:\n- allowed.md\n"
    task.write_text(original_packet, encoding="utf-8")

    before_path = tmp_path / "before.json"
    baseline_task = tmp_path / "task-before.md"
    before_path.write_text(json.dumps(snapshot(root)), encoding="utf-8")
    baseline_task.write_text(original_packet, encoding="utf-8")
    task.write_text("Allowed files/paths:\n- outside.md\n", encoding="utf-8")
    outside.write_text("unauthorized change", encoding="utf-8")

    assert verify(root, before_path, task, baseline_task) == [
        ".codex/tasks/task.md",
        "outside.md",
    ]
