import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from scripts import (
    check_public_safety,
    generate_worker_policy,
    scan_worker_changes,
    verify_task_scope,
)
from scripts.check_build_lock import validate as validate_build_lock
from scripts.validate_task_packet import seal, validate
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


def test_task_packet_validator_rejects_common_snake_case_secret_names(tmp_path: Path) -> None:
    packet = tmp_path / "task.md"
    packet.write_text(
        "client_secret = 'not-a-real-secret-value'\\nsession_token: another-placeholder-value\\n",
        encoding="utf-8",
    )
    assert validate(packet) == ["generic secret assignment"]


def test_task_packet_seal_requires_scope_and_preserves_exact_bytes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    task_root = repo / ".codex" / "tasks"
    task_root.mkdir(parents=True)
    packet = task_root / "task.md"
    packet.write_bytes(
        b"TARGET=AppCare\n"
        b"Repository root: .\n"
        b"Branch: codex/test\n"
        b"HEAD: 0123456789abcdef0123456789abcdef01234567\n\n"
        b"Allowed files/paths:\n- appcare/*\n\n"
        b"Do not touch:\n- WordPress Security resources\n\n"
        b"Forbidden commands/capabilities:\n"
        b"- no network, credentials, production, or deployment\n\n"
        b"Read-only bounded review.\n"
    )
    sealed = tmp_path / "run" / "task.md"

    assert (
        seal(
            packet,
            sealed,
            repo,
            task_root,
            expected_head="0123456789abcdef0123456789abcdef01234567",
            expected_branch="codex/test",
        )
        == []
    )
    assert sealed.read_bytes() == packet.read_bytes()


def test_task_packet_seal_rejects_missing_scope(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    task_root = repo / ".codex" / "tasks"
    task_root.mkdir(parents=True)
    packet = task_root / "task.md"
    packet.write_text(
        "TARGET=AppCare\n"
        "Repository root: .\n"
        "Branch: codex/test\n"
        "HEAD: 0123456789abcdef0123456789abcdef01234567\n\n"
        "Do not touch:\n- WordPress Security resources\n\n"
        "Forbidden commands/capabilities:\n"
        "- no network, credentials, production, or deployment\n\n"
        "Read-only task without a scope.",
        encoding="utf-8",
    )

    assert seal(packet, tmp_path / "run" / "task.md", repo, task_root) == [
        "task packet must contain an Allowed files section"
    ]


def test_task_packet_seal_rejects_context_drift(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    task_root = repo / ".codex" / "tasks"
    task_root.mkdir(parents=True)
    packet = task_root / "task.md"
    packet.write_text(
        "TARGET=AppCare\n"
        "Repository root: .\n"
        "Branch: codex/test\n"
        "HEAD: 0123456789abcdef0123456789abcdef01234567\n\n"
        "Allowed files/paths:\n- tests/*\n\n"
        "Do not touch:\n- WordPress Security resources\n\n"
        "Forbidden commands/capabilities:\n"
        "- no network, credentials, production, or deployment\n",
        encoding="utf-8",
    )
    findings = seal(
        packet,
        tmp_path / "run" / "task.md",
        repo,
        task_root,
        expected_head="fedcba9876543210fedcba9876543210fedcba98",
        expected_branch="codex/other",
    )
    assert findings == [
        "task packet branch does not match the coordinator branch",
        "task packet HEAD does not match the coordinator HEAD",
    ]


def test_task_specific_policy_binds_read_and_edit_paths(tmp_path: Path) -> None:
    task = tmp_path / "task.md"
    task.write_text(
        "Allowed files/paths:\n- tests/*\n"
        "\nRead-only files/paths:\n- scripts/check_build_lock.py\n",
        encoding="utf-8",
    )
    policy = generate_worker_policy.render(task)
    assert '"tests/*": allow' in policy
    assert '"scripts/check_build_lock.py": allow' in policy
    assert 'edit:\n    "*": deny' in policy
    assert '"docs/security/*": deny' in policy


def test_task_specific_policy_rejects_security_document_edits(tmp_path: Path) -> None:
    task = tmp_path / "task.md"
    task.write_text("Allowed files/paths:\n- docs/security/*\n", encoding="utf-8")
    try:
        generate_worker_policy.render(task)
    except ValueError as exc:
        assert "forbidden" in str(exc)
    else:
        raise AssertionError("security documentation path unexpectedly accepted")


def test_worker_secret_scan_fails_closed_when_gitleaks_is_missing(
    tmp_path: Path, monkeypatch: Any
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    changed = root / "changed.txt"
    changed.write_text("fake fixture", encoding="utf-8")
    before = snapshot(root)
    changed.write_text("worker fixture", encoding="utf-8")
    before_path = tmp_path / "before.json"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    monkeypatch.setattr(scan_worker_changes, "find_scanner", lambda: None)

    code, message = scan_worker_changes.scan(root, before_path)
    assert code == 127
    assert message == "worker secret scan unavailable: gitleaks is not installed"


def test_worker_secret_scan_redacts_report_and_does_not_log_values(
    tmp_path: Path, monkeypatch: Any
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    changed = root / "changed.txt"
    changed.write_text("before", encoding="utf-8")
    before = snapshot(root)
    changed.write_text("after", encoding="utf-8")
    before_path = tmp_path / "before.json"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    monkeypatch.setattr(scan_worker_changes, "find_scanner", lambda: "gitleaks")
    captured: dict[str, list[str]] = {}

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        report = Path(command[command.index("--report-path") + 1])
        report.write_text('[{"Description":"redacted fixture"}]', encoding="utf-8")
        return subprocess.CompletedProcess(command, 1, "secret-value", "secret-value")

    monkeypatch.setattr(scan_worker_changes, "execute_scanner", fake_run)
    code, message = scan_worker_changes.scan(root, before_path)

    assert code == 1
    assert message == "worker secret scan rejected 1 finding(s)"
    assert "--redact" in captured["command"]


def test_build_lock_accepts_fresh_hashed_inputs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools==84.0.0", "wheel==0.48.0"]\n',
        encoding="utf-8",
    )
    (repo / "requirements-dev.txt").write_text(
        "setuptools==84.0.0\nwheel==0.48.0\n", encoding="utf-8"
    )
    (repo / "requirements-dev.lock").write_text(
        "# appcare-lock-input-sha256: "
        + "0" * 64
        + "\nsetuptools==84.0.0 \\\n    --hash=sha256:"
        + "1" * 64
        + "\nwheel==0.48.0 \\\n    --hash=sha256:"
        + "2" * 64
        + "\n",
        encoding="utf-8",
    )
    from scripts.check_build_lock import input_digest

    lock = (repo / "requirements-dev.lock").read_text(encoding="utf-8")
    (repo / "requirements-dev.lock").write_text(
        lock.replace("0" * 64, input_digest(repo)), encoding="utf-8"
    )
    assert validate_build_lock(repo)[0].startswith("build lock is fresh:")


def test_build_lock_rejects_stale_declared_build_requirements(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools==84.0.0"]\n', encoding="utf-8"
    )
    (repo / "requirements-dev.txt").write_text("setuptools==84.0.0\n", encoding="utf-8")
    from scripts.check_build_lock import input_digest

    (repo / "requirements-dev.lock").write_text(
        "# appcare-lock-input-sha256: "
        + input_digest(repo)
        + "\nsetuptools==84.0.0 \\\n    --hash=sha256:"
        + "1" * 64
        + "\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools==84.0.1"]\n', encoding="utf-8"
    )
    assert any("input digest is stale" in error for error in validate_build_lock(repo))


def test_build_lock_rejects_fake_stale_input_metadata(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools==84.0.0"]\n', encoding="utf-8"
    )
    (repo / "requirements-dev.txt").write_text("setuptools==84.0.0\n", encoding="utf-8")
    (repo / "requirements-dev.lock").write_text(
        "# appcare-lock-input-sha256: "
        + "0" * 64
        + "\nsetuptools==84.0.0 \\\n    --hash=sha256:"
        + "1" * 64
        + "\n",
        encoding="utf-8",
    )
    errors = validate_build_lock(repo)
    assert any("input digest is stale" in error for error in errors)


def test_build_lock_rejects_missing_locked_build_requirement(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools==84.0.0"]\n', encoding="utf-8"
    )
    (repo / "requirements-dev.txt").write_text(
        "setuptools==84.0.0\nwheel==0.48.0\n", encoding="utf-8"
    )
    from scripts.check_build_lock import input_digest

    (repo / "requirements-dev.lock").write_text(
        "# appcare-lock-input-sha256: "
        + input_digest(repo)
        + "\nsetuptools==84.0.0 \\\n    --hash=sha256:"
        + "1" * 64
        + "\n",
        encoding="utf-8",
    )
    errors = validate_build_lock(repo)
    assert any("lock is missing wheel==0.48.0" in error for error in errors)


def test_build_lock_rejects_mismatched_locked_build_requirement(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools==84.0.0"]\n', encoding="utf-8"
    )
    (repo / "requirements-dev.txt").write_text("setuptools==84.0.0\n", encoding="utf-8")
    from scripts.check_build_lock import input_digest

    (repo / "requirements-dev.lock").write_text(
        "# appcare-lock-input-sha256: "
        + input_digest(repo)
        + "\nsetuptools==84.0.1 \\\n    --hash=sha256:"
        + "1" * 64
        + "\n",
        encoding="utf-8",
    )
    errors = validate_build_lock(repo)
    assert any(
        "lock version drift for setuptools: expected 84.0.0, found 84.0.1" in error
        for error in errors
    )


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
    (root / ".opencode" / "package.json").write_text("{}", encoding="utf-8")
    (root / ".opencode" / "package-lock.json").write_text("{}", encoding="utf-8")

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


def test_task_scope_promotion_preserves_file_mode(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    worker_file = root / "worker.sh"
    worker_file.write_text("#!/bin/sh\necho worker\n", encoding="utf-8")
    task = root / ".codex" / "tasks" / "task.md"
    task.parent.mkdir(parents=True)
    task.write_text("Allowed files/paths:\n- worker.sh\n", encoding="utf-8")

    target = tmp_path / "target"
    shutil.copytree(root, target)
    before_path = tmp_path / "before.json"
    baseline_task = tmp_path / "task-before.md"
    before_path.write_text(json.dumps(snapshot(root)), encoding="utf-8")
    baseline_task.write_text(task.read_text(encoding="utf-8"), encoding="utf-8")
    os.chmod(worker_file, 0o751)  # noqa: S103 - mode preservation fixture
    os.chmod(target / "worker.sh", 0o640)

    assert promote(root, target, before_path, task, baseline_task) == []
    assert stat.S_IMODE((target / "worker.sh").stat().st_mode) == stat.S_IMODE(
        worker_file.stat().st_mode
    )


def test_task_scope_promotion_ignores_other_coordinator_task_packets(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    worker_file = root / "worker.txt"
    worker_file.write_text("before", encoding="utf-8")
    task = root / ".codex" / "tasks" / "task.md"
    task.parent.mkdir(parents=True)
    task.write_text("Allowed files/paths:\n- worker.txt\n", encoding="utf-8")

    target = tmp_path / "target"
    shutil.copytree(root, target)
    (target / ".codex" / "tasks" / "other-task.md").write_text(
        "coordinator-local packet", encoding="utf-8"
    )
    before_path = tmp_path / "before.json"
    baseline_task = tmp_path / "task-before.md"
    before_path.write_text(json.dumps(snapshot(root)), encoding="utf-8")
    baseline_task.write_text(task.read_text(encoding="utf-8"), encoding="utf-8")
    worker_file.write_text("after", encoding="utf-8")

    assert promote(root, target, before_path, task, baseline_task) == []
    assert (target / "worker.txt").read_text(encoding="utf-8") == "after"
    assert (target / ".codex" / "tasks" / "other-task.md").read_text(
        encoding="utf-8"
    ) == "coordinator-local packet"


def test_task_scope_promotion_rolls_back_after_apply_failure(
    tmp_path: Path, monkeypatch: Any
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    for name in ("first.txt", "second.txt"):
        (root / name).write_text("before", encoding="utf-8")
    task = root / ".codex" / "tasks" / "task.md"
    task.parent.mkdir(parents=True)
    task.write_text("Allowed files/paths:\n- first.txt\n- second.txt\n", encoding="utf-8")

    target = tmp_path / "target"
    shutil.copytree(root, target)
    before_path = tmp_path / "before.json"
    baseline_task = tmp_path / "task-before.md"
    before_path.write_text(json.dumps(snapshot(root)), encoding="utf-8")
    baseline_task.write_text(task.read_text(encoding="utf-8"), encoding="utf-8")
    (root / "first.txt").write_text("after-first", encoding="utf-8")
    (root / "second.txt").write_text("after-second", encoding="utf-8")

    real_apply = verify_task_scope._apply_staged_changes

    def apply_then_fail(*args: Any, **kwargs: Any) -> None:
        real_apply(*args, **kwargs)
        raise OSError("injected promotion failure")

    monkeypatch.setattr(verify_task_scope, "_apply_staged_changes", apply_then_fail)
    try:
        promote(root, target, before_path, task, baseline_task)
    except OSError as exc:
        assert str(exc) == "injected promotion failure"
    else:
        raise AssertionError("promotion unexpectedly succeeded")

    assert (target / "first.txt").read_text(encoding="utf-8") == "before"
    assert (target / "second.txt").read_text(encoding="utf-8") == "before"


def test_task_scope_rejects_unplanned_target_content_before_mutation(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    first = root / "first.txt"
    first.write_text("before", encoding="utf-8")
    removable = root / "removable"
    removable.mkdir()
    (removable / "tracked.txt").write_text("tracked", encoding="utf-8")
    task = root / ".codex" / "tasks" / "task.md"
    task.parent.mkdir(parents=True)
    task.write_text("Allowed files/paths:\n- first.txt\n- removable/**\n", encoding="utf-8")

    target = tmp_path / "target"
    shutil.copytree(root, target)
    (target / "removable" / "local-state.txt").write_text("keep", encoding="utf-8")
    before_path = tmp_path / "before.json"
    baseline_task = tmp_path / "task-before.md"
    before_path.write_text(json.dumps(snapshot(root)), encoding="utf-8")
    baseline_task.write_text(task.read_text(encoding="utf-8"), encoding="utf-8")
    shutil.rmtree(removable)
    first.write_text("after", encoding="utf-8")

    try:
        promote(root, target, before_path, task, baseline_task)
    except ValueError as exc:
        assert "unplanned content" in str(exc)
    else:
        raise AssertionError("promotion unexpectedly succeeded")

    assert (target / "first.txt").read_text(encoding="utf-8") == "before"
    assert (target / "removable" / "tracked.txt").read_text(encoding="utf-8") == "tracked"
    assert (target / "removable" / "local-state.txt").read_text(encoding="utf-8") == "keep"


def test_task_scope_nested_directory_rollback_restores_parent_and_child(
    tmp_path: Path, monkeypatch: Any
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    nested = root / "nested"
    nested.mkdir()
    child = nested / "child.txt"
    child.write_text("before", encoding="utf-8")
    task = root / ".codex" / "tasks" / "task.md"
    task.parent.mkdir(parents=True)
    task.write_text("Allowed files/paths:\n- nested/**\n", encoding="utf-8")

    target = tmp_path / "target"
    shutil.copytree(root, target)
    before_path = tmp_path / "before.json"
    baseline_task = tmp_path / "task-before.md"
    before_path.write_text(json.dumps(snapshot(root)), encoding="utf-8")
    baseline_task.write_text(task.read_text(encoding="utf-8"), encoding="utf-8")
    before_nested_mode = stat.S_IMODE((target / "nested").stat().st_mode)
    child.write_text("after", encoding="utf-8")
    os.chmod(nested, 0o751)  # noqa: S103 - nested rollback fixture

    real_apply = verify_task_scope._apply_staged_changes

    def apply_then_fail(*args: Any, **kwargs: Any) -> None:
        real_apply(*args, **kwargs)
        raise OSError("injected nested promotion failure")

    monkeypatch.setattr(verify_task_scope, "_apply_staged_changes", apply_then_fail)
    try:
        promote(root, target, before_path, task, baseline_task)
    except OSError as exc:
        assert str(exc) == "injected nested promotion failure"
    else:
        raise AssertionError("promotion unexpectedly succeeded")

    assert (target / "nested" / "child.txt").read_text(encoding="utf-8") == "before"
    assert stat.S_IMODE((target / "nested").stat().st_mode) == before_nested_mode


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
