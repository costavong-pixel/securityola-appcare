"""Negative and deterministic tests for the direct DeepSeek worker boundary."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import cast
from urllib.request import Request

import pytest

from scripts import direct_deepseek_worker as worker


def _diff(path: str = "scripts/direct_deepseek_worker.py") -> str:
    return "\n".join(
        (
            f"diff --git a/{path} b/{path}",
            f"--- a/{path}",
            f"+++ b/{path}",
            "@@ -1,1 +1,1 @@",
            '-"old"',
            '+"new"',
            "",
        )
    )


def _output(**overrides: object) -> str:
    payload: dict[str, object] = {
        "analysis_summary": "bounded implementation result",
        "files_to_change": ["scripts/direct_deepseek_worker.py"],
        "unified_diff": _diff(),
        "tests_to_run": ["pytest"],
        "risks": [],
        "assumptions": [],
    }
    payload.update(overrides)
    return json.dumps(payload)


class _Response:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self, _limit: int) -> bytes:
        return self.body


class _Opener:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.request: Request | None = None

    def open(self, request: Request, *, timeout: float) -> _Response:
        assert timeout == 15.0
        self.request = request
        return _Response(self.body)


def test_endpoint_is_exact_and_rejects_openai_or_user_proxy() -> None:
    assert worker.validate_endpoint(worker.DEEPSEEK_CHAT_ENDPOINT) == worker.DEEPSEEK_CHAT_ENDPOINT
    for endpoint in (
        "https://api.openai.com/v1/chat/completions",
        "https://api.deepseek.com.evil.example/chat/completions",
        "http://api.deepseek.com/chat/completions",
        "https://api.deepseek.com:443/chat/completions",
    ):
        with pytest.raises(worker.WorkerError, match="deepseek_endpoint_rejected"):
            worker.validate_endpoint(endpoint)


def test_direct_client_uses_only_fixed_endpoint_and_structured_response() -> None:
    opener = _Opener(
        json.dumps(
            {
                "model": "deepseek-chat",
                "choices": [
                    {
                        "message": {
                            "content": _output(),
                        }
                    }
                ],
            }
        ).encode()
    )
    client = worker.DirectDeepSeekClient(
        model="deepseek-chat",
        api_key_loader=lambda: "k",
        opener=opener,
        timeout_seconds=15,
    )

    completion = client.complete("TARGET=AppCare\nsealed task")

    assert completion.actual_model == "deepseek-chat"
    assert completion.content.startswith("{")
    assert opener.request is not None
    request = opener.request
    assert request.full_url == worker.DEEPSEEK_CHAT_ENDPOINT
    assert request.get_header("Authorization") == "Bearer k"
    assert request.data is not None
    assert json.loads(cast(bytes, request.data))["model"] == "deepseek-chat"


def test_direct_client_requires_server_model_attestation() -> None:
    opener = _Opener(
        json.dumps(
            {
                "choices": [{"message": {"content": _output()}}],
            }
        ).encode()
    )
    client = worker.DirectDeepSeekClient(
        model="deepseek-chat",
        api_key_loader=lambda: "k",
        opener=opener,
        timeout_seconds=15,
    )

    with pytest.raises(worker.WorkerError, match="response_invalid"):
        client.complete("TARGET=AppCare\nsealed task")


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX mode bits are required for this worker-host check"
)
def test_trusted_key_loader_rejects_world_readable_file(tmp_path: Path) -> None:
    path = tmp_path / "api-key"
    path.write_text("k\n", encoding="ascii")
    os.chmod(path, 0o644)

    with pytest.raises(worker.WorkerError, match="permissions_invalid"):
        worker.load_api_key(path, require_root_owner=False)


def test_output_paths_and_diff_must_stay_allowlisted() -> None:
    with pytest.raises(worker.WorkerError, match="out_of_scope"):
        worker.parse_worker_output(
            _output(files_to_change=["../outside.py"]),
            allowed_paths=["scripts/direct_deepseek_worker.py"],
        )
    with pytest.raises(worker.WorkerError, match="files_do_not_match_diff"):
        worker.parse_worker_output(
            _output(
                files_to_change=["scripts/direct_deepseek_worker.py"],
                unified_diff=_diff("tests/x.py"),
            ),
            allowed_paths=["scripts/direct_deepseek_worker.py", "tests/x.py"],
        )


def test_output_rejects_delete_rename_and_binary_patches() -> None:
    for marker in ("deleted file mode 100644", "similarity index 100%", "GIT binary patch"):
        with pytest.raises(worker.WorkerError):
            worker.parse_worker_output(
                _output(unified_diff=_diff() + marker + "\n"),
                allowed_paths=["scripts/direct_deepseek_worker.py"],
            )


def test_output_rejects_secret_shaped_content_without_printing_value() -> None:
    secret_assignment = "api_key = " + repr("abcdefgh")
    with pytest.raises(worker.WorkerError, match="contains_secret"):
        worker.parse_worker_output(
            _output(analysis_summary=secret_assignment),
            allowed_paths=["scripts/direct_deepseek_worker.py"],
        )


def test_model_tests_are_metadata_only_and_runner_uses_fixed_commands(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(
        command: tuple[str, ...],
        *,
        cwd: Path,
        timeout_seconds: int,
        environment: dict[str, str],
        limit_resources: bool,
        isolate_to_test_identity: bool,
    ) -> worker.ProcessStatus:
        calls.append(command)
        assert cwd == tmp_path
        assert timeout_seconds == 30
        assert environment["TARGET"] == "AppCare"
        assert limit_resources is True
        assert isolate_to_test_identity is True
        return worker.ProcessStatus(0, False, False, True)

    monkeypatch.setattr(worker, "_run_process", fake_run)
    worker.run_deterministic_tests(tmp_path, timeout_seconds=30)

    assert len(calls) == 4
    assert all("evil-command" not in call for call in calls)
    assert calls[-1][-2:] == ("pytest", "-q")


def test_model_output_requires_all_contract_fields() -> None:
    payload = json.loads(_output())
    del payload["risks"]
    with pytest.raises(worker.WorkerError, match="schema_invalid"):
        worker.parse_worker_output(
            json.dumps(payload),
            allowed_paths=["scripts/direct_deepseek_worker.py"],
        )


def test_git_status_distinguishes_ignored_untracked_and_real_changes(tmp_path: Path) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is required for the cleanliness regression test")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".codex/tasks/\n", encoding="utf-8")
    (repo / "tracked.txt").write_text("clean\n", encoding="utf-8")
    subprocess.run(  # noqa: S603 - Git is resolved before fixed test argv
        [git, "init", "-q", "-b", "main"], cwd=repo, check=True
    )
    subprocess.run(  # noqa: S603 - Git is resolved before fixed test argv
        [git, "add", ".gitignore", "tracked.txt"], cwd=repo, check=True
    )
    subprocess.run(  # noqa: S603 - Git is resolved before fixed test argv
        [
            git,
            "-c",
            "user.name=AppCare Test",
            "-c",
            "user.email=appcare-test@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        cwd=repo,
        check=True,
    )

    assert worker._git_status(repo)[2] == ""

    ignored_task = repo / ".codex" / "tasks" / "direct.md"
    ignored_task.parent.mkdir(parents=True)
    ignored_task.write_text("ignored\n", encoding="utf-8")
    assert worker._git_status(repo)[2] == ""

    (repo / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    assert worker._git_status(repo)[2] == "dirty"
    (repo / "unexpected.txt").unlink()

    (repo / "tracked.txt").write_text("modified\n", encoding="utf-8")
    assert worker._git_status(repo)[2] == "dirty"

    subprocess.run(  # noqa: S603 - Git is resolved before fixed test argv
        [git, "add", "tracked.txt"], cwd=repo, check=True
    )
    assert worker._git_status(repo)[2] == "dirty"


def test_systemd_units_use_worker_path_constants() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    api_service = (
        repository_root / "ops" / "worker" / "securityola-appcare-deepseek-api@.service"
    ).read_text(encoding="utf-8")
    worker_service = (
        repository_root / "ops" / "worker" / "securityola-appcare-deepseek-worker@.service"
    ).read_text(encoding="utf-8")

    state_path = worker.WORKER_STATE_ROOT.as_posix()
    key_directory = worker.DEEPSEEK_API_KEY_PATH.parent.as_posix()

    def path_values(service: str, directive: str) -> tuple[str, ...]:
        prefix = f"{directive}="
        return tuple(
            value
            for line in service.splitlines()
            if line.startswith(prefix)
            for value in line[len(prefix) :].split()
        )

    assert path_values(api_service, "ReadWritePaths") == (state_path,)
    assert path_values(api_service, "ReadOnlyPaths") == (key_directory,)
    assert path_values(worker_service, "ReadWritePaths") == (state_path,)
    assert path_values(worker_service, "ReadOnlyPaths") == ()
    assert path_values(worker_service, "InaccessiblePaths") == (
        worker.DEEPSEEK_API_KEY_PATH.as_posix(),
    )


def test_receipt_does_not_overstate_validation_or_model_attestation() -> None:
    unvalidated = worker._base_receipt(
        run_id="a" * 32,
        base_sha="a" * 40,
        branch="main",
        model="deepseek-chat",
    )
    assert unvalidated.routing_metadata_validated == "NO"
    assert unvalidated.model_attested == "NO"

    mismatched = worker._base_receipt(
        run_id="b" * 32,
        base_sha="b" * 40,
        branch="main",
        model="deepseek-chat",
        actual_model="deepseek-reasoner",
        routing_metadata_validated="YES",
    )
    assert mismatched.routing_metadata_validated == "YES"
    assert mismatched.model_attested == "NO"


@pytest.mark.skipif(os.name == "nt", reason="Symlink directory fixture is POSIX-only")
def test_sealed_packet_copy_rejects_symlinked_task_directory(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (worktree / ".codex").symlink_to(outside, target_is_directory=True)
    packet = worker.TaskPacket(
        text="sealed",
        branch="main",
        expected_head="a" * 40,
        allowed_paths=("src.py",),
    )

    with pytest.raises(worker.WorkerError, match="task_directory_invalid"):
        worker._copy_sealed_packet(worktree, packet)


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX worker locking is required for this lifecycle test"
)
def test_worker_lifecycle_uses_disposable_worktree_and_sanitized_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is required for the lifecycle test")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "src.py").write_text('"old"\n', encoding="utf-8")
    (repo / ".gitignore").write_text(".codex/tasks/\n", encoding="utf-8")
    subprocess.run(  # noqa: S603 - Git is resolved before fixed test argv
        [git, "init", "-q", "-b", "main"], cwd=repo, check=True
    )
    subprocess.run(  # noqa: S603 - Git is resolved before fixed test argv
        [git, "add", ".gitignore", "src.py"], cwd=repo, check=True
    )
    subprocess.run(  # noqa: S603 - Git is resolved before fixed test argv
        [
            git,
            "-c",
            "user.name=AppCare Test",
            "-c",
            "user.email=appcare-test@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        cwd=repo,
        check=True,
    )
    head = subprocess.check_output(  # noqa: S603 - Git is resolved before fixed test argv
        [git, "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    task_root = repo / ".codex" / "tasks"
    task_root.mkdir(parents=True)
    task = task_root / "direct.md"
    task.write_text(
        "Phase: P02\n"
        "Issue: APPCARE-DIRECT-WORKER\n"
        "Goal: validate the isolated direct worker\n"
        "TARGET=AppCare\n"
        "Coding lane: DIRECT_DEEPSEEK\n"
        "Worker host: PROMPT_OLA_VPS\n"
        "Model provider: DEEPSEEK_API\n"
        "Codex Spark quota involved: NO\n"
        "OpenAI API involved: NO\n"
        "DeepSeek API involved: YES\n"
        "Repository root: .\n"
        "Branch: main\n"
        f"Expected base SHA: {head}\n\n"
        "Allowed files/paths:\n"
        "- src.py\n\n"
        "Do not touch:\n"
        "- WordPress Security resources\n\n"
        "Forbidden commands/capabilities:\n"
        "- no network, credentials, production, or deployment\n",
        encoding="utf-8",
    )
    state = tmp_path / "state"
    monkeypatch.setattr(worker, "_assert_non_root", lambda: None)
    monkeypatch.setattr(worker, "_assert_virtualenv", lambda: None)
    monkeypatch.setattr(
        worker,
        "_validate_worker_roots",
        lambda _repo, _state: (repo, state),
    )
    monkeypatch.setattr(worker, "load_model", lambda: "deepseek-chat")
    client = worker.DirectDeepSeekClient(
        model="deepseek-chat",
        api_key_loader=lambda: "k",
        opener=_Opener(
            json.dumps(
                {
                    "model": "deepseek-chat",
                    "choices": [
                        {
                            "message": {
                                "content": _output(
                                    files_to_change=["src.py"], unified_diff=_diff("src.py")
                                )
                            }
                        }
                    ],
                }
            ).encode()
        ),
        timeout_seconds=15,
    )

    completion_path = worker.request_completion(
        task,
        run_id="a" * 32,
        repo_root=repo,
        state_root=state,
        client=client,
    )
    assert completion_path.name == "completion.json"
    monkeypatch.setattr(
        worker,
        "load_api_key",
        lambda: pytest.fail("apply stage must never load the API key"),
    )

    receipt_path = worker.execute_stored_worker(
        "a" * 32,
        repo_root=repo,
        state_root=state,
        test_runner=lambda _worktree: None,
        secret_scanner=lambda _worktree, _before: None,
    )

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["endpoint"] == worker.DEEPSEEK_CHAT_ENDPOINT
    assert receipt["temporary_worker_state_removed"] == "YES"
    assert receipt["files_to_change"] == ["src.py"]
    run_id = receipt["run_id"]
    assert (receipt_path.parent / f"{run_id}.patch").is_file()
    assert not list((state / "runs").iterdir())
    assert not list((state / "requests").iterdir())
    assert (state / "consumed" / run_id).is_dir()
    receipt_bytes = receipt_path.read_bytes()

    with pytest.raises(worker.WorkerError, match="worker_run_already_consumed"):
        worker.execute_stored_worker(
            run_id,
            repo_root=repo,
            state_root=state,
            test_runner=lambda _worktree: pytest.fail("replayed run must not execute tests"),
            secret_scanner=lambda _worktree, _before: pytest.fail("replayed run must not scan"),
        )
    assert receipt_path.read_bytes() == receipt_bytes
