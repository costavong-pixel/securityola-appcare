"""Enforce the owner-approved Spark-to-direct-DeepSeek routing policy."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scripts.validate_task_packet import seal

ROOT = Path(__file__).resolve().parents[1]
ROUTING_MD = ROOT / "docs/governance/APPCARE_MODEL_EXECUTION_ROUTING.md"
ROUTING_JSON = ROOT / "docs/governance/APPCARE_MODEL_EXECUTION_ROUTING.json"
DEEPSEEK_LAUNCHER = ROOT / "scripts/deepseek-worker.sh"
TEST_HEAD = "0123456789abcdef0123456789abcdef01234567"


def _text(path: Path) -> str:
    assert path.is_file(), f"mandatory routing-governance file is missing: {path}"
    return path.read_text(encoding="utf-8")


def _routing() -> dict[str, Any]:
    payload = json.loads(_text(ROUTING_JSON))
    assert isinstance(payload, dict)
    return payload


def _direct_packet() -> str:
    return (
        "Phase: P02\n"
        "Issue: APPCARE-READINESS\n"
        "Goal: validate direct worker routing metadata\n"
        "TARGET=AppCare\n"
        "Coding lane: DIRECT_DEEPSEEK\n"
        "Worker host: PROMPT_OLA_VPS\n"
        "Model provider: DEEPSEEK_API\n"
        "Codex Spark quota involved: NO\n"
        "OpenAI API involved: NO\n"
        "DeepSeek API involved: YES\n"
        "Repository root: .\n"
        "Branch: codex/test\n"
        f"Expected base SHA: {TEST_HEAD}\n\n"
        "Allowed files/paths:\n"
        "- appcare/*\n\n"
        "Do not touch:\n"
        "- WordPress Security resources\n\n"
        "Forbidden commands/capabilities:\n"
        "- no network, credentials, production, or deployment\n"
    )


def _seal_direct_packet(tmp_path: Path, packet_text: str) -> list[str]:
    repo = tmp_path / "repo"
    task_root = repo / ".codex" / "tasks"
    task_root.mkdir(parents=True)
    packet = task_root / "task.md"
    packet.write_text(packet_text, encoding="utf-8")
    return seal(
        packet,
        tmp_path / "run" / "task.md",
        repo,
        task_root,
        expected_head=TEST_HEAD,
        expected_branch="codex/test",
    )


def test_direct_deepseek_fallback_does_not_use_spark_quota_or_openai_api() -> None:
    routing = _routing()
    fallback = routing["coding_lanes"]["quota_fallback"]

    assert fallback["id"] == "DIRECT_DEEPSEEK"
    assert fallback["worker_host"] == "Prompt Ola VPS"
    assert fallback["provider"] == "DeepSeek API"
    assert fallback["codex_spark_quota_involved"] is False
    assert fallback["openai_api_involved"] is False
    assert fallback["deepseek_api_involved"] is True
    assert fallback["credential_required"] is True
    assert fallback["credential_presence"] == "NOT_VERIFIED"
    assert "owner_has_api_credential" not in fallback
    assert fallback["credential_custody"] == "server-side-only"


def test_sealed_packet_contract_pins_direct_route_metadata() -> None:
    enforcement = _routing()["task_packet_enforcement"]

    assert "Coding lane" in enforcement["required_fields"]
    assert "Model provider" in enforcement["required_fields"]
    assert enforcement["direct_deepseek_exact_values"] == {
        "Coding lane": "DIRECT_DEEPSEEK",
        "Worker host": "PROMPT_OLA_VPS",
        "Model provider": "DEEPSEEK_API",
        "Codex Spark quota involved": "NO",
        "OpenAI API involved": "NO",
        "DeepSeek API involved": "YES",
    }
    assert enforcement["sanitized_runtime_attestation"] == [
        "REQUESTED_MODEL",
        "ACTUAL_MODEL",
        "MODEL_ATTESTED",
        "ROUTING_METADATA_VALIDATED",
    ]


def test_sealed_packet_rejects_inconsistent_direct_route_metadata(tmp_path: Path) -> None:
    packet = _direct_packet().replace("OpenAI API involved: NO", "OpenAI API involved: YES")

    findings = _seal_direct_packet(tmp_path, packet)

    assert "direct DeepSeek task packet must declare OpenAI API involved=NO" in findings


def test_sealed_packet_rejects_missing_routing_metadata(tmp_path: Path) -> None:
    packet = _direct_packet().replace("Model provider: DEEPSEEK_API\n", "")

    findings = _seal_direct_packet(tmp_path, packet)

    assert "task packet must declare exactly one Model provider field" in findings


def test_luna_terra_and_codex_security_roles_remain_independent() -> None:
    routing = _routing()

    assert routing["coordinator"]["model"] == "GPT-5.6 Luna Max"
    assert routing["review_lanes"] == {
        "architecture_security": "GPT-5.6 Terra",
        "independent_code_security": "Codex Security",
    }


def test_prompt_ola_vps_is_worker_host_not_prompt_ola_production_authority() -> None:
    isolation = _routing()["worker_isolation"]

    assert isolation["one_writer_per_branch"] is True
    assert isolation["dedicated_appcare_checkout"] is True
    assert isolation["dedicated_appcare_state"] is True
    assert isolation["sealed_task_packet"] is True
    assert isolation["allowlisted_writes"] is True
    assert isolation["scope_verification"] is True
    assert isolation["secret_scan_before_promotion"] is True
    assert isolation["temporary_state_cleanup"] is True
    assert isolation["prompt_ola_production_access"] is False


def test_existing_opencode_launcher_is_not_misreported_as_direct_api() -> None:
    routing = _routing()
    launcher = routing["existing_launcher"]
    launcher_text = _text(DEEPSEEK_LAUNCHER)

    assert launcher["path"] == "scripts/deepseek-worker.sh"
    assert launcher["configured_model_route"] == "opencode/deepseek-v4-flash-free"
    assert launcher["direct_deepseek_api_compliant"] is False
    assert launcher["may_be_claimed_runtime_integrated"] is False
    assert 'MODEL="opencode/deepseek-v4-flash-free"' in launcher_text


def test_direct_route_requires_full_existing_worker_safety_controls() -> None:
    acceptance = _routing()["direct_route_acceptance"]

    for marker in (
        "must_call_deepseek_api_directly",
        "must_not_call_openai_api",
        "must_not_consume_spark_quota",
        "must_preserve_sealed_task",
        "must_preserve_isolated_worktree",
        "must_preserve_scope_verification",
        "must_preserve_secret_scan",
        "must_preserve_timeout_and_cleanup",
        "requires_luna_review",
        "requires_terra_review",
        "requires_codex_security",
        "requires_exact_head_ci",
    ):
        assert acceptance[marker] is True


def test_active_agent_guidance_links_to_routing_policy() -> None:
    for relative_path in ("AGENTS.md", "WORKER_PROTOCOL.md", ".specify/memory/constitution.md"):
        text = _text(ROOT / relative_path)
        assert "APPCARE_MODEL_EXECUTION_ROUTING" in text


def test_human_readable_policy_pins_direct_route_facts() -> None:
    policy = _text(ROUTING_MD)

    for marker in (
        "GPT-5.6 Luna Max coordinator",
        "Prompt Ola VPS",
        "direct DeepSeek worker",
        "CODEX_SPARK_QUOTA_INVOLVED=NO",
        "OPENAI_API_INVOLVED=NO",
        "DEEPSEEK_API_INVOLVED=YES",
        "DEEPSEEK_API_CREDENTIAL_PRESENCE=NOT_VERIFIED",
        "ROUTING_METADATA_VALIDATED",
        "scripts/deepseek-worker.sh",
        "does **not** by itself prove the owner-approved direct DeepSeek API route",
    ):
        assert marker in policy
