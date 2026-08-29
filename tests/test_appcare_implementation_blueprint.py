"""Enforce the owner-approved AppCare implementation blueprint and current scope."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BLUEPRINT_PATH = ROOT / "APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md"
SCOPE_PATH = ROOT / "docs/governance/APPCARE_CURRENT_SCOPE.json"


def _text(path: Path) -> str:
    assert path.is_file(), f"mandatory implementation-governance file is missing: {path}"
    return path.read_text(encoding="utf-8")


def _scope() -> dict[str, Any]:
    payload = json.loads(_text(SCOPE_PATH))
    assert isinstance(payload, dict)
    return payload


def test_blueprint_is_binding_and_defines_all_twelve_phases() -> None:
    blueprint = _text(BLUEPRINT_PATH)

    required_markers = (
        "Status: **MANDATORY CURRENT-SCOPE IMPLEMENTATION GOVERNANCE**",
        "First supported beta profile: Linux-hosted PHP 8.x applications",
        "First real acceptance target: `video.slabfranchise.com`",
        "The unqualified word `IMPLEMENTED` is prohibited in readiness reports.",
        "WORDPRESS=FUTURE_BRANCH",
        "WOOCOMMERCE=FUTURE_BRANCH",
        "GPT-5.6 Luna Max — primary coordinator",
        "GPT-5.3 Spark — primary coder",
        "GPT-5.6 Terra — independent architecture/security challenger",
        "LIVE_CUSTOMER_PRODUCTION_ENABLED=NO",
    )
    for marker in required_markers:
        assert marker in blueprint

    for number in range(1, 13):
        assert f"# PHASE {number:02d} —" in blueprint

    assert blueprint.count("## Hard exit gate") == 12


def test_machine_readable_scope_matches_owner_decision() -> None:
    scope = _scope()

    assert scope["status"] == "MANDATORY_CURRENT_SCOPE"
    assert scope["target"] == "AppCare"

    profile = scope["first_supported_profile"]
    assert profile["os_family"] == "linux"
    assert profile["runtime"] == "php-8.x"
    assert profile["web_servers"] == ["nginx", "apache"]
    assert profile["primary_database"] == "mariadb-mysql"

    target = scope["first_real_acceptance_target"]
    assert target["application"] == "video.slabfranchise.com"
    assert target["host"] == "64.44.115.21"
    assert target["expected_hostname"] == "slab-prompt-ola"

    assert scope["vercel"]["current_critical_path"] is False

    for future_branch in ("wordpress", "woocommerce"):
        policy = scope["future_branches"][future_branch]
        assert policy["current_implementation_authorized"] is False
        assert policy["owner_authorization_required"] is True


def test_maturity_model_and_model_roles_cannot_be_weakened_silently() -> None:
    scope = _scope()

    assert scope["maturity_levels"] == [
        "DOCUMENTED",
        "COMPONENT_IMPLEMENTED",
        "RUNTIME_INTEGRATED",
        "LIVE_VERIFIED",
        "SERVICE_READY",
    ]
    assert scope["model_roles"] == {
        "coordinator": "GPT-5.6 Luna Max",
        "primary_coder": "GPT-5.3 Spark",
        "security_architecture_challenger": "GPT-5.6 Terra",
        "independent_security_scan": "Codex Security",
    }


def test_phase_dependency_graph_is_complete_and_fail_closed() -> None:
    scope = _scope()
    phases = scope["phases"]

    assert [phase["id"] for phase in phases] == [f"P{number:02d}" for number in range(1, 13)]
    assert all(phase["hard_exit_gate"] is True for phase in phases)

    expected_dependencies = {
        "P01": [],
        "P02": ["P01"],
        "P03": ["P02"],
        "P04": ["P03"],
        "P05": ["P03"],
        "P06": ["P04", "P05"],
        "P07": ["P06"],
        "P08": ["P07"],
        "P09": ["P08"],
        "P10": ["P09"],
        "P11": ["P10"],
        "P12": ["P11"],
    }
    assert {phase["id"]: phase["depends_on"] for phase in phases} == expected_dependencies


def test_backup_and_private_beta_policies_remain_fail_closed() -> None:
    scope = _scope()

    backup = scope["backup_policy"]
    assert backup["pre_change_backup_required"] is True
    assert backup["files_frequency"] == "daily"
    assert backup["database_frequency"] == "daily"
    assert backup["b2_operational_retention_days"] == 30
    assert backup["glacier_monthly_archive_months"] == 12
    assert backup["remote_readback_every_backup"] is True
    assert backup["isolated_restore_rehearsal"] == "monthly"
    assert backup["large_site_processing"] == "streaming-or-chunked"

    production = scope["private_beta_production_policy"]
    assert production["explicit_application_approval_required"] is True
    assert production["deployment_without_reliable_rollback"] == "denied"
    assert production["deliberate_production_failure_drill"] == "prohibited"
    assert production["global_live_customer_production_enabled"] is False


def test_readiness_stays_red_below_core_until_real_evidence_exists() -> None:
    readiness = _scope()["current_readiness"]

    assert readiness["CORE_PLATFORM_READY"] is True
    for marker in (
        "STACK_GENERIC_LINUX_READY",
        "STACK_WORDPRESS_READY",
        "STACK_WOOCOMMERCE_READY",
        "STACK_GITHUB_VERCEL_SUPABASE_READY",
        "CUSTOMER_ONBOARDING_READY",
        "PILOT_READY",
        "PAID_SERVICE_READY",
        "LIVE_CUSTOMER_PRODUCTION_ENABLED",
    ):
        assert readiness[marker] is False


def test_active_repository_guidance_links_to_blueprint() -> None:
    for relative_path in (
        "README.md",
        "AGENTS.md",
        "WORKER_PROTOCOL.md",
        "BETA_LOOP.md",
    ):
        assert "APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md" in _text(ROOT / relative_path)
