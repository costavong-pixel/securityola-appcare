"""Enforce the owner-approved AppCare blueprint and current scope contract."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from appcare.readiness import (
    REQUIRED_SECURITY_GATE_IDS,
    CapabilityEvidence,
    CapabilityStatus,
    CoordinatorApproval,
    CoordinatorDecision,
    EvidenceClass,
    LayeredReadinessDecision,
    ReadinessEvaluationError,
    ReadinessEvaluator,
    ReadinessEvidence,
    ReadinessLevel,
    ReadinessStatus,
    ReadinessTier,
    SecurityGateDecision,
    SupportabilityEvaluator,
    default_capability_registry,
)

ROOT = Path(__file__).resolve().parents[1]
BLUEPRINT_PATH = ROOT / "APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md"
SCOPE_PATH = ROOT / "docs/governance/APPCARE_CURRENT_SCOPE.json"

PHASE_CONTRACT_FIELDS = frozenset(
    {
        "objective",
        "components",
        "runtime_wiring",
        "security_requirements",
        "positive_tests",
        "negative_adversarial_tests",
        "live_reference_evidence",
        "hard_exit_requirements",
        "maturity_effect",
        "readiness_effect",
        "predecessor_dependencies",
        "prohibited_actions",
        "owner_only_gates",
    }
)
PHASE_KEYS = frozenset({"id", "name", "depends_on", "hard_exit_gate"}) | PHASE_CONTRACT_FIELDS
SCOPE_KEYS = {
    "schema_version",
    "status",
    "owner_decision_date",
    "target",
    "first_supported_profile",
    "first_real_acceptance_target",
    "future_branches",
    "vercel",
    "maturity_levels",
    "model_roles",
    "backup_policy",
    "private_beta_production_policy",
    "enforcement_invariants",
    "phases",
    "current_readiness",
}
EXPECTED_PHASES = (
    ("P01", "Binding blueprint and enforcement", ()),
    ("P02", "Credential custody and SSH onboarding", ("P01",)),
    ("P03", "Live CONNECT, INVENTORY, and immutable baseline", ("P02",)),
    ("P04", "Streaming filesystem backup and data classification", ("P03",)),
    ("P05", "Live MariaDB/MySQL transport and isolated database restore", ("P03",)),
    ("P06", "B2, Glacier, and complete application restore", ("P04", "P05")),
    ("P07", "Live security scanning and test discovery", ("P06",)),
    ("P08", "Brownfield normalization, staging, and remediation", ("P07",)),
    ("P09", "Deployment, migration safety, verification, and rollback", ("P08",)),
    ("P10", "Monitoring, scheduler, alerting, reporting, and support tiers", ("P09",)),
    (
        "P11",
        "Operator productization, commercial lifecycle, offboarding, and AppCare DR",
        ("P10",),
    ),
    (
        "P12",
        "Real-target acceptance, exact-release security review, and beta decision",
        ("P11",),
    ),
)
EXPECTED_HARD_EXIT_REQUIREMENTS = {
    "P01": (
        "P01_BLUEPRINT_MERGED=YES",
        "P01_SCOPE_MACHINE_READABLE=YES",
        "P01_TWELVE_PHASES=PASS",
        "P01_HARD_EXIT_GATES=PASS",
        "P01_CI_ENFORCEMENT=PASS",
        "P01_CROSS_DOCUMENT_CONSISTENCY=PASS",
        "P01_LUNA_APPROVAL=PASS",
        "P01_TERRA_APPROVAL=PASS",
        "P01_CODEX_SECURITY=PASS",
        "P01_EXACT_HEAD_CI=PASS",
        "P01_PROTECTED_MAIN_VERIFIED=PASS",
    ),
    "P02": (
        "P02_LOCAL_VAULT=RUNTIME_INTEGRATED",
        "P02_MANUAL_ONBOARDING=LIVE_VERIFIED",
        "P02_BOOTSTRAP_PATH=LIVE_VERIFIED_OR_BLOCKED_EXTERNAL_WITH_MANUAL_PATH_PASS",
        "P02_ROTATION=LIVE_VERIFIED",
        "P02_OFFBOARDING=LIVE_VERIFIED",
        "P02_SECRETS_EXPOSED=NO",
    ),
    "P03": (
        "P03_HOST_IDENTITY=PASS",
        "P03_CONNECT=LIVE_VERIFIED",
        "P03_INVENTORY=LIVE_VERIFIED",
        "P03_IMMUTABLE_REVISION=LIVE_VERIFIED",
        "P03_INTERNAL_MIRROR=RUNTIME_INTEGRATED",
    ),
    "P04": (
        "P04_FILESYSTEM_BACKUP=LIVE_VERIFIED",
        "P04_STREAMING_BOUNDED=PASS",
        "P04_MANIFEST=PASS",
        "P04_ISOLATED_FILE_RESTORE=PASS",
    ),
    "P05": (
        "P05_DATABASE_BACKUP=LIVE_VERIFIED",
        "P05_ISOLATED_DB_RESTORE=LIVE_VERIFIED",
        "P05_PRODUCTION_DB_WRITES=NO",
        "P05_CREDENTIAL_EXPOSURE=NO",
    ),
    "P06": (
        "P06_OFFSITE_BACKUP=LIVE_VERIFIED",
        "P06_REMOTE_READBACK=LIVE_VERIFIED",
        "P06_COMPLETE_ISOLATED_RESTORE=LIVE_VERIFIED",
        "P06_MONTHLY_RESTORE_SCHEDULE=RUNTIME_INTEGRATED",
    ),
    "P07": (
        "P07_SECURITY_SCAN=LIVE_VERIFIED",
        "P07_TEST_DISCOVERY=LIVE_VERIFIED",
        "P07_SCANNER_SANDBOX=PASS",
        "P07_FINDING_EVIDENCE=PASS",
    ),
    "P08": (
        "P08_BROWNFIELD_NORMALIZED=LIVE_VERIFIED",
        "P08_STAGING=LIVE_VERIFIED",
        "P08_REMEDIATION=LIVE_VERIFIED",
        "P08_PREPRODUCTION_RECEIPT=PASS",
    ),
    "P09": (
        "P09_DEPLOY=LIVE_VERIFIED",
        "P09_PRODUCTION_VERIFY=LIVE_VERIFIED",
        "P09_DATABASE_MIGRATION_SAFETY=LIVE_VERIFIED",
        "P09_ROLLBACK=LIVE_VERIFIED",
    ),
    "P10": (
        "P10_MONITORING=LIVE_VERIFIED",
        "P10_SCHEDULER=LIVE_VERIFIED",
        "P10_ALERTING=LIVE_VERIFIED",
        "P10_REPORTING=LIVE_VERIFIED",
        "P10_RESTART_DURABILITY=PASS",
    ),
    "P11": (
        "P11_OPERATOR_DASHBOARD=LIVE_VERIFIED",
        "P11_AUTH_APPROVAL=LIVE_VERIFIED",
        "P11_BILLING_OFFBOARDING=LIVE_VERIFIED",
        "P11_EXTERNAL_SECRET_MANAGER=LIVE_VERIFIED",
        "P11_APPCARE_DR=LIVE_VERIFIED",
    ),
    "P12": (
        "P12_REAL_TARGET_FULL_LIFECYCLE=PASS",
        "P12_S01_S30=PASS",
        "P12_INTERNAL_PILOT=PASS",
        "P12_REAL_COST_MEASURED=YES",
        "P12_OPEN_CRITICAL_FINDINGS=0",
    ),
}

# These markers pin the security meaning of every structured phase field. The
# scope JSON remains the machine-readable contract; the blueprint must carry
# the same meaning in its human-readable contract. Non-empty values alone are
# intentionally insufficient because they would allow vacuous policy text.
PHASE_SEMANTIC_MARKERS = {
    "P01": {
        "objective": ("current AppCare", "scope"),
        "components": ("blueprint", "governance"),
        "runtime_wiring": ("CI parses", "no customer capability"),
        "security_requirements": ("protected review", "no credentials", "fail-closed"),
        "positive_tests": ("product contract", "phase graph", "readiness floor"),
        "negative_adversarial_tests": ("weak", "authority"),
        "live_reference_evidence": ("governance evidence",),
        "maturity_effect": ("SERVICE_READY", "governance"),
        "readiness_effect": ("no CONNECT", "production capability"),
        "predecessor_dependencies": ("NONE",),
        "prohibited_actions": ("customer access", "production write", "readiness bypass"),
        "owner_only_gates": ("scope", "protected merge"),
    },
    "P02": {
        "objective": ("encrypted", "revocable", "SSH"),
        "components": ("encrypted vault", "Ed25519", "revocation", "offboarding"),
        "runtime_wiring": ("credential references", "typed operations", "durable audit"),
        "security_requirements": ("plaintext", "non-root", "tenant", "fail-closed"),
        "positive_tests": ("create", "resolve", "rotate", "revoke", "offboard"),
        "negative_adversarial_tests": ("secret leakage", "cross-tenant", "partial bootstrap"),
        "live_reference_evidence": ("approved internal target", "no customer production"),
        "maturity_effect": ("highest evidence-backed",),
        "readiness_effect": ("remain unpromoted",),
        "predecessor_dependencies": ("P01",),
        "prohibited_actions": ("customer production", "unrestricted sudo", "private-key"),
        "owner_only_gates": ("external credential", "first customer production"),
    },
    "P03": {
        "objective": ("trusted live target identity", "normalized inventory", "immutable"),
        "components": ("target registration", "host-key binding", "typed connect"),
        "runtime_wiring": ("Spec 014", "Spec 013", "tenant/application"),
        "security_requirements": ("strict host-key", "non-root read-only", "no TOFU"),
        "positive_tests": ("connect", "inventory", "baseline digest"),
        "negative_adversarial_tests": ("wrong host", "symlink escape", "partial inventory"),
        "live_reference_evidence": ("real-target", "fixtures"),
        "maturity_effect": ("live evidence",),
        "readiness_effect": ("exact target", "remain missing"),
        "predecessor_dependencies": ("P02",),
        "prohibited_actions": ("filesystem", "deployment", "WordPress"),
        "owner_only_gates": ("trust anchor", "production mutation"),
    },
    "P04": {
        "objective": ("real target filesystem", "bounded streaming", "data classification"),
        "components": ("source", "streaming archive", "manifest"),
        "runtime_wiring": ("existing AppCare backup", "restore pipeline"),
        "security_requirements": ("Tenant roots", "symlink", "secret exclusion", "resource caps"),
        "positive_tests": ("stream", "manifest", "restore"),
        "negative_adversarial_tests": ("traversal", "secret", "checksum"),
        "live_reference_evidence": ("REAL TARGET", "fixture/reference"),
        "maturity_effect": ("bounded streaming", "restore evidence"),
        "readiness_effect": ("no off-site", "P06"),
        "predecessor_dependencies": ("P03",),
        "prohibited_actions": ("full-memory-archive", "secret-capture", "alternate-backup-root"),
        "owner_only_gates": ("customer-filesystem-scope", "destructive-cleanup"),
    },
    "P05": {
        "objective": ("MariaDB/MySQL", "isolated restore"),
        "components": ("database credential broker", "consistent dump", "restore target"),
        "runtime_wiring": ("Spec 015 adapters", "Spec 013", "exact target binding"),
        "security_requirements": ("closed commands", "no arbitrary SQL", "non-production restore"),
        "positive_tests": ("logical dump", "isolated restore", "post-restore"),
        "negative_adversarial_tests": (
            "wrong DB identity",
            "unsafe definer",
            "production restore",
        ),
        "live_reference_evidence": ("real-target database", "fixtures and isolated reference"),
        "maturity_effect": ("exact engine", "restore evidence"),
        "readiness_effect": ("database capability alone", "whole-application"),
        "predecessor_dependencies": ("P03",),
        "prohibited_actions": (
            "production",
            "arbitrary SQL",
            "WordPress",
        ),
        "owner_only_gates": ("database scope", "customer database access"),
    },
    "P06": {
        "objective": ("immutable off-site recovery", "complete isolated restore"),
        "components": ("B2 vault", "Glacier archive", "retention/readback"),
        "runtime_wiring": (
            "canonical AppCare backup boundary",
            "provider wrappers",
            "isolated restore",
        ),
        "security_requirements": (
            "least-privilege provider",
            "immutable retention",
            "remote readback",
            "no production restore",
        ),
        "positive_tests": ("upload", "read", "checksum", "retention"),
        "negative_adversarial_tests": ("wrong prefix", "missing readback", "restore escape"),
        "live_reference_evidence": ("provider-controlled or real-target", "local snapshots"),
        "maturity_effect": ("provider and isolated-recovery",),
        "readiness_effect": ("no deploy or pilot", "recovery point"),
        "predecessor_dependencies": ("P04", "P05"),
        "prohibited_actions": (
            "alternate backup namespace",
            "customer-data migration",
            "production overwrite",
        ),
        "owner_only_gates": ("provider/account authority", "customer data scope"),
    },
    "P07": {
        "objective": ("allowlisted scanners", "discover tests safely"),
        "components": (
            "sandboxed scanner",
            "pinned",
            "finding normalization",
        ),
        "runtime_wiring": ("scanner and test-discovery results", "authorize"),
        "security_requirements": (
            "no arbitrary executable",
            "bounded resources",
            "inherited secrets",
        ),
        "positive_tests": ("scan", "discover", "finding"),
        "negative_adversarial_tests": ("injection", "SSRF", "archive bomb"),
        "live_reference_evidence": ("real target", "reference"),
        "maturity_effect": ("scanner", "live evidence"),
        "readiness_effect": ("production", "remediation"),
        "predecessor_dependencies": ("P06",),
        "prohibited_actions": (
            "scanner",
            "production",
            "remediation",
        ),
        "owner_only_gates": ("scope", "invasive"),
    },
    "P08": {
        "objective": ("brownfield", "staging", "remediation"),
        "components": ("baseline", "staging", "remediation"),
        "runtime_wiring": ("normalized", "staging"),
        "security_requirements": ("production", "staging"),
        "positive_tests": ("stag", "fix", "security"),
        "negative_adversarial_tests": ("production", "patch"),
        "live_reference_evidence": ("real", "evidence"),
        "maturity_effect": ("staging", "evidence"),
        "readiness_effect": ("promotion", "production"),
        "predecessor_dependencies": ("P07",),
        "prohibited_actions": ("production", "WordPress", "patch"),
        "owner_only_gates": ("scope", "remediation"),
    },
    "P09": {
        "objective": ("deployment", "migration", "rollback"),
        "components": ("deployment", "migration", "rollback"),
        "runtime_wiring": ("approved artifact", "verification", "automatic rollback"),
        "security_requirements": ("immutable intent", "explicit approval", "duplicate"),
        "positive_tests": ("deploy", "health", "rollback"),
        "negative_adversarial_tests": ("wrong artifact", "migration", "duplicate"),
        "live_reference_evidence": ("real target", "fixture"),
        "maturity_effect": ("exact", "rollback"),
        "readiness_effect": ("production", "rollback"),
        "predecessor_dependencies": ("P08",),
        "prohibited_actions": (
            "production",
            "mutation",
        ),
        "owner_only_gates": ("application scoped", "approval"),
    },
    "P10": {
        "objective": ("monitoring", "schedul", "alerting", "reporting"),
        "components": ("collectors", "scheduler", "alert"),
        "runtime_wiring": ("PostgreSQL", "restart", "dashboard"),
        "security_requirements": ("durable", "dedup", "quota", "no secret"),
        "positive_tests": ("restart", "alert", "report"),
        "negative_adversarial_tests": ("stale state", "duplicate", "alert storm"),
        "live_reference_evidence": ("real target", "monitoring"),
        "maturity_effect": ("monitoring", "restart"),
        "readiness_effect": ("no paid-service", "operations"),
        "predecessor_dependencies": ("P09",),
        "prohibited_actions": ("in-memory-only", "unbounded polling", "WordPress"),
        "owner_only_gates": ("support tier", "production incident"),
    },
    "P11": {
        "objective": ("operator productization", "commercial lifecycle", "DR"),
        "components": ("operator dashboard", "billing/offboarding", "AppCare DR"),
        "runtime_wiring": ("support tiers", "billing", "offboarding"),
        "security_requirements": ("external secret custody", "least privilege", "recovery"),
        "positive_tests": ("onboarding", "cancellation", "offboarding", "DR"),
        "negative_adversarial_tests": ("unauthorized", "credential", "data retention"),
        "live_reference_evidence": ("real operational", "service-ready"),
        "maturity_effect": ("complete operations",),
        "readiness_effect": ("paid-service", "customer onboarding"),
        "predecessor_dependencies": ("P10",),
        "prohibited_actions": ("billing mutation", "unapproved", "WordPress"),
        "owner_only_gates": ("billing/account", "legal"),
    },
    "P12": {
        "objective": ("real-target", "exact-release", "beta decision"),
        "components": ("end-to-end", "S01-S30", "release evaluator"),
        "runtime_wiring": ("all predecessor", "exact-head", "decision"),
        "security_requirements": (
            "real target",
            "cost",
            "rotation",
            "offboarding",
            "restart",
            "S01-S30",
        ),
        "positive_tests": ("full lifecycle", "adversarial", "release readiness"),
        "negative_adversarial_tests": ("missing receipt", "stale", "security"),
        "live_reference_evidence": ("real internal application", "synthetic"),
        "maturity_effect": ("SERVICE_READY",),
        "readiness_effect": ("PRIVATE_BETA", "LIVE_CUSTOMER_PRODUCTION_ENABLED=NO"),
        "predecessor_dependencies": ("P11",),
        "prohibited_actions": ("customer production", "readiness bypass", "Vercel retry"),
        "owner_only_gates": ("owner approval", "first private-beta", "production"),
    },
}


def _text(path: Path) -> str:
    assert path.is_file(), f"mandatory implementation-governance file is missing: {path}"
    return path.read_text(encoding="utf-8")


def _scope() -> dict[str, Any]:
    payload = json.loads(_text(SCOPE_PATH))
    assert isinstance(payload, dict)
    return payload


def _phase_sections(blueprint: str) -> dict[str, str]:
    matches = list(re.finditer(r"(?m)^# PHASE (?P<number>\d{2}) — .+$", blueprint))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        phase_id = f"P{match.group('number')}"
        end = matches[index + 1].start() if index + 1 < len(matches) else len(blueprint)
        sections[phase_id] = blueprint[match.start() : end]
    return sections


def _contract_text(section: str) -> str:
    marker = "## Enforceable phase contract"
    start = section.index(marker)
    next_section = section.find("\n## ", start + len(marker))
    return section[start : next_section if next_section >= 0 else len(section)]


def _field_text(contract: str, field: str) -> str:
    match = re.search(rf"(?m)^- {re.escape(field)}: (?P<value>.+)$", contract)
    assert match is not None, f"missing phase contract field: {field}"
    value = match.group("value").strip()
    assert value, f"empty phase contract field: {field}"
    return value


def _gate_block(section: str) -> str:
    marker = "## Hard exit gate"
    start = section.index(marker)
    next_section = section.find("\n## ", start + len(marker))
    return section[start : next_section if next_section >= 0 else len(section)]


def _assert_nonempty(value: Any) -> None:
    if isinstance(value, str):
        assert value.strip()
        return
    if isinstance(value, list):
        assert value
        assert all(isinstance(item, str) and item.strip() for item in value)
        return
    raise AssertionError(f"phase contract value has unsafe type: {type(value).__name__}")


def _contract_value_text(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(str(item) for item in value)
    return str(value)


def _assert_semantic_markers(value: Any, markers: tuple[str, ...]) -> None:
    text = _contract_value_text(value).casefold().replace("-", " ").replace("/", " ")
    for marker in markers:
        normalized_marker = marker.casefold().replace("-", " ").replace("/", " ")
        assert normalized_marker in text, f"missing required phase policy marker: {marker}"


def test_scope_schema_and_phase_contract_keys_are_exact() -> None:
    scope = _scope()
    assert set(scope) == SCOPE_KEYS
    assert scope["schema_version"] == 1
    assert scope["status"] == "MANDATORY_CURRENT_SCOPE"
    assert scope["target"] == "AppCare"

    phases = scope["phases"]
    assert isinstance(phases, list)
    assert len(phases) == len(EXPECTED_PHASES)
    for phase in phases:
        assert isinstance(phase, dict)
        assert set(phase) == PHASE_KEYS
        for field in PHASE_CONTRACT_FIELDS:
            _assert_nonempty(phase[field])


def test_phase_order_names_dependencies_and_gates_are_exact() -> None:
    phases = _scope()["phases"]
    observed = [(phase["id"], phase["name"], tuple(phase["depends_on"])) for phase in phases]
    assert observed == list(EXPECTED_PHASES)

    for phase in phases:
        assert phase["hard_exit_gate"] is True
        expected_predecessors = phase["depends_on"] or ["NONE"]
        assert phase["predecessor_dependencies"] == expected_predecessors
        assert (
            tuple(phase["hard_exit_requirements"]) == EXPECTED_HARD_EXIT_REQUIREMENTS[phase["id"]]
        )


def test_blueprint_has_an_enforceable_contract_for_every_phase() -> None:
    blueprint = _text(BLUEPRINT_PATH)
    sections = _phase_sections(blueprint)
    assert set(sections) == {phase[0] for phase in EXPECTED_PHASES}

    scope_phases = _scope()["phases"]
    for phase_id, _, dependencies in EXPECTED_PHASES:
        section = sections[phase_id]
        contract = _contract_text(section)
        for field in PHASE_CONTRACT_FIELDS:
            assert _field_text(contract, field)
        for dependency in dependencies:
            assert dependency in _field_text(contract, "predecessor_dependencies")

        phase = next(item for item in scope_phases if item["id"] == phase_id)
        gate_block = _gate_block(section)
        for gate in phase["hard_exit_requirements"]:
            assert gate in _field_text(contract, "hard_exit_requirements")
            assert gate in gate_block


def test_phase_policy_semantics_are_pinned_in_json_and_blueprint() -> None:
    blueprint_sections = _phase_sections(_text(BLUEPRINT_PATH))
    for phase in _scope()["phases"]:
        phase_id = phase["id"]
        contract = _contract_text(blueprint_sections[phase_id])
        expected_markers = PHASE_SEMANTIC_MARKERS[phase_id]
        for field, markers in expected_markers.items():
            _assert_semantic_markers(phase[field], markers)
            _assert_semantic_markers(_field_text(contract, field), markers)

        # The machine-readable phase contract and its human-readable contract
        # must agree on all required fields. The pinned markers above prevent
        # both sources from being weakened to semantically empty prose.
        assert phase["id"] in blueprint_sections[phase_id]
        assert phase["name"].casefold() in blueprint_sections[phase_id].casefold()
        assert phase["hard_exit_gate"] is True
        for gate in phase["hard_exit_requirements"]:
            assert gate in _field_text(contract, "hard_exit_requirements")


def _governance_supportability() -> tuple[CapabilityEvidence, ...]:
    revision = "a" * 40
    artifact = "b" * 64
    stamp = datetime(2026, 8, 29, tzinfo=UTC)
    return tuple(
        CapabilityEvidence(
            tenant_id="governance-tenant",
            application_id="governance-app",
            stack_id="linux-php",
            capability=name,
            status=CapabilityStatus.SUPPORTED,
            evidence_class=EvidenceClass.FIXTURE,
            evidence_ref=f"governance-capability-{name}",
            observed_at=stamp,
            source_revision=revision,
            artifact_digest=artifact,
        )
        for name in default_capability_registry().mandatory_capabilities
    )


def _governance_security_gate(revision: str) -> SecurityGateDecision:
    stamp = datetime(2026, 8, 29, tzinfo=UTC)
    refs = {
        "dependency_audit_ref": "governance-dependency",
        "secret_scan_ref": "governance-secret-scan",
        "graphify_ref": "governance-graphify",
        "saveruflo_ref": "governance-saveruflo",
        "exact_head_ci_ref": "governance-ci",
        "real_target_security_ref": "governance-target-security",
        "known_limitations_ref": "governance-limitations",
    }
    return SecurityGateDecision(
        release_candidate_sha=revision,
        gate_version="s01-s30",
        individual_gate_results={item: True for item in REQUIRED_SECURITY_GATE_IDS},
        security_findings_open=0,
        codex_security_refs=("governance-codex-security",),
        **refs,
        coordinator_decision=CoordinatorDecision.APPROVE,
        decided_at=stamp,
    )


def _governance_readiness(
    onboarding_class: EvidenceClass,
    *,
    onboarding_revision: str = "a" * 40,
    onboarding_application: str = "governance-app",
    include_approval: bool = True,
) -> LayeredReadinessDecision:
    revision = "a" * 40
    artifact = "b" * 64
    stamp = datetime(2026, 8, 29, tzinfo=UTC)
    definitions = (
        (ReadinessTier.CORE, "core", EvidenceClass.FIXTURE),
        (ReadinessTier.STACK, "stack", EvidenceClass.FIXTURE),
        (ReadinessTier.CUSTOMER_ONBOARDING, "preproduction", onboarding_class),
        (ReadinessTier.PILOT, "production", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "verification", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "rollback", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "monitoring", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "alerting", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "reporting", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "restart_durability", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "cost_measurement", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "sustained_operation", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "operator_workflow", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "customer_dashboard", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "offboarding", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "credential_rotation", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "cost_controls", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "disaster_recovery", EvidenceClass.REAL_TARGET),
    )
    evidence: list[ReadinessEvidence] = []
    grouped: dict[ReadinessTier, list[ReadinessEvidence]] = {}
    for index, (level, kind, evidence_class) in enumerate(definitions):
        source_revision = (
            onboarding_revision if level == ReadinessTier.CUSTOMER_ONBOARDING else revision
        )
        application = (
            onboarding_application
            if level == ReadinessTier.CUSTOMER_ONBOARDING
            else "governance-app"
        )
        item = ReadinessEvidence(
            tenant_id="governance-tenant",
            application_id=application,
            level=level,
            evidence_ref=f"governance-readiness-{index}",
            evidence_class=evidence_class,
            passed=True,
            observed_at=stamp,
            source_revision=source_revision,
            artifact_digest=artifact,
            kind=kind,
        )
        evidence.append(item)
        grouped.setdefault(level, []).append(item)

    levels = tuple(
        ReadinessLevel(
            level=level,
            scope="governance-app",
            status=ReadinessStatus.READY,
            evidence_refs=tuple(item.evidence_ref for item in grouped[level]),
            evaluated_at=stamp,
            evaluator="governance-test",
            evidence_classes=tuple(item.evidence_class for item in grouped[level]),
            evidence_kinds=tuple(item.kind for item in grouped[level]),
            exact_head=revision,
            artifact_digest=artifact,
            coordinator_decision=CoordinatorDecision.APPROVE,
        )
        for level in ReadinessTier
    )
    supportability_evaluator = SupportabilityEvaluator()
    supportability_pending = supportability_evaluator.evaluate(
        "governance-tenant",
        "governance-app",
        "linux-php",
        _governance_supportability(),
        expected_source_revision=revision,
        expected_artifact_digest=artifact,
        decided_at=stamp,
    )
    supportability = supportability_evaluator.evaluate(
        "governance-tenant",
        "governance-app",
        "linux-php",
        _governance_supportability(),
        expected_source_revision=revision,
        expected_artifact_digest=artifact,
        coordinator_approval=SupportabilityEvaluator.approve(
            supportability_pending, approved_at=stamp
        ),
        decided_at=stamp,
    )
    evaluator = ReadinessEvaluator()
    gate = _governance_security_gate(revision)
    digest = evaluator.assessment_digest(
        levels,
        evidence=evidence,
        supportability=supportability,
        security_gate=gate,
        candidate_sha=revision,
    )
    approval = CoordinatorApproval.for_luna(digest, approved_at=stamp) if include_approval else None
    return evaluator.evaluate(
        levels,
        tenant_id="governance-tenant",
        application_id="governance-app",
        stack_id="linux-php",
        evidence=evidence,
        supportability=supportability,
        security_gate=gate,
        candidate_sha=revision,
        coordinator_approval=approval,
        evaluated_at=stamp,
    )


def test_spec013_evaluator_rejects_non_live_and_caller_claimed_readiness() -> None:
    for evidence_class in (
        EvidenceClass.FIXTURE,
        EvidenceClass.REFERENCE,
        EvidenceClass.CONTROLLED_LIVE_PROVIDER,
    ):
        decision = _governance_readiness(evidence_class)
        onboarding = decision.for_level(ReadinessTier.CUSTOMER_ONBOARDING)
        assert onboarding.status == ReadinessStatus.BLOCKED
        assert "READINESS_EVIDENCE_CLASS_INSUFFICIENT" in onboarding.reason_codes
        assert decision.authoritative is False

    stale = _governance_readiness(EvidenceClass.REAL_TARGET, onboarding_revision="c" * 40)
    assert stale.for_level(ReadinessTier.CUSTOMER_ONBOARDING).status == ReadinessStatus.BLOCKED
    assert (
        "STALE_READINESS_REVISION"
        in stale.for_level(ReadinessTier.CUSTOMER_ONBOARDING).reason_codes
    )

    caller_claim = _governance_readiness(EvidenceClass.REAL_TARGET, include_approval=False)
    assert caller_claim.authoritative is False
    assert caller_claim.coordinator_decision == CoordinatorDecision.BLOCKED
    assert all(item.status == ReadinessStatus.BLOCKED for item in caller_claim.levels)


def test_spec013_evaluator_rejects_cross_scope_evidence() -> None:
    with pytest.raises(ReadinessEvaluationError):
        _governance_readiness(
            EvidenceClass.REAL_TARGET,
            onboarding_application="another-tenant-app",
        )


def test_product_contract_and_operational_lifecycle_order_are_binding() -> None:
    blueprint = _text(BLUEPRINT_PATH)
    product_contract = blueprint.split("## 2. Current supported scope", maxsplit=1)[0]
    assert "SCAN\n→ FIX\n→ BACKUP\n→ MONITOR\n→ RECOVER" in product_contract

    lifecycle = (
        "CONNECT",
        "INVENTORY",
        "IMMUTABLE BASELINE",
        "FILESYSTEM BACKUP",
        "DATABASE BACKUP",
        "B2 UPLOAD",
        "REMOTE READBACK",
        "ISOLATED RESTORE",
        "SECURITY SCAN",
        "TEST DISCOVERY",
        "STAGING",
        "REMEDIATION",
        "DEPLOYMENT PACKAGE",
        "ROLLBACK READY",
        "MONITORING",
        "ALERTING",
        "REPORTING",
    )
    positions = [product_contract.index(step) for step in lifecycle]
    assert positions == sorted(positions)
    assert "At least one real internal application must complete" in product_contract


def test_profile_target_exclusions_and_provider_scope_are_exact() -> None:
    scope = _scope()
    assert scope["first_supported_profile"] == {
        "os_family": "linux",
        "runtime": "php-8.x",
        "web_servers": ["nginx", "apache"],
        "primary_database": "mariadb-mysql",
        "deployment_models": [
            "direct-filesystem-after-normalization",
            "git-based-after-exact-binding",
        ],
    }
    assert scope["first_real_acceptance_target"] == {
        "application": "video.slabfranchise.com",
        "host": "64.44.115.21",
        "expected_hostname": "slab-prompt-ola",
    }
    for branch in ("wordpress", "woocommerce"):
        assert scope["future_branches"][branch] == {
            "current_implementation_authorized": False,
            "owner_authorization_required": True,
        }
    assert scope["vercel"] == {"current_critical_path": False, "tracking_issue": 30}


def test_enforcement_invariants_keep_authority_and_evidence_fail_closed() -> None:
    invariants = _scope()["enforcement_invariants"]
    assert invariants == {
        "evidence_classes": [
            "fixture",
            "reference",
            "controlled_live_provider",
            "real_target",
        ],
        "fixture_reference_cannot_promote_live": True,
        "worker_self_approval": False,
        "global_live_customer_production_enabled": False,
        "production_requires_application_approval": True,
        "production_requires_rollback": True,
        "backup_requires_remote_readback": True,
        "backup_requires_isolated_restore": True,
        "governance_amendment_requires_protected_pr": True,
        "only_real_target_can_promote_customer_readiness": True,
        "controlled_live_provider_cannot_promote_real_target": True,
        "readiness_evaluator_is_authoritative": True,
        "production_authority_is_resolved_not_caller_boolean": True,
    }

    blueprint = _text(BLUEPRINT_PATH)
    for marker in (
        "A component contract, fixture, reference environment, synthetic rehearsal",
        "No row may advance solely because a worker reports success.",
        (
            "Model output cannot become arbitrary shell, SQL, scanner command, deployment command, "
            "or path."
        ),
        (
            "Every private-beta production change requires explicit owner/customer-approver "
            "authorization."
        ),
        (
            "Upload success is not backup success. Remote readback and isolated restore evidence "
            "are required."
        ),
        "Terra does not merge or self-approve a patch it authored.",
        (
            "Only qualifying `real_target` evidence may promote customer-onboarding, pilot, or "
            "paid-service readiness"
        ),
        (
            "The Spec 013 readiness evaluator is the sole authority for capability and readiness "
            "promotion"
        ),
        (
            "Production authority is resolved from persisted, scope-bound approval and recovery "
            "evidence"
        ),
    ):
        assert marker in blueprint


def test_backup_policy_and_readiness_floor_remain_fail_closed() -> None:
    scope = _scope()
    assert scope["backup_policy"] == {
        "pre_change_backup_required": True,
        "files_frequency": "daily",
        "database_frequency": "daily",
        "b2_operational_retention_days": 30,
        "glacier_monthly_archive_months": 12,
        "remote_readback_every_backup": True,
        "isolated_restore_rehearsal": "monthly",
        "large_site_processing": "streaming-or-chunked",
    }
    production = scope["private_beta_production_policy"]
    assert production["explicit_application_approval_required"] is True
    assert production["deployment_without_reliable_rollback"] == "denied"
    assert production["deliberate_production_failure_drill"] == "prohibited"
    assert production["global_live_customer_production_enabled"] is False

    readiness = scope["current_readiness"]
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


def test_model_roles_maturity_and_active_guidance_are_bound() -> None:
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
    for relative_path in (
        ".specify/memory/constitution.md",
        "README.md",
        "AGENTS.md",
        "WORKER_PROTOCOL.md",
        "BETA_LOOP.md",
    ):
        guidance = _text(ROOT / relative_path)
        assert "APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md" in guidance
        assert "docs/governance/APPCARE_CURRENT_SCOPE.json" in guidance

    blueprint = _text(BLUEPRINT_PATH)
    assert "The unqualified word `IMPLEMENTED` is prohibited" in blueprint
    assert "No row may advance solely because a worker reports success." in blueprint
    assert "LIVE_CUSTOMER_PRODUCTION_ENABLED=NO" in blueprint


def test_late_phase_contracts_keep_external_gates_and_no_false_scope() -> None:
    sections = _phase_sections(_text(BLUEPRINT_PATH))
    p11 = _contract_text(sections["P11"])
    for marker in (
        "external secret custody",
        "billing/cancellation",
        "rotation/offboarding",
        "restart durability",
        "DR recovery",
    ):
        assert marker in p11

    p12 = _contract_text(sections["P12"])
    for marker in ("S01-S30", "real internal application", "real cost", "owner", "stop"):
        assert marker.lower() in p12.lower()

    for section in sections.values():
        contract = _contract_text(section).lower()
        assert "live_customer_production_enabled=yes" not in contract
        assert not re.search(
            r"(?:wordpress|woocommerce).*(?:current|implemented|supported)", contract
        )


def test_p01_gate_block_contains_complete_hard_exit_contract() -> None:
    section = _phase_sections(_text(BLUEPRINT_PATH))["P01"]
    gate_block = _gate_block(section)
    expected = (
        "P01_BLUEPRINT_MERGED=YES",
        "P01_SCOPE_MACHINE_READABLE=YES",
        "P01_TWELVE_PHASES=PASS",
        "P01_HARD_EXIT_GATES=PASS",
        "P01_CI_ENFORCEMENT=PASS",
        "P01_CROSS_DOCUMENT_CONSISTENCY=PASS",
        "P01_LUNA_APPROVAL=PASS",
        "P01_TERRA_APPROVAL=PASS",
        "P01_CODEX_SECURITY=PASS",
        "P01_EXACT_HEAD_CI=PASS",
        "P01_PROTECTED_MAIN_VERIFIED=PASS",
    )
    for marker in expected:
        assert marker in gate_block
