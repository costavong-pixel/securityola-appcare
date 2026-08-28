"""Fail CI if mandatory AppCare readiness/security governance is removed or weakened."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    target = ROOT / path
    assert target.is_file(), f"mandatory governance file is missing: {path}"
    return target.read_text(encoding="utf-8")


def test_binding_governance_documents_exist_and_are_linked() -> None:
    constitution = _text(".specify/memory/constitution.md")
    gap_register = _text("docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md")
    security_gate = _text("docs/security/PRE_BETA_SECURITY_GATE.md")
    beta_loop = _text("BETA_LOOP.md")
    readiness_spec = _text("specs/013-product-readiness/spec.md")

    assert "Product completeness is a security and release invariant" in constitution
    assert "Mandatory pre-beta security review" in constitution
    assert "docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md" in constitution
    assert "docs/security/PRE_BETA_SECURITY_GATE.md" in constitution

    assert "Status: **MANDATORY GOVERNANCE**" in gap_register
    assert "Status: **MANDATORY RELEASE BLOCKER**" in security_gate
    assert "specs/013-product-readiness/" in beta_loop
    assert "docs/security/PRE_BETA_SECURITY_GATE.md" in beta_loop
    assert "CUSTOMER_ONBOARDING_READY=YES" in readiness_spec


def test_layered_readiness_cannot_disappear_from_governance() -> None:
    gap_register = _text("docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md")
    readme = _text("README.md")

    required_levels = (
        "CORE_PLATFORM_READY",
        "STACK_GENERIC_LINUX_READY",
        "STACK_WORDPRESS_READY",
        "STACK_WOOCOMMERCE_READY",
        "STACK_GITHUB_VERCEL_SUPABASE_READY",
        "CUSTOMER_ONBOARDING_READY",
        "PILOT_READY",
        "PAID_SERVICE_READY",
        "LIVE_CUSTOMER_PRODUCTION_ENABLED",
    )
    for marker in required_levels:
        assert marker in gap_register
        assert marker in readme

    assert "CUSTOMER_ONBOARDING_READY=NO" in readme
    assert "PILOT_READY=NO" in readme
    assert "PAID_SERVICE_READY=NO" in readme
    assert "LIVE_CUSTOMER_PRODUCTION_ENABLED=NO" in readme


def test_complete_live_capability_roadmap_is_retained() -> None:
    gap_register = _text("docs/governance/PRODUCT_READINESS_AND_GAP_REGISTER.md")

    for spec_number in range(13, 24):
        assert f"specs/{spec_number:03d}-" in gap_register

    mandatory_capabilities = (
        "CONNECT",
        "INVENTORY",
        "SOURCE_REVISION",
        "FILESYSTEM_BACKUP",
        "DATABASE_BACKUP",
        "OFFSITE_BACKUP",
        "REMOTE_READBACK",
        "ISOLATED_RESTORE",
        "SECURITY_SCAN",
        "TEST_DISCOVERY",
        "STAGING",
        "REMEDIATION",
        "DEPLOY",
        "PRODUCTION_VERIFY",
        "DATABASE_MIGRATION_SAFETY",
        "ROLLBACK",
        "MONITORING",
        "SCHEDULER",
        "ALERTING",
        "REPORTING",
        "CREDENTIAL_ROTATION",
        "OFFBOARDING",
    )
    for capability in mandatory_capabilities:
        assert capability in gap_register


def test_pre_beta_security_gate_retains_all_security_domains() -> None:
    security_gate = _text("docs/security/PRE_BETA_SECURITY_GATE.md")

    # S01-S30 is intentionally explicit so reducing the final security review
    # requires a visible governance change rather than an accidental edit.
    for gate_number in range(1, 31):
        assert f"Gate S{gate_number:02d}" in security_gate

    required_security_terms = (
        "Tenant and application isolation",
        "Authentication and session security",
        "Authorization and production approval",
        "Customer credential custody",
        "SSH and remote execution",
        "Filesystem and archive safety",
        "Database safety",
        "Backup confidentiality, integrity, and immutability",
        "Restore and recovery safety",
        "Scanner execution security",
        "Remediation and AI/agent safety",
        "Supply-chain and dependency security",
        "Staging isolation",
        "Deployment security",
        "Rollback and data-loss security",
        "Monitoring collector security",
        "Scheduler and worker security",
        "Dashboard and API security",
        "AppCare self-protection and disaster recovery",
        "Real-target adversarial acceptance",
        "Final release decision",
    )
    for term in required_security_terms:
        assert term in security_gate
