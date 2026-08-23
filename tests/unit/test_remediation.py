"""Unit tests for the deterministic BETA-06 remediation boundary."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Literal

import pytest

from appcare.remediation import (
    FileChange,
    GateResult,
    GateRunner,
    PatchBuilder,
    PatchValidator,
    RemediationContext,
    WorkspaceManager,
    apply_patch_atomically,
)
from appcare.remediation.contracts import (
    PatchCandidate,
    RemediationBoundaryError,
    RemediationWorkspace,
    evidence_digest,
)
from appcare.scanning import (
    EvidenceRecord,
    Finding,
    ScanContext,
    ScannerObservation,
    ScopeError,
    normalize_observation,
)


def _finding_and_context() -> tuple[RemediationContext, Finding, EvidenceRecord]:
    scan_context = ScanContext("tenant-appcare-1", "target-appcare-1", scan_id="scan-beta-06")
    observation = ScannerObservation(
        adapter_kind="source",
        rule_id="source.debug",
        title="Debug setting enabled",
        summary="A release configuration enables debug behavior.",
        location="config/settings.py",
        asset_id="config-file",
        severity="high",
        confidence="high",
        raw_evidence={"actual": "enabled", "expected": "disabled"},
    )
    finding, evidence = normalize_observation(scan_context, observation)
    context = RemediationContext(
        tenant_id=scan_context.tenant_id,
        application_id=scan_context.target_id,
        job_id="job-beta-06-1",
        finding_fingerprint=finding.fingerprint,
        source_revision="a" * 40,
    )
    return context, finding, evidence


def _change(path: str = "appcare/config.py") -> FileChange:
    before = "DEBUG = True\n"
    after = "DEBUG = False\n"
    return FileChange(
        path=path,
        operation="modify",
        before_digest=hashlib.sha256(before.encode()).hexdigest(),
        after_digest=hashlib.sha256(after.encode()).hexdigest(),
        content=after,
    )


def _patch(tmp_path: Path) -> tuple[WorkspaceManager, RemediationWorkspace, PatchCandidate]:
    context, finding, evidence = _finding_and_context()
    builder = PatchBuilder()
    patch = builder.build(
        context,
        finding,
        evidence_refs=(evidence.evidence_id,),
        changes=(_change(),),
        reference_commit="a" * 40,
        rollback_reference="b" * 40,
    )
    manager = WorkspaceManager(tmp_path / "appcare-workspaces")
    workspace = manager.create(context)
    target = workspace.root / "appcare" / "config.py"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"DEBUG = True\n")
    return manager, workspace, patch


def test_valid_finding_creates_one_stable_patch_and_applies_atomically(tmp_path: Path) -> None:
    manager, workspace, patch = _patch(tmp_path)

    first = PatchValidator().validate(workspace, patch)
    applied = apply_patch_atomically(workspace, patch)
    second = PatchValidator().validate(workspace, patch)

    assert first.status == "passed"
    assert applied.status == "passed"
    assert second.status == "blocked"  # The preimage no longer matches.
    assert (workspace.root / "appcare/config.py").read_text(encoding="utf-8") == "DEBUG = False\n"
    manager.destroy(workspace)


def test_duplicate_build_is_idempotent(tmp_path: Path) -> None:
    _manager, _workspace, first = _patch(tmp_path)
    context, finding, evidence = _finding_and_context()
    second = PatchBuilder().build(
        context,
        finding,
        evidence_refs=(evidence.evidence_id,),
        changes=(_change(),),
        reference_commit="a" * 40,
        rollback_reference="b" * 40,
    )
    assert first.patch_id == second.patch_id
    assert first.patch_digest == second.patch_digest


def test_validator_rejects_tampered_patch_digest(tmp_path: Path) -> None:
    manager, workspace, patch = _patch(tmp_path)

    result = PatchValidator().validate(workspace, replace(patch, patch_digest="c" * 64))

    assert result.status == "blocked"
    assert result.code == "patch_digest_mismatch"
    manager.destroy(workspace)


def test_suppressed_finding_and_missing_evidence_are_rejected() -> None:
    context, finding, evidence = _finding_and_context()
    builder = PatchBuilder()
    with pytest.raises(RemediationBoundaryError, match="active findings"):
        builder.build(
            context,
            replace(finding, status="suppressed", suppression_reason="fixture"),
            evidence_refs=(evidence.evidence_id,),
            changes=(_change(),),
            reference_commit="a" * 40,
            rollback_reference="b" * 40,
        )
    with pytest.raises(RemediationBoundaryError, match="evidence"):
        builder.build(
            context,
            finding,
            evidence_refs=("c" * 64,),
            changes=(_change(),),
            reference_commit="a" * 40,
            rollback_reference="b" * 40,
        )


def test_cross_tenant_finding_is_rejected() -> None:
    context, finding, evidence = _finding_and_context()
    other_context = replace(context, tenant_id="tenant-other-1")
    with pytest.raises(RemediationBoundaryError, match="outside"):
        PatchBuilder().build(
            other_context,
            finding,
            evidence_refs=(evidence.evidence_id,),
            changes=(_change(),),
            reference_commit="a" * 40,
            rollback_reference="b" * 40,
        )


@pytest.mark.parametrize(
    "path", ["../outside.py", "/etc/passwd", "wordpress/plugin.py", "appcare/.env"]
)
def test_forbidden_patch_paths_are_rejected(path: str) -> None:
    context, finding, evidence = _finding_and_context()
    with pytest.raises(RemediationBoundaryError):
        PatchBuilder().build(
            context,
            finding,
            evidence_refs=(evidence.evidence_id,),
            changes=(_change(path),),
            reference_commit="a" * 40,
            rollback_reference="b" * 40,
        )


def test_secret_like_patch_content_is_rejected() -> None:
    context, finding, evidence = _finding_and_context()
    assignment_name = "API" + "_KEY"
    content = f'{assignment_name} = "not-a-real-secret-value"\n'
    change = FileChange(
        path="appcare/config.py",
        operation="add",
        before_digest=None,
        after_digest=hashlib.sha256(content.encode()).hexdigest(),
        content=content,
    )
    with pytest.raises(RemediationBoundaryError, match="credential-like"):
        PatchBuilder().build(
            context,
            finding,
            evidence_refs=(evidence.evidence_id,),
            changes=(change,),
            reference_commit="a" * 40,
            rollback_reference="b" * 40,
        )


def test_scanner_context_failure_is_not_a_finding() -> None:
    context = ScanContext("tenant-appcare-1", "target-appcare-1", scan_id="scan-beta-06")
    observation = ScannerObservation(
        adapter_kind="source",
        rule_id="source.debug",
        title="Debug setting enabled",
        summary="A release configuration enables debug behavior.",
        location="config/settings.py",
        asset_id="config-file",
        severity="high",
        confidence="high",
    )
    with pytest.raises(ScopeError):
        normalize_observation(
            context,
            replace(observation, tenant_id="tenant-other-1"),
        )


class _StaticGate:
    kind: Literal["regression", "security"]
    status: Literal["passed", "failed"]

    def __init__(
        self,
        kind: Literal["regression", "security"],
        status: Literal["passed", "failed"],
    ) -> None:
        self.kind = kind
        self.status = status

    def run(self, patch: PatchCandidate, workspace: RemediationWorkspace) -> GateResult:
        return GateResult(
            kind=self.kind,
            status=self.status,
            code=f"{self.kind}_{self.status}",
            evidence_ref=evidence_digest("gate", patch.patch_id, self.kind, self.status),
        )


def test_both_gates_must_pass(tmp_path: Path) -> None:
    _manager, workspace, patch = _patch(tmp_path)
    passed = GateRunner().run(
        patch,
        workspace,
        (_StaticGate("regression", "passed"), _StaticGate("security", "passed")),
    )
    failed = GateRunner().run(
        patch,
        workspace,
        (_StaticGate("regression", "passed"), _StaticGate("security", "failed")),
    )
    assert passed.promotion_ready
    assert not failed.promotion_ready
