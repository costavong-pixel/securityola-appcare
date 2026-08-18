"""Integration-style tests for BETA-06 patch, preview, and approval boundaries."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Literal

import pytest

from appcare.remediation import (
    ApprovalQueue,
    FileChange,
    FixturePreviewAdapter,
    GateResult,
    GateRunner,
    PatchBuilder,
    PatchValidator,
    PreviewPolicy,
    UnapprovedVercelPreviewAdapter,
    WorkspaceManager,
)
from appcare.remediation.contracts import (
    PatchCandidate,
    PatchValidationResult,
    RemediationBoundaryError,
    RemediationContext,
    RemediationWorkspace,
    evidence_digest,
)
from appcare.remediation.gates import GateSummary
from appcare.remediation.preview import build_preview_request
from appcare.remediation.workspace import WorkspaceBoundaryError
from appcare.scanning import ScanContext, ScannerObservation, normalize_observation


def _patch(
    tmp_path: Path,
) -> tuple[WorkspaceManager, RemediationWorkspace, PatchCandidate, PatchValidationResult]:
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
    )
    finding, evidence = normalize_observation(scan_context, observation)
    context = RemediationContext(
        tenant_id=scan_context.tenant_id,
        application_id=scan_context.target_id,
        job_id="job-beta-06-1",
        finding_fingerprint=finding.fingerprint,
        source_revision="a" * 40,
    )
    before = "DEBUG = True\n"
    after = "DEBUG = False\n"
    change = FileChange(
        path="appcare/config.py",
        operation="modify",
        before_digest=hashlib.sha256(before.encode()).hexdigest(),
        after_digest=hashlib.sha256(after.encode()).hexdigest(),
        content=after,
    )
    patch = PatchBuilder().build(
        context,
        finding,
        evidence_refs=(evidence.evidence_id,),
        changes=(change,),
        reference_commit="a" * 40,
        rollback_reference="b" * 40,
    )
    manager = WorkspaceManager(tmp_path / "appcare-workspaces")
    workspace = manager.create(context)
    target = workspace.root / "appcare" / "config.py"
    target.parent.mkdir(parents=True)
    target.write_bytes(before.encode("utf-8"))
    validation = PatchValidator().validate(workspace, patch)
    return manager, workspace, patch, validation


class _Gate:
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


def _passed_gates(patch: PatchCandidate, workspace: RemediationWorkspace) -> GateSummary:
    return GateRunner().run(
        patch,
        workspace,
        (_Gate("regression", "passed"), _Gate("security", "passed")),
    )


def test_preimage_drift_blocks_before_any_apply(tmp_path: Path) -> None:
    manager, workspace, patch, _validation = _patch(tmp_path)
    (workspace.root / "appcare/config.py").write_bytes(b"DEBUG = changed\n")

    result = PatchValidator().validate(workspace, patch)

    assert result.status == "blocked"
    assert result.code == "patch_preimage_does_not_match_workspace"
    manager.destroy(workspace)


def test_failing_or_unavailable_gate_blocks_preview(tmp_path: Path) -> None:
    manager, workspace, patch, validation = _patch(tmp_path)
    failed = GateRunner().run(
        patch,
        workspace,
        (_Gate("regression", "passed"), _Gate("security", "failed")),
    )
    assert not failed.promotion_ready
    with pytest.raises(ValueError, match="passed gates"):
        build_preview_request(
            patch,
            PreviewPolicy(
                provider="vercel",
                project_reference="appcare://fixture/beta06",
                environment="preview",
                skill_revision="fixture-v1",
                skill_reviewed=True,
                provider_scope=("preview:deploy",),
            ),
            validation,
            failed,
        )
    manager.destroy(workspace)


def test_gate_summary_cannot_be_forged_as_passed() -> None:
    with pytest.raises(RemediationBoundaryError, match="both required gates"):
        GateSummary(status="passed", results=(), evidence_refs=())


def test_preview_policy_rejects_unallowlisted_scope_and_traversal() -> None:
    with pytest.raises(RemediationBoundaryError, match="allowlisted"):
        PreviewPolicy(
            provider="vercel",
            project_reference="appcare://fixture/beta06",
            environment="preview",
            skill_revision="fixture-v1",
            skill_reviewed=True,
            provider_scope=("preview:delete",),
        )
    with pytest.raises(RemediationBoundaryError, match="AppCare-owned"):
        PreviewPolicy(
            provider="vercel",
            project_reference="appcare://fixture/../production",
            environment="preview",
            skill_revision="fixture-v1",
            skill_reviewed=True,
            provider_scope=("preview:deploy",),
        )


def test_fixture_preview_and_tenant_scoped_approval(tmp_path: Path) -> None:
    manager, workspace, patch, validation = _patch(tmp_path)
    gates = _passed_gates(patch, workspace)
    request = build_preview_request(
        patch,
        PreviewPolicy(
            provider="vercel",
            project_reference="appcare://fixture/beta06",
            environment="preview",
            skill_revision="fixture-v1",
            skill_reviewed=True,
            provider_scope=("preview:deploy", "preview:read"),
        ),
        validation,
        gates,
    )
    preview = FixturePreviewAdapter().request(request)
    queue = ApprovalQueue()
    approval = queue.request(
        tenant_id=patch.context.tenant_id,
        patch_id=patch.patch_id,
        preview=preview,
        rollback_reference=patch.rollback_reference,
    )
    decided = queue.decide(
        approval.approval_id,
        actor_tenant_id=patch.context.tenant_id,
        decision="approved",
        decision_ref="reviewer-beta06-1",
    )
    assert preview.status == "passed"
    assert decided.status == "approved"
    assert decided.actor_tenant_id == patch.context.tenant_id
    with pytest.raises(RemediationBoundaryError, match="identity"):
        queue.request(
            tenant_id=patch.context.tenant_id,
            patch_id="c" * 64,
            preview=preview,
            rollback_reference=patch.rollback_reference,
        )
    with pytest.raises(RemediationBoundaryError, match="tenant"):
        queue.decide(
            approval.approval_id,
            actor_tenant_id="tenant-other-1",
            decision="rejected",
            decision_ref="reviewer-other-1",
        )
    manager.destroy(workspace)


def test_unapproved_vercel_adapter_makes_no_external_call(tmp_path: Path) -> None:
    manager, workspace, patch, validation = _patch(tmp_path)
    gates = _passed_gates(patch, workspace)
    request = build_preview_request(
        patch,
        PreviewPolicy(
            provider="vercel",
            project_reference="appcare://fixture/beta06",
            environment="preview",
            skill_revision="fixture-v1",
            skill_reviewed=True,
            provider_scope=("preview:deploy",),
            mode="live",
        ),
        validation,
        gates,
    )
    adapter = UnapprovedVercelPreviewAdapter()

    result = adapter.request(request)

    assert result.status == "blocked"
    assert result.code == "vercel_skill_unapproved"
    assert adapter.external_call_count == 0
    manager.destroy(workspace)


def test_preview_smoke_or_security_failure_cannot_enter_approval(tmp_path: Path) -> None:
    manager, workspace, patch, validation = _patch(tmp_path)
    request = build_preview_request(
        patch,
        PreviewPolicy(
            provider="vercel",
            project_reference="appcare://fixture/beta06",
            environment="preview",
            skill_revision="fixture-v1",
            skill_reviewed=True,
            provider_scope=("preview:deploy",),
        ),
        validation,
        _passed_gates(patch, workspace),
    )
    failed_preview = FixturePreviewAdapter(security_passed=False).request(request)
    with pytest.raises(RemediationBoundaryError, match="verified preview"):
        ApprovalQueue().request(
            tenant_id=patch.context.tenant_id,
            patch_id=patch.patch_id,
            preview=failed_preview,
            rollback_reference=patch.rollback_reference,
        )
    manager.destroy(workspace)


def test_symlink_workspace_child_is_rejected_when_supported(tmp_path: Path) -> None:
    manager, workspace, _patch_candidate, _validation = _patch(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = workspace.root / "appcare" / "linked"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable in this test environment")
    with pytest.raises(WorkspaceBoundaryError):
        manager.child(workspace, "appcare/linked/file.py")
    with pytest.raises(WorkspaceBoundaryError, match="traversal"):
        manager.child(workspace, "appcare/../outside.py")
    manager.destroy(workspace)
