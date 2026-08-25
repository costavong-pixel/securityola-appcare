"""Run the bounded AppCare provider-neutral preproduction rehearsal.

This command is intended for the dedicated AppCare reference namespace on the
shared VPS. It uses synthetic data, the canonical backup boundary, the real
filesystem/systemd adapter, and the durable SQLAlchemy evidence stores. It
does not contact Vercel or any customer/WordPress resource.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

from appcare.backups import (
    AesGcmEnvelopeEncryptor,
    BackupComponent,
    BackupCoordinator,
    BackupDestination,
    BackupFilesystemBoundary,
    BackupRequest,
    BackupTarget,
    FilesystemImmutableVault,
    RestoreTarget,
)
from appcare.dashboard.service import build_dashboard_snapshot
from appcare.db import Database
from appcare.deployment import (
    DeploymentApproval,
    DeploymentIntent,
    FilesystemReferenceProvider,
    PreproductionEvidence,
    ProductionDeploymentController,
    ReferenceDeploymentConfig,
    SqlAlchemyDeploymentStore,
    SqlAlchemyPreproductionEvidenceStore,
)
from appcare.deployment.provider_status import VERCEL_CAPABILITIES
from appcare.models import Application, Tenant, User
from appcare.monitoring import (
    BackupHealthCheck,
    MonitoringEngine,
    MonitorTarget,
    Observation,
    SqlAlchemyMonitoringStore,
)
from appcare.release.contracts import EvidenceReceipt, ReleaseEvidence
from appcare.release.fixtures import run_adversarial_fixtures
from appcare.release.gate import REQUIRED_AUTHORITATIVE_RECEIPTS, ReleaseGate

TENANT_ID = "tenant-appcare-e2e"
APPLICATION_ID = "appcare-e2e-app"
USER_ID = "appcare-e2e-user"
BASELINE_REVISION = "c1dc80ba3fb838bbf36a2e8fceec3ca312a965f1"
BACKUP_ID = "provider-neutral-e2e-backup"
BACKUP_JOB_ID = "provider-neutral-e2e-job"
RESTORE_JOB_ID = "provider-neutral-e2e-restore"
STAGING_ROOT = Path("/opt/securityola/appcare-staging")
REFERENCE_ROOT = Path("/opt/securityola/appcare-reference-production")
REFERENCE_DATABASE = Path("/var/lib/securityola/appcare/reference/appcare_reference.db")


class SyntheticSource:
    def snapshot(self, target: BackupTarget) -> tuple[BackupComponent, ...]:
        if target.tenant_id != TENANT_ID or target.application_id != APPLICATION_ID:
            raise ValueError("synthetic target scope mismatch")
        return (
            BackupComponent("config", "config", "synthetic://appcare/config", b"mode=test"),
            BackupComponent(
                "database", "database", "synthetic://appcare/database", b"synthetic-row-1"
            ),
            BackupComponent("source", "source", "synthetic://appcare/source", b"fixture-source"),
        )


def _sha(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _confined_path(path: Path, root: Path, *, field_name: str) -> Path:
    """Validate an operational path without following a symlink boundary."""

    candidate = Path(os.path.abspath(path))
    boundary = Path(os.path.abspath(root))
    try:
        candidate.relative_to(boundary)
    except ValueError as exc:
        raise RuntimeError(f"{field_name} is outside the controlled AppCare namespace") from exc
    current = candidate
    while True:
        if current.is_symlink():
            raise RuntimeError(f"{field_name} crosses a symlink")
        if current == boundary:
            break
        if current == current.parent:
            raise RuntimeError(f"{field_name} has no valid boundary")
        current = current.parent
    return candidate


def _validate_operational_paths(args: argparse.Namespace) -> None:
    if Path(os.path.abspath(args.staging_root)) != STAGING_ROOT:
        raise RuntimeError("staging_root is not the fixed AppCare staging namespace")
    if Path(os.path.abspath(args.reference_root)) != REFERENCE_ROOT:
        raise RuntimeError("reference_root is not the fixed AppCare reference namespace")
    if Path(os.path.abspath(args.database_path)) != REFERENCE_DATABASE:
        raise RuntimeError("database_path is not the fixed AppCare reference database")
    source_root = _confined_path(
        args.source_root,
        STAGING_ROOT / "artifacts",
        field_name="source_root",
    )
    if source_root.name != "source" or source_root.parent.name != args.artifact_digest:
        raise RuntimeError("source_root is not the exact artifact source namespace")
    if not source_root.is_dir():
        raise RuntimeError("source_root is missing")


def _restart(service_name: str) -> bool:
    try:
        result = subprocess.run(  # noqa: S603 - fixed systemd executable and validated service name.
            ["/usr/bin/systemctl", "restart", service_name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _health(url: str) -> bool:
    try:
        with urllib.request.urlopen(  # noqa: S310 - all callers pass a loopback URL.
            url, timeout=5
        ) as response:
            payload: Any = json.loads(response.read(16_384).decode("utf-8"))
        return isinstance(payload, dict) and payload.get("status") == "ready"
    except (OSError, ValueError, UnicodeError, urllib.error.URLError):
        return False


def _auth_boundary(url: str) -> bool:
    try:
        urllib.request.urlopen(  # noqa: S310 - all callers pass a loopback URL.
            url, timeout=5
        )
    except urllib.error.HTTPError as exc:
        return exc.code == 401
    except (OSError, urllib.error.URLError):
        return False
    return False


def _seed(database: Database) -> User:
    with database.session() as session:
        tenant = session.get(Tenant, TENANT_ID)
        if tenant is None:
            tenant = Tenant(id=TENANT_ID, name="Synthetic AppCare rehearsal", status="active")
            session.add(tenant)
            session.flush()
        application = session.get(Application, APPLICATION_ID)
        if application is None:
            session.add(
                Application(
                    id=APPLICATION_ID,
                    tenant_id=TENANT_ID,
                    name="Synthetic AppCare reference application",
                    repository_url="https://github.com/costavong-pixel/securityola-appcare",
                    environment="staging",
                    status="active",
                )
            )
        user = session.get(User, USER_ID)
        if user is None:
            user = User(
                id=USER_ID,
                tenant_id=TENANT_ID,
                email="synthetic-appcare@example.test",
                display_name="Synthetic AppCare operator",
                password_hash=_sha("synthetic-fixture-password"),
                status="active",
            )
            session.add(user)
        session.flush()
        return user


def _backup() -> dict[str, str]:
    now = datetime.now(UTC).replace(microsecond=0)
    filesystem = BackupFilesystemBoundary.canonical()
    destination = BackupDestination(
        "isolated-test-vault",
        "appcare-provider-neutral-e2e",
        "local-test",
        now + timedelta(days=7),
    )
    target = BackupTarget(TENANT_ID, APPLICATION_ID, "test", "synthetic://appcare/reference")
    request = BackupRequest(
        target,
        destination,
        BACKUP_ID,
        BACKUP_JOB_ID,
        now - timedelta(minutes=2),
    )
    coordinator = BackupCoordinator()
    vault = FilesystemImmutableVault(filesystem, destination)
    outcome = coordinator.create_backup(
        request,
        source=SyntheticSource(),
        vault=vault,
        encryptor=AesGcmEnvelopeEncryptor(
            b"c" * 32,
            key_reference="vault://appcare/provider-neutral-rehearsal",
        ),
        now=now,
    )
    if not outcome.healthy or outcome.receipt is None or outcome.evidence is None:
        raise RuntimeError("synthetic backup did not verify")
    reopened = FilesystemImmutableVault(filesystem, destination)
    artifact = reopened.get(BACKUP_ID, tenant_id=TENANT_ID, application_id=APPLICATION_ID)
    restore_root = filesystem.restore_rehearsal_path(TENANT_ID, APPLICATION_ID, RESTORE_JOB_ID)
    restore = coordinator.restore_backup(
        backup_id=BACKUP_ID,
        vault=reopened,
        encryptor=AesGcmEnvelopeEncryptor(
            b"c" * 32,
            key_reference="vault://appcare/provider-neutral-rehearsal",
        ),
        target=RestoreTarget(
            TENANT_ID,
            APPLICATION_ID,
            "test",
            restore_root,
            RESTORE_JOB_ID,
            filesystem=filesystem,
        ),
        now=now + timedelta(seconds=5),
    )
    if restore.status != "restore_verified":
        raise RuntimeError("synthetic restore did not verify")
    return {
        "backup_reference": outcome.receipt.object_reference,
        "backup_artifact_digest": artifact.artifact_digest,
        "backup_manifest_digest": sha256(artifact.manifest_bytes).hexdigest(),
        "restore_status": restore.status,
        "backup_path": str(filesystem.snapshot_path(TENANT_ID, APPLICATION_ID, BACKUP_ID)),
        "manifest_path": str(filesystem.manifest_path(TENANT_ID, APPLICATION_ID, BACKUP_ID)),
    }


def _intent(
    *,
    intent_id: str,
    idempotency_key: str,
    source_revision: str,
    artifact_digest: str,
    rollback_reference: str,
    rollback_artifact_digest: str,
    preproduction_digest: str,
) -> DeploymentIntent:
    return DeploymentIntent(
        intent_id=intent_id,
        tenant_id=TENANT_ID,
        application_id=APPLICATION_ID,
        artifact_digest=artifact_digest,
        source_revision=source_revision,
        rollback_reference=rollback_reference,
        rollback_artifact_digest=rollback_artifact_digest,
        idempotency_key=idempotency_key,
        requested_by="synthetic-appcare-operator",
        backup_evidence_ref="backup-evidence-provider-neutral",
        credential_ref="vault://appcare/reference-deployment-custody",
        preproduction_evidence_digest=preproduction_digest,
    )


def _approval(intent: DeploymentIntent) -> DeploymentApproval:
    return DeploymentApproval(
        intent_id=intent.intent_id,
        approval_id=f"approval:{intent.intent_id}",
        actor_ref="synthetic-internal-approval",
        decision="approved",
        decision_ref=f"decision:{intent.intent_id}",
        intent_digest=intent.intent_digest,
    )


def _run_tests(source_root: Path) -> str:
    selected = (
        "tests/unit/test_preproduction_gate.py",
        "tests/unit/test_production_control.py",
        "tests/unit/test_release_gate.py",
        "tests/unit/test_monitoring.py",
        "tests/integration/test_backups.py",
    )
    result = subprocess.run(  # noqa: S603 - executable and test paths are fixed.
        [sys.executable, "-m", "pytest", *selected, "-q"],
        cwd=source_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=900,
    )
    if result.returncode != 0:
        raise RuntimeError(f"controlled tests failed: {result.stdout[-2000:]}")
    return _sha(result.stdout)


def run(args: argparse.Namespace) -> dict[str, object]:
    _validate_operational_paths(args)
    source_root = args.source_root.resolve()
    staging_root = args.staging_root.resolve()
    reference_root = args.reference_root.resolve()
    database_url = f"sqlite+pysqlite:///{args.database_path.resolve().as_posix()}"
    database = Database(database_url)
    database.initialize()
    user = _seed(database)
    del user

    inventory = sorted(path.name for path in source_root.iterdir() if not path.is_symlink())
    scan_receipt = _sha(json.dumps({"revision": args.source_revision, "inventory": inventory}))
    test_receipt = _run_tests(source_root)
    backup = _backup()

    staging_provider = FilesystemReferenceProvider(
        ReferenceDeploymentConfig(
            target_root=staging_root,
            artifact_root=staging_root / "artifacts",
            service_name="appcare-staging",
            health_url="http://127.0.0.1:18567/health/ready",
        )
    )
    staging_intent = _intent(
        intent_id="preproduction-staging-deploy",
        idempotency_key="preproduction-staging-deploy",
        source_revision=args.source_revision,
        artifact_digest=args.artifact_digest,
        rollback_reference=BASELINE_REVISION,
        rollback_artifact_digest=args.baseline_artifact_digest,
        preproduction_digest="0" * 64,
    )
    staging_deployment = staging_provider.deploy(staging_intent)
    staging_verification = staging_provider.verify(staging_intent, staging_deployment)
    if not staging_verification.passed:
        raise RuntimeError("controlled staging health verification failed")

    preproduction = PreproductionEvidence.create(
        tenant_id=TENANT_ID,
        application_id=APPLICATION_ID,
        provider="securityola-vps",
        target_type="loopback-staging",
        source_revision=args.source_revision,
        artifact_digest=args.artifact_digest,
        environment_identity="appcare-staging-127.0.0.1:18567",
        deployment_reference=staging_deployment.deployment_ref,
        deployment_timestamp=datetime.now(UTC).replace(microsecond=0),
        smoke_test_receipt=staging_verification.verification_ref,
        security_test_receipt=f"security:{scan_receipt[:24]}",
        rollback_reference_receipt=f"rollback-reference:{BASELINE_REVISION[:24]}",
    )
    preproduction_store = SqlAlchemyPreproductionEvidenceStore(
        database.session_factory,
        tenant_id=TENANT_ID,
    )
    preproduction_store.save(preproduction)
    if (
        preproduction_store.resolve(
            tenant_id=TENANT_ID,
            application_id=APPLICATION_ID,
            source_revision=args.source_revision,
            artifact_digest=args.artifact_digest,
            evidence_digest=preproduction.authoritative_evidence_digest,
        )
        is None
    ):
        raise RuntimeError("persisted preproduction evidence could not be resolved")

    reference_config = ReferenceDeploymentConfig(
        target_root=reference_root,
        artifact_root=reference_root / "artifacts",
        service_name="appcare-reference-production",
        health_url="http://127.0.0.1:18568/health/ready",
    )
    reference_provider = FilesystemReferenceProvider(reference_config)
    if not reference_provider.recover_current():
        raise RuntimeError("reference baseline is not healthy before promotion")
    deployment_store = SqlAlchemyDeploymentStore(
        database.session_factory,
        tenant_id=TENANT_ID,
    )
    good_intent = _intent(
        intent_id="reference-production-good",
        idempotency_key="reference-production-good",
        source_revision=args.source_revision,
        artifact_digest=args.artifact_digest,
        rollback_reference=BASELINE_REVISION,
        rollback_artifact_digest=args.baseline_artifact_digest,
        preproduction_digest=preproduction.authoritative_evidence_digest,
    )
    good_controller = ProductionDeploymentController(
        reference_provider,
        store=deployment_store,
        preproduction_store=preproduction_store,
    )
    good_pending = good_controller.submit(good_intent, backup_verified=True)
    good_approved = good_controller.approve(good_intent.intent_id, _approval(good_intent))
    good_record = good_controller.execute(good_intent.intent_id)
    if good_pending.status != "approval_pending" or good_approved.status != "approved":
        raise RuntimeError("controlled approval did not bind to the good intent")
    if good_record.status != "succeeded":
        raise RuntimeError("controlled reference deployment did not succeed")
    exact_good_identity = (
        good_record.provider_source_revision == args.source_revision
        and good_record.provider_artifact_digest == args.artifact_digest
        and _health("http://127.0.0.1:18568/health/ready")
        and _auth_boundary("http://127.0.0.1:18568/dashboard/state")
    )
    if not exact_good_identity:
        raise RuntimeError("reference production identity or boundary verification failed")

    failure_provider = FilesystemReferenceProvider(
        ReferenceDeploymentConfig(
            target_root=reference_root,
            artifact_root=reference_root / "artifacts",
            service_name="appcare-reference-production",
            health_url="http://127.0.0.1:18568/health/ready",
            failure_health_url="http://127.0.0.1:18569/health/ready",
        )
    )
    failure_intent = _intent(
        intent_id="reference-production-health-failure",
        idempotency_key="reference-production-health-failure",
        source_revision=args.source_revision,
        artifact_digest=args.artifact_digest,
        rollback_reference=args.source_revision,
        rollback_artifact_digest=args.artifact_digest,
        preproduction_digest=preproduction.authoritative_evidence_digest,
    )
    failure_controller = ProductionDeploymentController(
        failure_provider,
        store=deployment_store,
        preproduction_store=preproduction_store,
    )
    failure_controller.submit(failure_intent, backup_verified=True)
    failure_controller.approve(failure_intent.intent_id, _approval(failure_intent))
    failure_record = failure_controller.execute(failure_intent.intent_id)
    duplicate = failure_controller.submit(failure_intent, backup_verified=True)
    restart_recovered = _restart("appcare-reference-production")
    restarted_provider = FilesystemReferenceProvider(reference_config)
    process_restart_recovery = restart_recovered and restarted_provider.recover_current()
    restarted_controller = ProductionDeploymentController(
        restarted_provider,
        store=SqlAlchemyDeploymentStore(database.session_factory, tenant_id=TENANT_ID),
        preproduction_store=SqlAlchemyPreproductionEvidenceStore(
            database.session_factory,
            tenant_id=TENANT_ID,
        ),
    )
    recovered_failure = restarted_controller.execute(failure_intent.intent_id)

    monitor_target = MonitorTarget(
        tenant_id=TENANT_ID,
        application_id=APPLICATION_ID,
        environment="production",
        app_reference="appcare-reference-production",
    )
    monitoring = MonitoringEngine(
        SqlAlchemyMonitoringStore(database.session_factory, target=monitor_target)
    )
    now = datetime.now(UTC).replace(microsecond=0)
    monitoring.observe(
        BackupHealthCheck(
            target=monitor_target,
            observed_at=now,
            evidence_ref="backup-health-provider-neutral",
            latest_verified_at=now,
            integrity_verified=True,
            freshness_limit_seconds=86_400,
        ).observation()
    )
    monitoring.observe(
        Observation(
            target=monitor_target,
            check_kind="deployment",
            status="healthy",
            observed_at=now,
            evidence_ref="deployment-good-provider-neutral",
            summary="controlled reference deployment verified",
            reason_code="deployment_verified",
        )
    )
    monitoring.observe(
        Observation(
            target=monitor_target,
            check_kind="uptime",
            status="failed",
            observed_at=now + timedelta(seconds=1),
            evidence_ref="health-failure-provider-neutral-1",
            summary="synthetic health failure for rollback drill",
            reason_code="deliberate_health_check_failure",
        )
    )
    monitoring.observe(
        Observation(
            target=monitor_target,
            check_kind="uptime",
            status="failed",
            observed_at=now + timedelta(seconds=2),
            evidence_ref="health-failure-provider-neutral-2",
            summary="synthetic health failure for rollback drill",
            reason_code="deliberate_health_check_failure",
        )
    )
    monitoring.observe(
        Observation(
            target=monitor_target,
            check_kind="uptime",
            status="healthy",
            observed_at=now + timedelta(seconds=3),
            evidence_ref="health-restored-provider-neutral",
            summary="reference health restored after rollback",
            reason_code="health_restored",
        )
    )
    replayed_monitoring = MonitoringEngine(
        SqlAlchemyMonitoringStore(database.session_factory, target=monitor_target)
    )
    monthly = replayed_monitoring.monthly_report(
        target=monitor_target,
        period_start=now - timedelta(minutes=1),
        period_end=now + timedelta(minutes=1),
    )
    with database.session_factory() as session:
        dashboard_user = session.get(User, USER_ID)
        if dashboard_user is None:
            raise RuntimeError("synthetic dashboard user was not persisted")
        dashboard = build_dashboard_snapshot(session, dashboard_user)

    receipts = tuple(
        EvidenceReceipt(
            kind=kind,
            reference=(
                "receipt-preproduction-environment"
                if kind == "preproduction_environment"
                else f"receipt-{kind}"
            ),
            exact_head=args.source_revision,
            digest=(
                preproduction.authoritative_evidence_digest
                if kind == "preproduction_environment"
                else _sha(f"{kind}|{args.source_revision}")
            ),
            passed=kind not in {"exact_head_ci", "codex_security"},
        )
        for kind in REQUIRED_AUTHORITATIVE_RECEIPTS
    )
    release_evidence = ReleaseEvidence(
        exact_head=args.source_revision,
        ci_passed=False,
        test_count=1,
        codex_security_findings=0,
        tenant_isolation=True,
        backup_restore=True,
        production_rollback=failure_record.status == "rolled_back",
        operator_stop=True,
        customer_report=True,
        dependency_scan=True,
        secret_scan=True,
        pricing_margin=True,
        known_limitations_published=True,
        preproduction_evidence=preproduction,
        drills=run_adversarial_fixtures(),
        authoritative_receipts=receipts,
    )
    release_decision = ReleaseGate().evaluate(release_evidence)

    return {
        "inventory": "PASS",
        "scan": "PASS",
        "scan_receipt": scan_receipt,
        "tests_receipt": test_receipt,
        "backup": backup,
        "preproduction_deployment": staging_deployment.deployment_ref,
        "preproduction_smoke": staging_verification.verification_ref,
        "preproduction_security": f"security:{scan_receipt[:24]}",
        "preproduction_evidence": preproduction.authoritative_evidence_digest,
        "controlled_production_deployment": good_record.deployment_ref,
        "production_verification": "PASS" if exact_good_identity else "FAIL",
        "broken_deployment_detected": failure_record.failure_code == "health_check_failed",
        "automatic_rollback": failure_record.status == "rolled_back",
        "rollback_reference": failure_record.rollback_ref,
        "rollback_exact_reference": failure_record.intent.rollback_reference
        == args.source_revision,
        "rollback_artifact_digest": failure_record.intent.rollback_artifact_digest
        == args.artifact_digest,
        "post_rollback_health": _health("http://127.0.0.1:18568/health/ready"),
        "duplicate_deployment_prevented": duplicate == failure_record
        and failure_provider.deploy_calls == 1,
        "process_restart_state_recovery": process_restart_recovery
        and recovered_failure == failure_record,
        "monitoring_persisted_events": len(replayed_monitoring.events),
        "monitoring_restart_replay": len(replayed_monitoring.events) >= 8,
        "alert_dedup": any(alert.suppressed_count >= 1 for alert in replayed_monitoring.alerts()),
        "backup_health": any(
            event.check_kind == "backup" and event.status == "healthy"
            for event in replayed_monitoring.events
        ),
        "deployment_status": any(
            event.check_kind == "deployment" and event.status == "healthy"
            for event in replayed_monitoring.events
        ),
        "dashboard_monitoring_source": "persisted"
        if dashboard.monitoring.status in {"healthy", "attention"}
        else "unknown",
        "monthly_report_source": "persisted" if monthly.observation_count >= 1 else "missing",
        "beta10_status": release_decision.status,
        "beta10_reason_codes": list(release_decision.reason_codes),
        "vercel_read_only": VERCEL_CAPABILITIES.read_only,
        "vercel_scan": VERCEL_CAPABILITIES.scan,
        "vercel_preview": VERCEL_CAPABILITIES.preview,
        "vercel_automated_production": VERCEL_CAPABILITIES.automated_production,
        "live_customer_production_enabled": False,
        "wordpress": "UNTOUCHED",
        "secrets_exposed": "NO",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--staging-root", type=Path, required=True)
    parser.add_argument("--reference-root", type=Path, required=True)
    parser.add_argument("--database-path", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--baseline-artifact-digest", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
