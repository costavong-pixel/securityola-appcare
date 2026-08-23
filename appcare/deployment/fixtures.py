"""Deterministic provider fixtures for BETA-07 failure-injection tests."""

from __future__ import annotations

from dataclasses import dataclass, field

from .contracts import (
    DeploymentIntent,
    ProviderDeployment,
    ProviderRollback,
    ProviderVerification,
)


@dataclass
class FixtureProductionProvider:
    """A no-network provider fixture with controllable identity and failures."""

    verification_passed: bool = True
    rollback_succeeds: bool = True
    target_environment: str = "production"
    revision_override: str | None = None
    artifact_override: str | None = None
    fail_deploy: bool = False
    deploy_calls: int = field(init=False, default=0)
    verify_calls: int = field(init=False, default=0)
    rollback_calls: int = field(init=False, default=0)

    def deploy(self, intent: DeploymentIntent) -> ProviderDeployment:
        self.deploy_calls += 1
        if self.fail_deploy:
            raise RuntimeError("fixture provider deployment failure")
        return ProviderDeployment(
            deployment_ref=f"fixture-deployment-{self.deploy_calls}",
            target_environment=self.target_environment,
            source_revision=self.revision_override or intent.source_revision,
            artifact_digest=self.artifact_override or intent.artifact_digest,
        )

    def verify(
        self, intent: DeploymentIntent, deployment: ProviderDeployment
    ) -> ProviderVerification:
        del intent
        self.verify_calls += 1
        return ProviderVerification(
            deployment_ref=deployment.deployment_ref,
            passed=self.verification_passed,
            verification_ref=f"fixture-verification-{self.verify_calls}",
            failure_code=None if self.verification_passed else "fixture_health_failed",
        )

    def rollback(
        self, intent: DeploymentIntent, deployment: ProviderDeployment
    ) -> ProviderRollback:
        del deployment
        self.rollback_calls += 1
        return ProviderRollback(
            rollback_ref=f"fixture-rollback-{self.rollback_calls}",
            rollback_reference=intent.rollback_reference,
            succeeded=self.rollback_succeeds,
            failure_code=None if self.rollback_succeeds else "fixture_rollback_failed",
        )


__all__ = ["FixtureProductionProvider"]
