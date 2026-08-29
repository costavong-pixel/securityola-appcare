"""Import all AppCare models so metadata creation is deterministic."""

from .audit import AuditEvent
from .base import Base, IdentityMixin, TimestampMixin, new_id, utcnow
from .deployment import (
    DeploymentControlRecord,
    DeploymentEvidenceRecord,
    DeploymentIntentRecord,
    DeploymentRevokedCredential,
)
from .identity import Tenant, User
from .monitoring import MonitoringEventRecord
from .operations import (
    Approval,
    Backup,
    Connector,
    ConnectorCheck,
    ConnectorCredential,
    DatabaseOperationRecord,
    DatabaseRestoreTargetRecord,
    Deployment,
    InventoryRun,
    Job,
    WorkflowAction,
    WorkflowEvidence,
    WorkflowTransition,
)
from .preproduction import PreproductionEvidenceRecord
from .readiness import (
    CapabilityEvidenceRecord,
    ReadinessDowngradeRecord,
    ReadinessLevelRecord,
    SecurityGateDecisionRecord,
    SupportabilityDecisionRecord,
)
from .resources import Application, Asset, Finding

__all__ = [
    "Approval",
    "Application",
    "Asset",
    "AuditEvent",
    "Backup",
    "Base",
    "CapabilityEvidenceRecord",
    "Connector",
    "ConnectorCheck",
    "ConnectorCredential",
    "DatabaseOperationRecord",
    "DatabaseRestoreTargetRecord",
    "Deployment",
    "DeploymentControlRecord",
    "DeploymentEvidenceRecord",
    "DeploymentIntentRecord",
    "DeploymentRevokedCredential",
    "Finding",
    "IdentityMixin",
    "InventoryRun",
    "Job",
    "MonitoringEventRecord",
    "PreproductionEvidenceRecord",
    "ReadinessDowngradeRecord",
    "ReadinessLevelRecord",
    "SecurityGateDecisionRecord",
    "SupportabilityDecisionRecord",
    "Tenant",
    "TimestampMixin",
    "User",
    "WorkflowAction",
    "WorkflowEvidence",
    "WorkflowTransition",
    "new_id",
    "utcnow",
]
