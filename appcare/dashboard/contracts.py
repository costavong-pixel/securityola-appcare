"""Sanitized, tenant-scoped dashboard response contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

DashboardStatus = Literal["healthy", "attention", "pending", "unknown", "empty"]


class DashboardSignal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["healthy", "attention", "pending", "unknown"]
    label: str = Field(min_length=1, max_length=120)
    detail: str = Field(min_length=1, max_length=300)
    last_event_at: datetime | None = None


class DashboardApplication(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    environment: Literal["development", "staging", "production"]
    status: Literal["active", "archived"]
    finding_count: int = Field(ge=0)
    open_finding_count: int = Field(ge=0)


class DashboardFindingSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(ge=0)
    open: int = Field(ge=0)
    critical: int = Field(ge=0)
    high: int = Field(ge=0)
    medium: int = Field(ge=0)
    low: int = Field(ge=0)
    informational: int = Field(ge=0)


class DashboardActivity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    subject_type: str
    outcome: str
    occurred_at: datetime


class ProductionControl(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: Literal[False] = False
    label: str = "Production deploys locked"
    reason_code: Literal["BETA06_LIVE_PREVIEW_REQUIRED"] = "BETA06_LIVE_PREVIEW_REQUIRED"


class DashboardSnapshot(BaseModel):
    """The only data shape the browser is allowed to render as dashboard state."""

    model_config = ConfigDict(extra="forbid")

    state_source: Literal["backend"] = "backend"
    captured_at: datetime
    tenant_name: str
    overall_status: DashboardStatus
    application_count: int = Field(ge=0)
    applications: list[DashboardApplication] = Field(default_factory=list)
    findings: DashboardFindingSummary
    backup: DashboardSignal
    connectors: DashboardSignal
    deployments: DashboardSignal
    monitoring: DashboardSignal
    recent_activity: list[DashboardActivity] = Field(default_factory=list)
    production: ProductionControl = Field(default_factory=ProductionControl)
