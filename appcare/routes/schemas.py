"""Strict request and response schemas for the BETA-01 HTTP contract."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TokenRequest(StrictModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=256)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().casefold()


class TokenResponse(StrictModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - protocol field, not a credential
    expires_in: int


class ApplicationCreate(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    repository_url: str = Field(min_length=1, max_length=500)
    environment: Literal["development", "staging", "production"] = "development"


class ApplicationPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    repository_url: str | None = Field(default=None, min_length=1, max_length=500)
    environment: Literal["development", "staging", "production"] | None = None
    status: Literal["active", "archived"] | None = None


class ApplicationResponse(StrictModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    name: str
    repository_url: str
    environment: str
    status: str
    created_at: datetime
    updated_at: datetime


class AssetCreate(StrictModel):
    application_id: str = Field(min_length=32, max_length=32)
    kind: str = Field(min_length=1, max_length=100)
    locator: str = Field(min_length=1, max_length=500)


class AssetPatch(StrictModel):
    kind: str | None = Field(default=None, min_length=1, max_length=100)
    locator: str | None = Field(default=None, min_length=1, max_length=500)
    status: Literal["active", "retired"] | None = None


class AssetResponse(StrictModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    application_id: str
    kind: str
    locator: str
    status: str
    created_at: datetime
    updated_at: datetime


class FindingCreate(StrictModel):
    application_id: str = Field(min_length=32, max_length=32)
    asset_id: str | None = Field(default=None, min_length=32, max_length=32)
    severity: Literal["critical", "high", "medium", "low", "informational"]
    title: str = Field(min_length=1, max_length=300)
    summary: str = Field(min_length=1, max_length=10_000)
    fingerprint: str = Field(min_length=1, max_length=128)


class FindingPatch(StrictModel):
    status: Literal["open", "accepted", "resolved"] | None = None
    title: str | None = Field(default=None, min_length=1, max_length=300)
    summary: str | None = Field(default=None, min_length=1, max_length=10_000)


class FindingResponse(StrictModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    application_id: str
    asset_id: str | None
    severity: str
    status: str
    title: str
    summary: str
    fingerprint: str
    created_at: datetime
    updated_at: datetime


class ConnectorCreate(StrictModel):
    application_id: str = Field(min_length=32, max_length=32)
    provider: str = Field(min_length=1, max_length=100)
    kind: str = Field(min_length=1, max_length=100)
    display_name: str = Field(min_length=1, max_length=200)


class ConnectorResponse(StrictModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    application_id: str
    provider: str
    kind: str
    status: str
    display_name: str
    last_checked_at: datetime | None
    created_at: datetime
    updated_at: datetime


class JobCreate(StrictModel):
    application_id: str = Field(min_length=32, max_length=32)
    kind: str = Field(min_length=1, max_length=100)
    cost_amount: Decimal | None = Field(default=None, ge=0, max_digits=12, decimal_places=6)
    cost_currency: str | None = Field(default=None, min_length=3, max_length=3)


class JobPatch(StrictModel):
    status: Literal["running", "succeeded", "failed", "cancelled"]
    retry_count: int | None = Field(default=None, ge=0)
    failure_code: str | None = Field(default=None, max_length=100)
    failure_message: str | None = Field(default=None, max_length=1_000)


class JobResponse(StrictModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    application_id: str
    kind: str
    status: str
    retry_count: int
    cost_amount: Decimal | None
    cost_currency: str | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    failure_code: str | None
    failure_message: str | None
    created_at: datetime
    updated_at: datetime


class BackupCreate(StrictModel):
    application_id: str = Field(min_length=32, max_length=32)
    provider: str = Field(min_length=1, max_length=100)
    artifact_reference: str | None = Field(default=None, max_length=500)


class BackupResponse(StrictModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    application_id: str
    status: str
    provider: str
    artifact_reference: str | None
    verified_at: datetime | None
    failure_code: str | None
    created_at: datetime
    updated_at: datetime


class ApprovalCreate(StrictModel):
    application_id: str = Field(min_length=32, max_length=32)
    kind: str = Field(min_length=1, max_length=100)


class ApprovalResponse(StrictModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    application_id: str
    kind: str
    status: str
    requested_by: str
    decided_by: str | None
    decision_reason: str | None
    requested_at: datetime
    decided_at: datetime | None
    created_at: datetime
    updated_at: datetime


class DeploymentCreate(StrictModel):
    application_id: str = Field(min_length=32, max_length=32)
    environment: Literal["development", "staging", "production"]
    revision: str = Field(min_length=1, max_length=200)


class DeploymentResponse(StrictModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    application_id: str
    environment: str
    status: str
    requested_by: str
    approved_by: str | None
    revision: str
    failure_code: str | None
    created_at: datetime
    updated_at: datetime


class AuditEventResponse(StrictModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    actor_user_id: str | None
    action: str
    subject_type: str
    subject_id: str | None
    outcome: str
    metadata_json: dict[str, Any]
    occurred_at: datetime
    previous_event_hash: str | None
    event_hash: str
